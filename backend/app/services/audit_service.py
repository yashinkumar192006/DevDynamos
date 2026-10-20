"""Audit trail queries with authorization scopes (docs/api-design.md §4.8–4.9).

Access model (fail-closed, derived from the *verified* principal only):

* ``admin`` (user role, or a service account holding ``*`` / ``role:admin``)
  sees the complete trail.
* ``hr_manager`` / ``executive`` (or the equivalent ``role:*`` service
  scopes) see **privacy-pipeline events** — data access/denial, policy
  evaluation, transformation, AI query, output inspection — for all actors.
  Authentication and administrative events stay admin-only.
* Every other authenticated principal (user *or* agent) sees only its **own**
  events, of any action.

Scopes are enforced in SQL (``actor_id`` / ``action IN`` constraints), so
out-of-scope rows are never loaded. An explicit out-of-scope *filter* (e.g.
``requester_id=<someone else>`` or ``action=admin_action``) is rejected with
403 rather than silently dropped; a direct fetch of an out-of-scope event
returns 404 (its existence is not disclosed).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthorizationError
from app.models import (
    AuditAction,
    AuditEvent,
    Role,
    ServiceAccount,
    User,
    UserRole,
)
from app.repositories import AuditRepository
from app.schemas.audit import (
    AuditActorInfo,
    AuditDecisionEntry,
    AuditEventDetail,
    AuditEventListResponse,
    AuditEventSummary,
    AuditLLMInfo,
    AuditPagination,
    AuditTransformationEntry,
)
from app.services.auth_service import Principal

#: Events that describe the privacy pipeline itself.
PRIVACY_TRAIL_ACTIONS: frozenset[AuditAction] = frozenset(
    {
        AuditAction.DATA_ACCESS,
        AuditAction.DATA_DENIED,
        AuditAction.POLICY_EVALUATION,
        AuditAction.TRANSFORMATION,
        AuditAction.AI_QUERY,
        AuditAction.OUTPUT_INSPECTION,
    }
)

#: Roles that may read the privacy trail for all actors.
COMPLIANCE_ROLES: frozenset[str] = frozenset({"hr_manager", "executive"})

#: Own-events scope applies to every authenticated principal that is not
#: covered by a wider scope above.


@dataclass(frozen=True)
class AuditVisibility:
    """Which slice of the trail a principal may read."""

    full: bool = False
    privacy_only: bool = False
    actor_only: bool = False


def resolve_visibility(principal: Principal) -> AuditVisibility:
    """Map a verified principal to its audit-read scope (fail closed)."""
    if principal.kind == "user":
        roles = set(principal.roles)
        if "admin" in roles:
            return AuditVisibility(full=True)
        if roles & COMPLIANCE_ROLES:
            return AuditVisibility(privacy_only=True)
        return AuditVisibility(actor_only=True)

    # Service/agent principals must carry an explicit role scope.
    scopes = set(principal.scopes)
    if "*" in scopes or "role:admin" in scopes:
        return AuditVisibility(full=True)
    if {f"role:{name}" for name in COMPLIANCE_ROLES} & scopes:
        return AuditVisibility(privacy_only=True)
    return AuditVisibility(actor_only=True)


# ── Defensive parsing helpers (stored detail JSON is never trusted) ────


def _parse_json_object(raw: str | None) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _opt_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _string_list(value: Any, *, limit: int = 100) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value[:limit]:
        text = _opt_str(item)
        if text:
            result.append(text)
    return result


def _decision_entries(raw: Any) -> list[AuditDecisionEntry]:
    if not isinstance(raw, list):
        return []
    entries: list[AuditDecisionEntry] = []
    for item in raw[:200]:
        if not isinstance(item, dict):
            continue
        field = _opt_str(item.get("field"))
        action = _opt_str(item.get("action"))
        reason_code = _opt_str(item.get("reason_code"))
        if not field or not action or not reason_code:
            continue
        entries.append(
            AuditDecisionEntry(
                field=field,
                action=action,
                reason_code=reason_code,
                policy_id=_opt_str(item.get("policy_id")),
                policy_version=_opt_int(item.get("policy_version")),
                sensitivity=_opt_str(item.get("sensitivity")),
                pii_category=_opt_str(item.get("pii_category")),
            )
        )
    return entries


def _transformation_entries(raw: Any) -> list[AuditTransformationEntry]:
    if not isinstance(raw, list):
        return []
    entries: list[AuditTransformationEntry] = []
    for item in raw[:200]:
        if not isinstance(item, dict):
            continue
        field = _opt_str(item.get("field"))
        transformation = _opt_str(item.get("transformation"))
        if field and transformation:
            entries.append(
                AuditTransformationEntry(field=field, transformation=transformation)
            )
    return entries


def _llm_info(raw: Any) -> AuditLLMInfo | None:
    if not isinstance(raw, dict):
        return None
    return AuditLLMInfo(
        requested=raw.get("requested") is True,
        invoked=raw.get("invoked") is True,
        provider=_opt_str(raw.get("provider")),
        model=_opt_str(raw.get("model")),
        guard_triggered=raw.get("guard_triggered") is True,
        guard_action=_opt_str(raw.get("guard_action")),
        guard_reason_code=_opt_str(raw.get("guard_reason_code")),
        error_code=_opt_str(raw.get("error_code")),
    )


class AuditService:
    """Read-side service for the audit trail APIs."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = AuditRepository(session)

    # ── Queries ─────────────────────────────────────────────────────

    async def list_events(
        self,
        principal: Principal,
        *,
        limit: int = 20,
        offset: int = 0,
        requester_id: str | None = None,
        action: AuditAction | None = None,
        resource: str | None = None,
        outcome: str | None = None,
        session_id: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> AuditEventListResponse:
        """Run a visibility-scoped, filtered, paginated audit query."""
        visibility = resolve_visibility(principal)

        actor_id: str | None = None
        if visibility.actor_only:
            if requester_id is not None and requester_id != principal.id:
                raise AuthorizationError(
                    "You may only read your own audit events"
                )
            actor_id = principal.id
        elif requester_id is not None:
            actor_id = requester_id

        action_filter: AuditAction | None = action
        actions_in: Sequence[AuditAction] | None = None
        if visibility.privacy_only:
            if action is not None and action not in PRIVACY_TRAIL_ACTIONS:
                raise AuthorizationError(
                    "Your role may only read privacy-pipeline audit events"
                )
            if action is None:
                actions_in = sorted(PRIVACY_TRAIL_ACTIONS, key=lambda a: a.value)
            else:
                action_filter = action

        rows, total = await self.repo.query_events(
            limit=limit,
            offset=offset,
            actor_id=actor_id,
            action=action_filter,
            actions_in=actions_in,
            resource=resource,
            outcome=outcome,
            session_id=session_id,
            start=_as_utc(start_date),
            end=_as_utc(end_date),
        )

        actors = await self._resolve_actors(rows)
        items = [
            self._summary(event, actors.get(event.actor_id or "", _unknown_actor(event)))
            for event in rows
        ]
        return AuditEventListResponse(
            items=items,
            pagination=AuditPagination(
                total=total,
                limit=limit,
                offset=offset,
                has_more=offset + len(items) < total,
            ),
        )

    async def get_event(
        self, principal: Principal, event_id: str
    ) -> AuditEvent | None:
        """Fetch one event if (and only if) the principal may read it.

        ``None`` covers both "not found" and "out of scope" — callers
        respond with 404 either way so event existence is not disclosed.
        """
        event = await self.repo.get_by_id(event_id)
        if event is None:
            return None
        visibility = resolve_visibility(principal)
        if visibility.actor_only and event.actor_id != principal.id:
            return None
        if visibility.privacy_only and event.action not in PRIVACY_TRAIL_ACTIONS:
            return None
        return event

    async def summaries(
        self, events: Sequence[AuditEvent]
    ) -> list[AuditEventSummary]:
        """Project events to the list-item shape used by the audit API.

        Used by aggregation endpoints (e.g. the dashboard) that embed the
        audit projection; actor identities are resolved from trusted
        database state exactly as in :meth:`list_events`.
        """
        if not events:
            return []
        actors = await self._resolve_actors(events)
        return [
            self._summary(
                event, actors.get(event.actor_id or "", _unknown_actor(event))
            )
            for event in events
        ]

    async def describe(self, event: AuditEvent) -> AuditEventDetail:
        """Build the full detail projection for an in-scope event."""
        actors = await self._resolve_actors([event])
        actor = actors.get(event.actor_id or "", _unknown_actor(event))
        summary = self._summary(event, actor)
        detail = _parse_json_object(event.detail)
        target = detail.get("target")
        target = target if isinstance(target, dict) else {}
        llm = _llm_info(detail.get("llm"))

        return AuditEventDetail(
            **summary.model_dump(),
            purpose=_opt_str(detail.get("purpose")),
            purpose_recognized=(
                detail.get("purpose_recognized")
                if isinstance(detail.get("purpose_recognized"), bool)
                else None
            ),
            operation=_opt_str(detail.get("operation")),
            subject_scope=_opt_str(target.get("subject_scope")),
            flags=_string_list(detail.get("flags")),
            requested_fields=_string_list(detail.get("requested_fields")),
            decisions=_decision_entries(detail.get("decisions")),
            transformations=_transformation_entries(detail.get("transformations")),
            llm=llm,
            guard_triggered=bool(llm is not None and llm.guard_triggered),
            correlation=(
                detail.get("correlation")
                if isinstance(detail.get("correlation"), dict)
                else {}
            ),
            ip_address=event.ip_address,
            requester=(
                detail.get("requester")
                if isinstance(detail.get("requester"), dict)
                else None
            ),
            agent=(
                detail.get("agent") if isinstance(detail.get("agent"), dict) else None
            ),
        )

    # ── Mapping ─────────────────────────────────────────────────────

    def _summary(self, event: AuditEvent, actor: AuditActorInfo) -> AuditEventSummary:
        detail = _parse_json_object(event.detail)
        decisions = _decision_entries(detail.get("decisions"))
        reason_codes = _string_list(detail.get("reason_codes")) or [
            d.reason_code for d in decisions
        ]
        policy_versions = sorted(
            {d.policy_version for d in decisions if d.policy_version is not None}
        )
        categories = sorted({d.pii_category for d in decisions if d.pii_category})
        llm = _llm_info(detail.get("llm"))

        return AuditEventSummary(
            id=event.id,
            timestamp=event.created_at,
            action=event.action.value,
            outcome=event.outcome,
            actor=actor,
            request_id=_opt_str(detail.get("request_id")),
            session_id=event.session_id,
            resource=event.resource,
            resource_id=event.resource_id,
            overall_decision=_opt_str(detail.get("overall_decision")),
            reason_codes=reason_codes,
            policy_versions=policy_versions,
            sensitivity_categories=categories,
            model_requested=detail.get("model_requested") is True,
            model_invoked=(
                detail.get("model_invoked") is True
                or bool(llm is not None and llm.invoked)
            ),
            guard_outcome=(llm.guard_action if llm is not None else None),
            mosaic_warning=detail.get("mosaic_warning") is True,
        )

    async def _resolve_actors(
        self, events: Sequence[AuditEvent]
    ) -> dict[str, AuditActorInfo]:
        """Resolve verified actor identities for the events' actor ids."""
        by_id: dict[str, AuditActorInfo] = {}
        user_ids = {
            e.actor_id
            for e in events
            if e.actor_id and (e.actor_kind or "user") == "user"
        }
        service_ids = {
            e.actor_id for e in events if e.actor_id and e.actor_kind == "service"
        }

        if user_ids:
            rows = (
                await self.session.execute(
                    select(User.id, User.full_name, User.username).where(
                        User.id.in_(user_ids)
                    )
                )
            ).all()
            role_rows = (
                await self.session.execute(
                    select(UserRole.user_id, Role.name)
                    .join(Role, Role.id == UserRole.role_id)
                    .where(UserRole.user_id.in_(user_ids))
                )
            ).all()
            roles_by_user: dict[str, list[str]] = {}
            for user_id, role_name in role_rows:
                roles_by_user.setdefault(user_id, []).append(role_name)
            for user_id, full_name, username in rows:
                by_id[user_id] = AuditActorInfo(
                    id=user_id,
                    kind="user",
                    name=full_name or username,
                    roles=sorted(roles_by_user.get(user_id, [])),
                )

        if service_ids:
            accounts = (
                (
                    await self.session.execute(
                        select(ServiceAccount).where(
                            ServiceAccount.id.in_(service_ids)
                        )
                    )
                )
                .scalars()
                .all()
            )
            for account in accounts:
                by_id[account.id] = AuditActorInfo(
                    id=account.id,
                    kind="service",
                    name=account.name,
                    scopes=sorted(account.scope_list()),
                )

        return by_id


def _unknown_actor(event: AuditEvent) -> AuditActorInfo:
    if event.actor_id is None:
        return AuditActorInfo(id=None, kind="unknown", name=None)
    return AuditActorInfo(
        id=event.actor_id,
        kind=event.actor_kind or "user",
        name=None,
    )


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalise query-param datetimes; naive values are treated as UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


__all__ = [
    "AuditService",
    "AuditVisibility",
    "resolve_visibility",
    "PRIVACY_TRAIL_ACTIONS",
    "COMPLIANCE_ROLES",
]

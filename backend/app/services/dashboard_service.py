"""Dashboard overview aggregation (docs/api-design.md §4.10).

Every number is computed from *recorded* audit events and live provider
configuration for the verified principal. Scope follows the audit-trail
visibility model (:func:`app.services.audit_service.resolve_visibility`):

* ``full`` — administrators see the complete trail;
* ``privacy_trail`` — compliance roles see privacy-pipeline events;
* ``own`` — everyone else sees only their own events.

If the visible trail contains no data the response carries zeros; the UI
renders an explicit empty state instead of inventing numbers, and no
synthetic events are ever created for display purposes.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.models import AuditAction, PolicyStatus, PrivacyPolicy
from app.repositories import AuditRepository
from app.schemas.dashboard import (
    DashboardDailyPoint,
    DashboardHealth,
    DashboardOverview,
    DashboardPolicyStats,
    DashboardSummary,
)
from app.services.audit_service import (
    PRIVACY_TRAIL_ACTIONS,
    AuditService,
    resolve_visibility,
)
from app.services.auth_service import Principal
from app.services.classification_service import ClassificationService
from app.services.llm_adapter import SafeLLMService

#: Audit actions that carry exactly one gateway decision each.
DECISION_ACTIONS = (AuditAction.DATA_ACCESS, AuditAction.DATA_DENIED)

_DECISION_NAMES = ("ALLOW", "PARTIAL_ALLOW", "BLOCK", "ESCALATION_NEEDED")
_BUCKET_BY_DECISION = {
    "ALLOW": "allow",
    "PARTIAL_ALLOW": "partial_allow",
    "BLOCK": "block",
    "ESCALATION_NEEDED": "escalation",
}

#: Defensive cap for in-memory aggregation (demo-scale data volumes).
_MAX_EVENTS = 20_000


def _parse_detail(raw: str | None) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _empty_bucket() -> dict[str, int]:
    return {
        "total": 0,
        "allow": 0,
        "partial_allow": 0,
        "block": 0,
        "escalation": 0,
    }


class DashboardService:
    """Read-side aggregation for the dashboard overview."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = AuditRepository(session)
        self.audit = AuditService(session)

    async def overview(
        self,
        principal: Principal,
        *,
        window_days: int = 14,
        recent_limit: int = 8,
    ) -> DashboardOverview:
        visibility = resolve_visibility(principal)
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=window_days)

        events = await self.repo.fetch_window(
            start=start,
            actor_id=principal.id if visibility.actor_only else None,
            actions_in=(
                sorted(PRIVACY_TRAIL_ACTIONS, key=lambda action: action.value)
                if visibility.privacy_only
                else None
            ),
            limit=_MAX_EVENTS,
        )

        counts = {name: 0 for name in _DECISION_NAMES}
        per_day: dict[str, dict[str, int]] = {}
        total_requests = 0
        with_transformations = 0
        model_invocations = 0
        guard_triggered = 0
        mosaic_warnings = 0
        policy_usage: dict[str, int] = {}

        for event in events:
            if event.action in DECISION_ACTIONS:
                total_requests += 1
                detail = _parse_detail(event.detail)
                decision = detail.get("overall_decision")
                if isinstance(decision, str) and decision in counts:
                    counts[decision] += 1
                    day = (
                        event.created_at.astimezone(timezone.utc)
                        .date()
                        .isoformat()
                    )
                    bucket = per_day.setdefault(day, _empty_bucket())
                    bucket["total"] += 1
                    bucket[_BUCKET_BY_DECISION[decision]] += 1
                if detail.get("transformations"):
                    with_transformations += 1
                if detail.get("mosaic_warning") is True:
                    mosaic_warnings += 1
                for entry in detail.get("decisions") or []:
                    if isinstance(entry, dict):
                        policy_id = entry.get("policy_id")
                        if isinstance(policy_id, str) and policy_id:
                            policy_usage[policy_id] = (
                                policy_usage.get(policy_id, 0) + 1
                            )
            elif event.action == AuditAction.AI_QUERY:
                model_invocations += 1
            elif event.action == AuditAction.OUTPUT_INSPECTION:
                detail = _parse_detail(event.detail)
                if event.outcome == "flagged" or detail.get("action_taken") not in (
                    None,
                    "none",
                ):
                    guard_triggered += 1

        # Continuous, zero-filled daily series for the chart.
        daily: list[DashboardDailyPoint] = []
        for offset in range(window_days - 1, -1, -1):
            day = (now - timedelta(days=offset)).date().isoformat()
            bucket = per_day.get(day) or _empty_bucket()
            daily.append(DashboardDailyPoint(date=day, **bucket))

        recent_events = [
            event for event in events if event.action in DECISION_ACTIONS
        ][:recent_limit]
        recent = await self.audit.summaries(recent_events)

        active_policies = int(
            await self.session.scalar(
                select(func.count(func.distinct(PrivacyPolicy.name))).where(
                    PrivacyPolicy.status == PolicyStatus.ACTIVE
                )
            )
            or 0
        )
        most_triggered = (
            max(policy_usage.items(), key=lambda item: (-item[1], item[0]))[0]
            if policy_usage
            else None
        )

        return DashboardOverview(
            scope=(
                "full"
                if visibility.full
                else "privacy_trail"
                if visibility.privacy_only
                else "own"
            ),
            window_days=window_days,
            summary=DashboardSummary(
                window_days=window_days,
                total_requests=total_requests,
                decisions=counts,
                requests_with_transformations=with_transformations,
                model_invocations=model_invocations,
                guard_triggered=guard_triggered,
                mosaic_warnings=mosaic_warnings,
            ),
            daily=daily,
            recent_decisions=recent,
            policy_stats=DashboardPolicyStats(
                active_policies=active_policies,
                most_triggered_policy=most_triggered,
            ),
            health=await self._health(),
            timestamp=now,
        )

    async def _health(self) -> DashboardHealth:
        """Live provider health — same safe shapes as ``/system/status``."""
        database = "healthy"
        latency_ms: float | None = None
        started = time.perf_counter()
        try:
            await self.session.execute(text("SELECT 1"))
            latency_ms = round((time.perf_counter() - started) * 1000, 2)
        except Exception as exc:  # pragma: no cover — defensive
            # Never surface driver errors to the client: they can disclose
            # hostnames, ports, or credentials. Only the class is logged.
            logger.warning(
                "dashboard_health_check_failed", error_type=type(exc).__name__
            )
            database = "unhealthy"
        llm = SafeLLMService(settings_obj=settings).status()
        classifier = ClassificationService(self.session).status()
        return DashboardHealth(
            database=database,
            database_latency_ms=latency_ms,
            llm=llm,
            classifier={
                "status": (
                    "ready"
                    if settings.CLASSIFIER_NLP_ENABLED
                    else "deterministic_only"
                ),
                **classifier,
            },
        )


__all__ = ["DashboardService", "DECISION_ACTIONS"]

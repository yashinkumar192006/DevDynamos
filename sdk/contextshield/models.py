"""Typed request/response models for the ContextShield SDK.

Responses are parsed defensively: unknown fields are preserved in
``.raw`` for forward compatibility, and malformed *critical* fields raise
:class:`~contextshield.exceptions.InvalidResponseError` instead of silently
producing wrong data.

Decision semantics (mirror of the gateway contract):

* ``ALLOW`` / ``PARTIAL_ALLOW`` — the request succeeded; read ``.fields``
  (and ``.records``) for the approved, already-transformed values.
* ``BLOCK`` — nothing was disclosed. This is a **normal outcome**, returned
  as a typed result; use ``.raise_if_blocked()`` if you prefer exceptions.
* ``ESCALATION_NEEDED`` — a human/policy review is required; nothing may be
  disclosed yet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from .exceptions import (
    InvalidResponseError,
    RequestBlockedError,
    RequestEscalatedError,
)

#: ``overall_decision`` values returned by the gateway.
DECISION_ALLOW = "ALLOW"
DECISION_PARTIAL_ALLOW = "PARTIAL_ALLOW"
DECISION_BLOCK = "BLOCK"
DECISION_ESCALATION_NEEDED = "ESCALATION_NEEDED"

#: Per-field actions that carry (possibly transformed) data.
GRANTED_ACTIONS = frozenset({"ALLOW", "MASK", "GENERALIZE", "TOKENIZE", "AGGREGATE"})

#: Guard actions reported by the output privacy guard.
GUARD_ACTION_NONE = "none"


# ── Parsing helpers (tolerant, never raise except where stated) ────────


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _as_bool(value: Any, default: bool = False) -> bool:
    return value if isinstance(value, bool) else default


def _as_int(value: Any) -> int | None:
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


def _as_str_tuple(value: Any, *, limit: int = 100) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    out: list[str] = []
    for item in value[:limit]:
        text = _as_str(item)
        if text:
            out.append(text)
    return tuple(out)


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


# ── Secure-request models ─────────────────────────────────────────────


@dataclass(frozen=True)
class SecureRequestContext:
    """Optional correlation metadata attached to a secure request.

    These values are treated by the gateway as *correlation only* — they are
    never identity, authorization, or policy evidence.
    """

    session_id: str | None = None
    conversation_id: str | None = None
    task_id: str | None = None
    turn_index: int | None = None
    agent_name: str | None = None
    additional_claims: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for key in ("session_id", "conversation_id", "task_id", "agent_name"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = str(value)[:64]
        if self.turn_index is not None:
            payload["turn_index"] = int(self.turn_index)
        if self.additional_claims:
            payload["additional_claims"] = dict(self.additional_claims)
        return payload


@dataclass(frozen=True)
class FieldDecision:
    """One per-field decision from the policy engine."""

    name: str
    action: str
    value: Any = None
    reason_code: str | None = None
    reason: str | None = None
    policy_id: str | None = None
    policy_version: int | None = None

    @property
    def granted(self) -> bool:
        """True when the action carries (possibly transformed) data."""
        return self.action.upper() in GRANTED_ACTIONS

    @classmethod
    def _from_entry(cls, name: str, payload: Mapping[str, Any]) -> "FieldDecision":
        return cls(
            name=name,
            action=(_as_str(payload.get("action")) or "BLOCK").upper(),
            value=payload.get("value"),
            reason_code=_as_str(payload.get("reason_code")),
            reason=_as_str(payload.get("reason")),
            policy_id=_as_str(payload.get("policy_id")),
            policy_version=_as_int(payload.get("policy_version")),
        )


@dataclass(frozen=True)
class GuardFinding:
    """One output-guard finding — category/rule/span, never matched text."""

    category: str | None = None
    rule: str | None = None
    permitted: bool = False
    start: int | None = None
    end: int | None = None
    redacted_as: str | None = None

    @classmethod
    def _from_dict(cls, payload: Mapping[str, Any]) -> "GuardFinding":
        return cls(
            category=_as_str(payload.get("category")),
            rule=_as_str(payload.get("rule")),
            permitted=_as_bool(payload.get("permitted")),
            start=_as_int(payload.get("start")),
            end=_as_int(payload.get("end")),
            redacted_as=_as_str(payload.get("redacted_as")),
        )


@dataclass(frozen=True)
class LLMGuard:
    """Output privacy guard metadata for one model invocation."""

    triggered: bool = False
    action: str = GUARD_ACTION_NONE
    reason_code: str | None = None
    findings: tuple[GuardFinding, ...] = ()

    @classmethod
    def _from_dict(cls, payload: Mapping[str, Any]) -> "LLMGuard":
        raw_findings = payload.get("findings")
        findings: tuple[GuardFinding, ...] = ()
        if isinstance(raw_findings, list):
            findings = tuple(
                GuardFinding._from_dict(item)
                for item in raw_findings
                if isinstance(item, dict)
            )
        return cls(
            triggered=_as_bool(payload.get("triggered")),
            action=_as_str(payload.get("action")) or GUARD_ACTION_NONE,
            reason_code=_as_str(payload.get("reason_code")),
            findings=findings,
        )


@dataclass(frozen=True)
class LLMInfo:
    """Structured model-stage info (provider/model/guard/error)."""

    requested: bool = True
    invoked: bool = False
    provider: str | None = None
    model: str | None = None
    error_code: str | None = None
    error: str | None = None
    guard: LLMGuard | None = None

    @classmethod
    def _from_dict(cls, payload: Mapping[str, Any]) -> "LLMInfo":
        raw_guard = payload.get("guard")
        guard = (
            LLMGuard._from_dict(raw_guard) if isinstance(raw_guard, dict) else None
        )
        return cls(
            requested=_as_bool(payload.get("requested"), default=True),
            invoked=_as_bool(payload.get("invoked")),
            provider=_as_str(payload.get("provider")),
            model=_as_str(payload.get("model")),
            error_code=_as_str(payload.get("error_code")),
            error=_as_str(payload.get("error")),
            guard=guard,
        )


@dataclass(frozen=True)
class SecureRequestResult:
    """Typed result of ``POST /api/v1/privacy/secure-request``.

    A ``BLOCK``/``ESCALATION_NEEDED`` decision is a normal outcome — the
    result is returned (never raised) so callers can branch on it.
    """

    request_id: str
    overall_decision: str
    reason_code: str | None = None
    reason: str | None = None
    fields: Mapping[str, FieldDecision] = field(default_factory=dict)
    records: tuple[Mapping[str, Any], ...] | None = None
    retrieved: bool = False
    llm_response: str | None = None
    llm: LLMInfo | None = None
    guard_triggered: bool = False
    mosaic_warning: bool = False
    audit_id: str | None = None
    timestamp: datetime | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    # ── Decision helpers ───────────────────────────────────────────

    @property
    def allowed(self) -> bool:
        return self.overall_decision in (DECISION_ALLOW, DECISION_PARTIAL_ALLOW)

    @property
    def blocked(self) -> bool:
        return self.overall_decision == DECISION_BLOCK

    @property
    def escalated(self) -> bool:
        return self.overall_decision == DECISION_ESCALATION_NEEDED

    def field(self, name: str) -> FieldDecision | None:
        """Case-insensitive field lookup."""
        lowered = name.lower()
        for field_name, decision in self.fields.items():
            if field_name.lower() == lowered:
                return decision
        return None

    def granted_values(self) -> dict[str, Any]:
        """Field name → value for every granted (data-carrying) field."""
        return {
            name: decision.value
            for name, decision in self.fields.items()
            if decision.granted
        }

    def _reason_codes(self) -> list[str]:
        codes = {
            decision.reason_code
            for decision in self.fields.values()
            if decision.reason_code
        }
        if self.reason_code:
            codes.add(self.reason_code)
        return sorted(codes)

    def raise_if_blocked(self) -> None:
        """Raise :class:`RequestBlockedError`/:class:`RequestEscalatedError`.

        Use this when a blocked request is exceptional for your control flow;
        otherwise branch on :attr:`allowed` / :attr:`blocked`.
        """
        if self.blocked:
            raise RequestBlockedError(
                f"ContextShield blocked the request (reason codes: {', '.join(self._reason_codes()) or 'unknown'})",
                request_id=self.request_id,
                reason_codes=self._reason_codes(),
            )
        if self.escalated:
            raise RequestEscalatedError(
                f"ContextShield requires escalation before disclosure (reason codes: {', '.join(self._reason_codes()) or 'unknown'})",
                request_id=self.request_id,
                reason_codes=self._reason_codes(),
            )

    # ── Parsing ────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, payload: Any) -> "SecureRequestResult":
        if not isinstance(payload, dict):
            raise InvalidResponseError(
                "secure-request response must be a JSON object"
            )
        request_id = payload.get("request_id")
        overall = payload.get("overall_decision")
        if not isinstance(request_id, str) or not request_id:
            raise InvalidResponseError("response is missing 'request_id'")
        if not isinstance(overall, str) or not overall:
            raise InvalidResponseError("response is missing 'overall_decision'")

        fields: dict[str, FieldDecision] = {}
        raw_fields = payload.get("fields")
        if isinstance(raw_fields, dict):
            for name, entry in raw_fields.items():
                if isinstance(entry, dict):
                    fields[str(name)] = FieldDecision._from_entry(str(name), entry)

        records: tuple[Mapping[str, Any], ...] | None = None
        raw_records = payload.get("records")
        if isinstance(raw_records, list):
            records = tuple(
                dict(item) for item in raw_records if isinstance(item, dict)
            )

        llm: LLMInfo | None = None
        raw_llm = payload.get("llm")
        if isinstance(raw_llm, dict):
            llm = LLMInfo._from_dict(raw_llm)

        llm_response = payload.get("llm_response")
        return cls(
            request_id=request_id,
            overall_decision=overall,
            reason_code=_as_str(payload.get("reason_code")),
            reason=_as_str(payload.get("reason")),
            fields=fields,
            records=records,
            retrieved=_as_bool(payload.get("retrieved")),
            llm_response=llm_response if isinstance(llm_response, str) else None,
            llm=llm,
            guard_triggered=_as_bool(payload.get("guard_triggered")),
            mosaic_warning=_as_bool(payload.get("mosaic_warning")),
            audit_id=_as_str(payload.get("audit_id")),
            timestamp=_as_datetime(payload.get("timestamp")),
            raw=dict(payload),
        )


# ── Audit models ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class AuditActor:
    """Verified actor identity attached to an audit event."""

    id: str | None = None
    kind: str = "unknown"
    name: str | None = None
    roles: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()

    @classmethod
    def _from_dict(cls, payload: Any) -> "AuditActor":
        if not isinstance(payload, dict):
            return cls()
        return cls(
            id=_as_str(payload.get("id")),
            kind=_as_str(payload.get("kind")) or "unknown",
            name=_as_str(payload.get("name")),
            roles=_as_str_tuple(payload.get("roles")),
            scopes=_as_str_tuple(payload.get("scopes")),
        )


@dataclass(frozen=True)
class AuditDecision:
    """One per-field decision as recorded in the audit trail."""

    field: str
    action: str
    reason_code: str
    policy_id: str | None = None
    policy_version: int | None = None
    sensitivity: str | None = None
    pii_category: str | None = None


@dataclass(frozen=True)
class AuditTransformation:
    """One applied transformation (type only — never values)."""

    field: str
    transformation: str


@dataclass(frozen=True)
class AuditEvent:
    """Audit event summary as returned by the list endpoint."""

    id: str
    timestamp: datetime | None = None
    action: str = ""
    outcome: str | None = None
    actor: AuditActor = field(default_factory=AuditActor)
    request_id: str | None = None
    session_id: str | None = None
    resource: str | None = None
    resource_id: str | None = None
    overall_decision: str | None = None
    reason_codes: tuple[str, ...] = ()
    policy_versions: tuple[int, ...] = ()
    sensitivity_categories: tuple[str, ...] = ()
    model_requested: bool = False
    model_invoked: bool = False
    guard_outcome: str | None = None
    mosaic_warning: bool = False
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _base_kwargs(cls, payload: Mapping[str, Any]) -> dict[str, Any]:
        policy_versions: list[int] = []
        raw_versions = payload.get("policy_versions")
        if isinstance(raw_versions, list):
            policy_versions = [
                value
                for value in (_as_int(item) for item in raw_versions)
                if value is not None
            ]
        return dict(
            id=str(payload.get("id") or ""),
            timestamp=_as_datetime(payload.get("timestamp")),
            action=_as_str(payload.get("action")) or "",
            outcome=_as_str(payload.get("outcome")),
            actor=AuditActor._from_dict(payload.get("actor")),
            request_id=_as_str(payload.get("request_id")),
            session_id=_as_str(payload.get("session_id")),
            resource=_as_str(payload.get("resource")),
            resource_id=_as_str(payload.get("resource_id")),
            overall_decision=_as_str(payload.get("overall_decision")),
            reason_codes=_as_str_tuple(payload.get("reason_codes")),
            policy_versions=tuple(policy_versions),
            sensitivity_categories=_as_str_tuple(payload.get("sensitivity_categories")),
            model_requested=_as_bool(payload.get("model_requested")),
            model_invoked=_as_bool(payload.get("model_invoked")),
            guard_outcome=_as_str(payload.get("guard_outcome")),
            mosaic_warning=_as_bool(payload.get("mosaic_warning")),
            raw=dict(payload),
        )

    @classmethod
    def from_dict(cls, payload: Any) -> "AuditEvent":
        if not isinstance(payload, dict):
            raise InvalidResponseError("audit event must be a JSON object")
        kwargs = cls._base_kwargs(payload)
        if not kwargs["id"]:
            raise InvalidResponseError("audit event is missing 'id'")
        return cls(**kwargs)


@dataclass(frozen=True)
class AuditEventDetail(AuditEvent):
    """Full audit event projection (detail endpoint)."""

    purpose: str | None = None
    purpose_recognized: bool | None = None
    operation: str | None = None
    subject_scope: str | None = None
    flags: tuple[str, ...] = ()
    requested_fields: tuple[str, ...] = ()
    decisions: tuple[AuditDecision, ...] = ()
    transformations: tuple[AuditTransformation, ...] = ()
    llm: LLMInfo | None = None
    guard_triggered: bool = False
    correlation: Mapping[str, Any] = field(default_factory=dict)
    ip_address: str | None = None
    requester: Mapping[str, Any] | None = None
    agent: Mapping[str, Any] | None = None

    @classmethod
    def from_dict(cls, payload: Any) -> "AuditEventDetail":
        if not isinstance(payload, dict):
            raise InvalidResponseError("audit event detail must be a JSON object")
        kwargs = cls._base_kwargs(payload)
        if not kwargs["id"]:
            raise InvalidResponseError("audit event detail is missing 'id'")

        decisions: list[AuditDecision] = []
        raw_decisions = payload.get("decisions")
        if isinstance(raw_decisions, list):
            for item in raw_decisions:
                if not isinstance(item, dict):
                    continue
                field_name = _as_str(item.get("field"))
                action = _as_str(item.get("action"))
                reason_code = _as_str(item.get("reason_code"))
                if not field_name or not action or not reason_code:
                    continue
                decisions.append(
                    AuditDecision(
                        field=field_name,
                        action=action,
                        reason_code=reason_code,
                        policy_id=_as_str(item.get("policy_id")),
                        policy_version=_as_int(item.get("policy_version")),
                        sensitivity=_as_str(item.get("sensitivity")),
                        pii_category=_as_str(item.get("pii_category")),
                    )
                )

        transformations: list[AuditTransformation] = []
        raw_transformations = payload.get("transformations")
        if isinstance(raw_transformations, list):
            for item in raw_transformations:
                if not isinstance(item, dict):
                    continue
                field_name = _as_str(item.get("field"))
                kind = _as_str(item.get("transformation"))
                if field_name and kind:
                    transformations.append(
                        AuditTransformation(field=field_name, transformation=kind)
                    )

        raw_llm = payload.get("llm")
        llm = LLMInfo._from_dict(raw_llm) if isinstance(raw_llm, dict) else None
        raw_requester = payload.get("requester")
        raw_agent = payload.get("agent")

        return cls(
            **kwargs,
            purpose=_as_str(payload.get("purpose")),
            purpose_recognized=(
                payload.get("purpose_recognized")
                if isinstance(payload.get("purpose_recognized"), bool)
                else None
            ),
            operation=_as_str(payload.get("operation")),
            subject_scope=_as_str(payload.get("subject_scope")),
            flags=_as_str_tuple(payload.get("flags")),
            requested_fields=_as_str_tuple(payload.get("requested_fields")),
            decisions=tuple(decisions),
            transformations=tuple(transformations),
            llm=llm,
            guard_triggered=_as_bool(payload.get("guard_triggered")),
            correlation=(
                dict(payload.get("correlation"))
                if isinstance(payload.get("correlation"), dict)
                else {}
            ),
            ip_address=_as_str(payload.get("ip_address")),
            requester=dict(raw_requester) if isinstance(raw_requester, dict) else None,
            agent=dict(raw_agent) if isinstance(raw_agent, dict) else None,
        )


@dataclass(frozen=True)
class AuditPagination:
    """Offset pagination metadata."""

    total: int = 0
    limit: int = 20
    offset: int = 0
    has_more: bool = False


@dataclass(frozen=True)
class AuditEventPage:
    """Paginated audit query result."""

    items: tuple[AuditEvent, ...] = ()
    pagination: AuditPagination = field(default_factory=AuditPagination)
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, payload: Any) -> "AuditEventPage":
        if not isinstance(payload, dict):
            raise InvalidResponseError("audit page must be a JSON object")
        raw_items = payload.get("items")
        items: list[AuditEvent] = []
        if isinstance(raw_items, list):
            items = [AuditEvent.from_dict(item) for item in raw_items]

        pagination = AuditPagination()
        raw_pagination = payload.get("pagination")
        if isinstance(raw_pagination, dict):
            pagination = AuditPagination(
                total=_as_int(raw_pagination.get("total")) or 0,
                limit=_as_int(raw_pagination.get("limit")) or len(items),
                offset=_as_int(raw_pagination.get("offset")) or 0,
                has_more=_as_bool(raw_pagination.get("has_more")),
            )
        return cls(items=tuple(items), pagination=pagination, raw=dict(payload))


__all__ = [
    "DECISION_ALLOW",
    "DECISION_PARTIAL_ALLOW",
    "DECISION_BLOCK",
    "DECISION_ESCALATION_NEEDED",
    "GRANTED_ACTIONS",
    "GUARD_ACTION_NONE",
    "SecureRequestContext",
    "FieldDecision",
    "GuardFinding",
    "LLMGuard",
    "LLMInfo",
    "SecureRequestResult",
    "AuditActor",
    "AuditDecision",
    "AuditTransformation",
    "AuditEvent",
    "AuditEventDetail",
    "AuditPagination",
    "AuditEventPage",
]

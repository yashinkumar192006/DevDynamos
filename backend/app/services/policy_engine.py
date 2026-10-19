"""Deterministic policy engine — the privacy decision core.

This module turns an :class:`~app.schemas.context.AnalyzedContext` (the
trusted, typed request context) plus the catalog's field metadata and the
active versioned policies into a **per-field** decision:

``ALLOW | MASK | TOKENIZE | GENERALIZE | AGGREGATE | BLOCK | ESCALATE``

Design guarantees
=================

* **Deterministic.** The same input always produces the same output.
  Nothing here consults an LLM or any untrusted text.
* **Fail-closed.** Unknown fields, unknown/incomplete authorization,
  missing or unrecognised purposes, evaluation errors — every one of
  them resolves to ``BLOCK`` (``EVALUATION_ERROR`` for internal errors).
  No code path reaches ``ALLOW`` unless a matching, active policy
  explicitly authorises it.
* **Mandatory constraints come first.** RBAC failure, invalid purpose,
  prompt-injection signals and never-disclosable categories (SSN) are
  evaluated *before* any policy is considered, so no permissive policy
  — however high its priority — can override them.
* **Explicit precedence.** Non-mandatory conflicts between matching
  policies resolve by: highest ``priority`` → highest ``version`` →
  most specific resource pattern → most restrictive action
  (``BLOCK > ESCALATE > AGGREGATE > GENERALIZE > MASK > TOKENIZE > ALLOW``,
  see ``docs/privacy-policies.md`` §4.2/§6.2).
* **Mandatory protection floors.** On third-party disclosures (the
  subject is not the requester's own record), raw coverage of certain
  PII categories is upgraded to a safer form: configurable mask floors
  (phone, email, bank account, credit card) and generalize floors
  (address, date of birth). SSN is blocked unconditionally. Floors can
  only make a decision *stricter*; a policy can never lower them.
* **Ceilings.** A policy's ``min_sensitivity`` is the *maximum*
  sensitivity it may expose (its clearance ceiling). Fields above the
  ceiling are not covered by that policy. AGGREGATE requests are the
  exception: the output is statistics only, so the ceiling is not
  applied to the source column (the minimum-group-size control is what
  protects the individuals).
* **Role-less policies are self-only.** A policy with no
  ``required_role`` never authorises access to somebody else's record;
  for personal assets it only applies to the requester's own record
  (otherwise ``SELF_ACCESS_ONLY``).
* **Destination awareness.** When the server declared a destination
  that could not be trusted, otherwise-granted fields are downgraded to
  ``ESCALATE`` (``ESCALATION_REQUIRED``).

The engine only *decides*; it never fetches data. Retrieval is the job
of :mod:`app.services.data_connector`, which honours the decision.
"""

from __future__ import annotations

import enum
import json
import logging
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as default_settings
from app.models import PrivacyPolicy, SensitivityLevel
from app.schemas.context import AnalyzedContext, ContextField
from app.services.authorization import (
    OWNERSHIP_ASSETS,
    PERSONAL_ASSETS,
    AuthorizationService,
)

logger = logging.getLogger(__name__)


class PolicyAction(str, enum.Enum):
    """The seven deterministic disclosure decisions."""

    ALLOW = "ALLOW"
    MASK = "MASK"
    TOKENIZE = "TOKENIZE"
    GENERALIZE = "GENERALIZE"
    AGGREGATE = "AGGREGATE"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


#: Restrictiveness ordering (most → least restrictive), docs §4.3.
ACTION_PRECEDENCE: tuple[PolicyAction, ...] = (
    PolicyAction.BLOCK,
    PolicyAction.ESCALATE,
    PolicyAction.AGGREGATE,
    PolicyAction.GENERALIZE,
    PolicyAction.MASK,
    PolicyAction.TOKENIZE,
    PolicyAction.ALLOW,
)

#: Numeric rank: higher means more restrictive.
_RESTRICTIVENESS: dict[PolicyAction, int] = {
    action: len(ACTION_PRECEDENCE) - index
    for index, action in enumerate(ACTION_PRECEDENCE)
}

#: Actions that permit some disclosure (possibly transformed).
GRANTED_ACTIONS: frozenset[PolicyAction] = frozenset(
    {
        PolicyAction.ALLOW,
        PolicyAction.MASK,
        PolicyAction.TOKENIZE,
        PolicyAction.GENERALIZE,
        PolicyAction.AGGREGATE,
    }
)


class ReasonCode(str, enum.Enum):
    """Machine-readable reason codes (docs §5 + phase-7 extensions)."""

    NORM_MATCHED = "NORM_MATCHED"
    NO_MATCHING_NORM = "NO_MATCHING_NORM"
    INSUFFICIENT_ROLE = "INSUFFICIENT_ROLE"
    INVALID_PURPOSE = "INVALID_PURPOSE"
    PURPOSE_NOT_VERIFIED = "PURPOSE_NOT_VERIFIED"
    SENSITIVITY_EXCEEDED = "SENSITIVITY_EXCEEDED"
    TRANSMISSION_VIOLATED = "TRANSMISSION_VIOLATED"
    GROUP_TOO_SMALL = "GROUP_TOO_SMALL"
    MOSAIC_RISK = "MOSAIC_RISK"
    SSN_ALWAYS_BLOCKED = "SSN_ALWAYS_BLOCKED"
    SELF_ACCESS_ONLY = "SELF_ACCESS_ONLY"
    EVALUATION_ERROR = "EVALUATION_ERROR"
    ESCALATION_REQUIRED = "ESCALATION_REQUIRED"
    FIELD_NOT_FOUND = "FIELD_NOT_FOUND"
    # Extensions added with the phase-7 implementation:
    #: A mandatory protection floor upgraded the policy's action.
    MANDATORY_PROTECTION = "MANDATORY_PROTECTION"
    #: Prompt-injection / override language detected in the purpose claim.
    INJECTION_SUSPECTED = "INJECTION_SUSPECTED"


#: Human-readable explanations, kept alongside the codes for audits.
REASON_TEXTS: dict[ReasonCode, str] = {
    ReasonCode.NORM_MATCHED: "Access authorised by policy: {policy_name}",
    ReasonCode.NO_MATCHING_NORM: (
        "No policy authorises this access for your role and purpose"
    ),
    ReasonCode.INSUFFICIENT_ROLE: (
        "Your role does not have access to this data type"
    ),
    ReasonCode.INVALID_PURPOSE: (
        "The stated purpose is not recognised or not permitted"
    ),
    ReasonCode.PURPOSE_NOT_VERIFIED: (
        "The stated purpose could not be verified server-side"
    ),
    ReasonCode.SENSITIVITY_EXCEEDED: (
        "The data sensitivity exceeds the ceiling of every matching policy"
    ),
    ReasonCode.TRANSMISSION_VIOLATED: (
        "Access condition not met (e.g. not the target's own department)"
    ),
    ReasonCode.GROUP_TOO_SMALL: (
        "Aggregate group has fewer than k members; individual risk"
    ),
    ReasonCode.MOSAIC_RISK: (
        "Repeated aggregate queries risk re-identification; approval required"
    ),
    ReasonCode.SSN_ALWAYS_BLOCKED: (
        "SSN is never accessible through the AI agent interface"
    ),
    ReasonCode.SELF_ACCESS_ONLY: (
        "This data is accessible only for your own record"
    ),
    ReasonCode.EVALUATION_ERROR: (
        "Policy check encountered an error; defaulting to BLOCK"
    ),
    ReasonCode.ESCALATION_REQUIRED: (
        "This access requires approval from a compliance reviewer"
    ),
    ReasonCode.FIELD_NOT_FOUND: (
        "The requested field does not exist in the data source"
    ),
    ReasonCode.MANDATORY_PROTECTION: (
        "A mandatory minimum-protection rule upgraded the disclosure to "
        "a safer form"
    ),
    ReasonCode.INJECTION_SUSPECTED: (
        "Override / identity-claim language detected in the purpose claim"
    ),
}

#: Sensitivity ranking (higher = more sensitive).
_SENSITIVITY_RANK: dict[SensitivityLevel, int] = {
    SensitivityLevel.LOW: 1,
    SensitivityLevel.MEDIUM: 2,
    SensitivityLevel.HIGH: 3,
    SensitivityLevel.RESTRICTED: 4,
}

#: Overall decision strings (docs api-design §4.6).
OVERALL_ALLOW = "ALLOW"
OVERALL_PARTIAL = "PARTIAL_ALLOW"
OVERALL_BLOCK = "BLOCK"
OVERALL_ESCALATION = "ESCALATION_NEEDED"


def _json_list(raw: str | None) -> list[str]:
    """Parse a JSON-list column, tolerating malformed/None values ([])."""
    try:
        value = json.loads(raw or "[]")
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _csv_set(raw: str | None) -> frozenset[str]:
    """Parse a comma-separated setting into a normalised set."""
    if not raw:
        return frozenset()
    return frozenset(
        item.strip().lower() for item in str(raw).split(",") if item.strip()
    )


def _parse_role_hierarchy(raw: str | None) -> dict[str, frozenset[str]]:
    """Parse ``"holder:inherited,holder2:inherited2"`` into a mapping."""
    mapping: dict[str, set[str]] = {}
    for pair in (raw or "").split(","):
        holder, separator, inherited = pair.partition(":")
        holder, inherited = holder.strip(), inherited.strip()
        if separator and holder and inherited:
            mapping.setdefault(holder, set()).add(inherited)
    return {holder: frozenset(values) for holder, values in mapping.items()}


@dataclass(frozen=True)
class FieldDecision:
    """The engine's decision for exactly one requested field."""

    field_name: str
    action: PolicyAction
    reason_code: ReasonCode
    reason: str
    column_name: str | None = None
    sensitivity: str | None = None
    pii_category: str | None = None
    policy_id: str | None = None
    policy_name: str | None = None
    policy_version: int | None = None
    field_type: str | None = None

    @property
    def granted(self) -> bool:
        """True when the action permits some (possibly transformed) data."""
        return self.action in GRANTED_ACTIONS

    @property
    def requires_retrieval(self) -> bool:
        """True when records/values must be fetched for this field."""
        return self.action in GRANTED_ACTIONS

    def to_response_entry(self) -> dict[str, Any]:
        """Response-shaped entry; ``value`` is filled by the connector."""
        return {
            "action": self.action.value,
            "value": None,
            "reason_code": self.reason_code.value,
            "reason": self.reason,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
        }

    def to_audit_dict(self) -> dict[str, Any]:
        """Audit-safe projection (no values, no raw text)."""
        return {
            "field": self.field_name,
            "action": self.action.value,
            "reason_code": self.reason_code.value,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "sensitivity": self.sensitivity,
            "pii_category": self.pii_category,
        }


@dataclass
class PolicyEvaluation:
    """Aggregate result of one policy evaluation run."""

    request_id: str
    entries: list[FieldDecision] = dataclass_field(default_factory=list)
    policies_considered: list[dict[str, Any]] = dataclass_field(default_factory=list)
    flags: list[str] = dataclass_field(default_factory=list)
    evaluated_at: datetime = dataclass_field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # ── Derived summary ─────────────────────────────────────────────

    @property
    def overall_decision(self) -> str:
        """ALLOW | PARTIAL_ALLOW | BLOCK | ESCALATION_NEEDED (docs §4.6).

        AGGREGATE counts as a full grant: statistics were requested and
        produced, nothing was withheld or downgraded.
        """
        if not self.entries:
            return OVERALL_BLOCK
        actions = [entry.action for entry in self.entries]
        if any(action is PolicyAction.ESCALATE for action in actions):
            return OVERALL_ESCALATION
        if all(action is PolicyAction.BLOCK for action in actions):
            return OVERALL_BLOCK
        if all(
            action in {PolicyAction.ALLOW, PolicyAction.AGGREGATE}
            for action in actions
        ):
            return OVERALL_ALLOW
        return OVERALL_PARTIAL

    @property
    def blocked(self) -> bool:
        """True when nothing may be disclosed."""
        return all(not entry.granted for entry in self.entries)

    @property
    def requires_escalation(self) -> bool:
        return any(entry.action is PolicyAction.ESCALATE for entry in self.entries)

    def entry_for(self, field_name: str) -> FieldDecision | None:
        lowered = field_name.lower()
        for entry in self.entries:
            if entry.field_name.lower() == lowered:
                return entry
        return None

    def reason_codes(self) -> list[str]:
        return [entry.reason_code.value for entry in self.entries]

    def to_response_fields(self) -> dict[str, dict[str, Any]]:
        return {entry.field_name: entry.to_response_entry() for entry in self.entries}


class PolicyEngine:
    """Deterministic evaluator; read-only with respect to protected data."""

    def __init__(self, session: AsyncSession, *, settings_obj: Any = None):
        self.session = session
        self.settings = settings_obj or default_settings
        self.authz = AuthorizationService(session)
        self._mask_categories = _csv_set(
            getattr(self.settings, "POLICY_MANDATORY_MASK_CATEGORIES", "phone,email,bank_account,credit_card")
        )
        self._generalize_categories = _csv_set(
            getattr(self.settings, "POLICY_MANDATORY_GENERALIZE_CATEGORIES", "address,date_of_birth")
        )
        self._block_categories = _csv_set(
            getattr(self.settings, "POLICY_MANDATORY_BLOCK_CATEGORIES", "ssn")
        )
        self._role_hierarchy = _parse_role_hierarchy(
            getattr(self.settings, "POLICY_ROLE_HIERARCHY", "")
        )

    # ── Public API ──────────────────────────────────────────────────

    async def evaluate(self, context: AnalyzedContext) -> PolicyEvaluation:
        """Evaluate every requested field; never raises, never returns ALLOW
        unless a policy explicitly authorises it."""
        try:
            return await self._evaluate(context)
        except Exception:  # noqa: BLE001 — fail closed on *any* error
            logger.exception(
                "Policy evaluation failed (request_id=%s); failing closed",
                getattr(context, "request_id", "?"),
            )
            return self._error_evaluation(context)

    # ── Internal evaluation ─────────────────────────────────────────

    async def _evaluate(self, context: AnalyzedContext) -> PolicyEvaluation:
        policies = await self.authz.get_relevant_policies(context.target.resource)

        evaluation = PolicyEvaluation(
            request_id=context.request_id,
            policies_considered=[
                {
                    "id": policy.id,
                    "name": policy.name,
                    "version": policy.version,
                    "action": policy.action,
                    "priority": policy.priority,
                }
                for policy in policies
            ],
        )

        gate = self._global_gate(context)
        if gate is not None:
            action, reason_code, reason = gate
            for requested in context.requested_fields:
                evaluation.entries.append(
                    self._decision(
                        requested,
                        action=action,
                        reason_code=reason_code,
                        reason=reason,
                    )
                )
            return evaluation

        field_metadata = await self._field_metadata(context.target.resource)
        self_subject = bool(
            context.target.ownership.checked and context.target.ownership.allowed
        )
        evaluation.flags.append("self_subject" if self_subject else "third_party")

        for requested in context.requested_fields:
            evaluation.entries.append(
                self._evaluate_field(
                    context,
                    requested,
                    field_metadata=field_metadata,
                    policies=policies,
                    self_subject=self_subject,
                )
            )
        return evaluation

    # ── Mandatory gates (evaluated before any policy) ───────────────

    def _global_gate(
        self, context: AnalyzedContext
    ) -> tuple[PolicyAction, ReasonCode, str] | None:
        """Hard constraints no policy priority can override, or ``None``.

        Order: identity sanity → RBAC → purpose → injection.
        """
        requester = context.requester
        if requester.kind not in {"user", "service"} or not requester.id:
            return (
                PolicyAction.BLOCK,
                ReasonCode.EVALUATION_ERROR,
                "unrecognised requester identity",
            )

        if not context.operation.allowed:
            return (
                PolicyAction.BLOCK,
                ReasonCode.INSUFFICIENT_ROLE,
                f"authorization pre-check failed ({context.operation.reason_code})",
            )

        purpose = context.purpose
        if purpose.normalized is None or not purpose.recognized:
            return (
                PolicyAction.BLOCK,
                ReasonCode.INVALID_PURPOSE,
                REASON_TEXTS[ReasonCode.INVALID_PURPOSE],
            )

        if purpose.injection_suspected:
            return (
                PolicyAction.BLOCK,
                ReasonCode.INJECTION_SUSPECTED,
                "injection signals detected: " + ", ".join(purpose.injection_signals),
            )

        return None

    # ── Field metadata ──────────────────────────────────────────────

    async def _field_metadata(self, resource: str) -> dict[str, Any]:
        """Map ``field_name (lower)`` → catalog field for the resource."""
        from app.repositories import DataAssetRepository

        asset = await DataAssetRepository(self.session).get_by_name_with_fields(
            resource
        )
        if asset is None:
            return {}
        return {field.field_name.lower(): field for field in asset.fields}

    # ── Per-field evaluation ────────────────────────────────────────

    def _evaluate_field(
        self,
        context: AnalyzedContext,
        requested: ContextField,
        *,
        field_metadata: dict[str, Any],
        policies: Sequence[PrivacyPolicy],
        self_subject: bool,
    ) -> FieldDecision:
        meta = field_metadata.get(requested.name.lower())
        if meta is None or not requested.known_in_asset:
            return self._decision(
                requested,
                action=PolicyAction.BLOCK,
                reason_code=ReasonCode.FIELD_NOT_FOUND,
                reason=REASON_TEXTS[ReasonCode.FIELD_NOT_FOUND],
            )

        category = (meta.pii_category or "").lower()
        if category in self._block_categories:
            reason_code = (
                ReasonCode.SSN_ALWAYS_BLOCKED
                if category == "ssn"
                else ReasonCode.MANDATORY_PROTECTION
            )
            return self._decision(
                requested,
                action=PolicyAction.BLOCK,
                reason_code=reason_code,
                reason=REASON_TEXTS[reason_code],
                meta=meta,
            )

        operation = context.operation.normalized or "read"
        purpose = context.purpose.normalized or ""
        is_personal = context.target.resource in PERSONAL_ASSETS
        ownership_asset = context.target.resource in OWNERSHIP_ASSETS
        # Policies without a required_role are self-service norms: they can
        # never authorise a third-party record (including unscoped reads) on
        # an ownership-tracked asset. Customer/order records are tracked too
        # (customers.user_id), so self-service only ever matches the owner.
        third_party = ownership_asset and not self_subject

        roles = self._effective_roles(context)

        candidates: list[PrivacyPolicy] = []
        role_mismatch = False
        ceiling_blocked = False
        roleless_skipped = False

        for policy in policies:
            purposes = _json_list(policy.allowed_purposes)
            if purpose not in purposes and "*" not in purposes:
                continue
            allowed_ops = _json_list(policy.allowed_actions)
            if operation not in allowed_ops and "*" not in allowed_ops:
                continue

            if policy.required_role is None:
                if third_party:
                    roleless_skipped = True
                    continue
            elif policy.required_role not in roles:
                role_mismatch = True
                continue

            # Sensitivity ceiling — not applied to AGGREGATE operations:
            # the output is statistics only (protected by k-anonymity).
            if operation != "aggregate" and policy.min_sensitivity:
                if not self._within_ceiling(meta.sensitivity, policy.min_sensitivity):
                    ceiling_blocked = True
                    continue

            candidates.append(policy)

        if not candidates:
            # Precedence: when a role-matched policy exists but the field is
            # above its sensitivity ceiling, say so precisely; otherwise a
            # skipped role-less self-service norm means the record is not
            # the requester's (or is unscoped), and a missing role is next.
            if ceiling_blocked:
                reason_code = ReasonCode.SENSITIVITY_EXCEEDED
            elif third_party and roleless_skipped:
                reason_code = ReasonCode.SELF_ACCESS_ONLY
            elif role_mismatch:
                reason_code = ReasonCode.INSUFFICIENT_ROLE
            else:
                reason_code = ReasonCode.NO_MATCHING_NORM
            return self._decision(
                requested,
                action=PolicyAction.BLOCK,
                reason_code=reason_code,
                reason=REASON_TEXTS[reason_code],
                meta=meta,
            )

        # Transmission principle: department / organisation scope checks.
        transmission_error = self._transmission_violation(context, is_personal)
        if transmission_error is not None:
            return self._decision(
                requested,
                action=PolicyAction.BLOCK,
                reason_code=ReasonCode.TRANSMISSION_VIOLATED,
                reason=REASON_TEXTS[ReasonCode.TRANSMISSION_VIOLATED]
                + f" ({transmission_error})",
                meta=meta,
            )

        chosen = self._resolve_conflict(candidates)
        action, action_error = self._policy_action(chosen)
        if action_error is not None:
            return self._decision(
                requested,
                action=PolicyAction.BLOCK,
                reason_code=ReasonCode.EVALUATION_ERROR,
                reason=action_error,
                meta=meta,
                policy=chosen,
            )

        # An aggregate request never returns individual rows, even when the
        # matched policy would allow a plain read.
        if operation == "aggregate" and action is PolicyAction.ALLOW:
            action = PolicyAction.AGGREGATE

        # Mandatory protection floors (third-party disclosures only).
        floor_applied = False
        if not self_subject:
            floor = self._protection_floor(category)
            if floor is not None and _RESTRICTIVENESS[floor] > _RESTRICTIVENESS[action]:
                action = floor
                floor_applied = True

        reason_code = ReasonCode.NORM_MATCHED
        if floor_applied:
            reason_code = ReasonCode.MANDATORY_PROTECTION

        # Destination cap: a declared-but-untrusted destination never
        # receives a granted disclosure — it becomes a pending approval.
        # Unrecognised kinds collapse to "unspecified" in the analyzer, so
        # the flag is also consulted.
        destination = context.destination
        destination_untrusted = (
            (destination.kind not in {"unspecified", ""} and not destination.trusted)
            or "DESTINATION_UNRECOGNIZED" in context.flag_codes()
        )
        if destination_untrusted and action not in {
            PolicyAction.BLOCK,
            PolicyAction.ESCALATE,
        }:
            action = PolicyAction.ESCALATE
            reason_code = ReasonCode.ESCALATION_REQUIRED

        reason = REASON_TEXTS[reason_code]
        if reason_code is ReasonCode.NORM_MATCHED:
            reason = reason.format(policy_name=f"{chosen.name} v{chosen.version}")
        elif reason_code is ReasonCode.MANDATORY_PROTECTION:
            reason += f" (category '{category}')"

        return self._decision(
            requested,
            action=action,
            reason_code=reason_code,
            reason=reason,
            meta=meta,
            policy=chosen,
        )

    # ── Helpers ─────────────────────────────────────────────────────

    def _effective_roles(self, context: AnalyzedContext) -> frozenset[str]:
        """Roles held by the requester, expanded through the configured
        role hierarchy. Service accounts contribute ``role:<name>`` scopes."""
        base: set[str] = set(context.requester.roles)
        if context.requester.kind == "service" and context.agent is not None:
            for scope in context.agent.scopes:
                if scope.startswith("role:"):
                    base.add(scope.split(":", 1)[1])
        # Transitive closure over the hierarchy.
        changed = True
        while changed:
            changed = False
            for role in list(base):
                for inherited in self._role_hierarchy.get(role, ()):
                    if inherited not in base:
                        base.add(inherited)
                        changed = True
        return frozenset(base)

    @staticmethod
    def _within_ceiling(
        sensitivity: SensitivityLevel, ceiling: str
    ) -> bool:
        try:
            ceiling_level = SensitivityLevel(str(ceiling).strip().lower())
        except ValueError:
            return False  # unknown ceiling → fail closed for this policy
        return _SENSITIVITY_RANK[sensitivity] <= _SENSITIVITY_RANK[ceiling_level]

    @staticmethod
    def _resolve_conflict(
        candidates: Sequence[PrivacyPolicy],
    ) -> PrivacyPolicy:
        """Deterministic conflict resolution.

        Ordering: priority (desc) → version (desc) → specificity of the
        resource pattern (exact beats wildcard) → most restrictive action.
        """
        def sort_key(policy: PrivacyPolicy) -> tuple:
            try:
                action = PolicyAction((policy.action or "ALLOW").strip().upper())
            except ValueError:
                action = PolicyAction.BLOCK  # unknown action sorts restrictive
            return (
                policy.priority or 0,
                policy.version or 0,
                0 if "*" in (policy.resource_pattern or "") else 1,
                _RESTRICTIVENESS[action],
            )

        return max(candidates, key=sort_key)

    @staticmethod
    def _policy_action(
        policy: PrivacyPolicy,
    ) -> tuple[PolicyAction, str | None]:
        """Parse the policy's action; unknown values fail closed."""
        raw = (policy.action or "ALLOW").strip().upper()
        try:
            return PolicyAction(raw), None
        except ValueError:
            return (
                PolicyAction.BLOCK,
                f"policy '{policy.name}' v{policy.version} declares an "
                f"unrecognised action",
            )

    def _protection_floor(self, category: str) -> PolicyAction | None:
        if category in self._mask_categories:
            return PolicyAction.MASK
        if category in self._generalize_categories:
            return PolicyAction.GENERALIZE
        return None

    @staticmethod
    def _transmission_violation(
        context: AnalyzedContext, is_personal: bool
    ) -> str | None:
        """Check the department/organisation transmission principle.

        Returns a short reason fragment when the flow must be blocked.
        """
        scope = context.target.subject_scope
        if scope == "department":
            if not is_personal:
                return "resource has no department dimension"
            if context.target.department_scope_match is not True:
                return "target department does not match the requester's own"
        if scope == "organization":
            return "organisation-wide disclosure is not authorised"
        return None

    @staticmethod
    def _decision(
        requested: ContextField,
        *,
        action: PolicyAction,
        reason_code: ReasonCode,
        reason: str,
        meta: Any = None,
        policy: PrivacyPolicy | None = None,
    ) -> FieldDecision:
        return FieldDecision(
            field_name=requested.name,
            action=action,
            reason_code=reason_code,
            reason=reason,
            column_name=(
                meta.column_name if meta is not None and meta.column_name else
                (requested.column_name or requested.name)
            ),
            sensitivity=(
                meta.sensitivity.value if meta is not None and meta.sensitivity else None
            ),
            pii_category=(
                (meta.pii_category or None) if meta is not None else None
            ),
            policy_id=policy.id if policy is not None else None,
            policy_name=policy.name if policy is not None else None,
            policy_version=policy.version if policy is not None else None,
            field_type=meta.field_type if meta is not None else None,
        )

    def _error_evaluation(self, context: AnalyzedContext) -> PolicyEvaluation:
        evaluation = PolicyEvaluation(
            request_id=getattr(context, "request_id", "unknown"),
            flags=["evaluation_error"],
        )
        requested_fields = getattr(context, "requested_fields", None) or []
        if not requested_fields:
            requested_fields = [ContextField(name="request", known_in_asset=False)]
        for requested in requested_fields:
            evaluation.entries.append(
                self._decision(
                    requested,
                    action=PolicyAction.BLOCK,
                    reason_code=ReasonCode.EVALUATION_ERROR,
                    reason=REASON_TEXTS[ReasonCode.EVALUATION_ERROR],
                )
            )
        return evaluation

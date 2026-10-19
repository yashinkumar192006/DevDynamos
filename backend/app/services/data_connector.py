"""Protected data connector — runs the secure-request pipeline.

Execution order (mandatory, see Prompt-7 requirements and
``docs/architecture.md`` §6):

1. **Authenticate and resolve identity.** The connector receives the
   verified :class:`~app.services.auth_service.Principal` (never a
   client-supplied identity) — service callers pass the same object the
   gateway resolved from the credential.
2. **Validate request and purpose.** Field count / resource / purpose
   shape are checked before anything else runs.
3. **Evaluate authorization and policy.** The
   :class:`~app.services.policy_engine.PolicyEngine` produces per-field
   decisions; the aggregate guard may escalate repeated queries.
4. **Determine permitted fields and transformations.**
5. **Retrieve only permitted records and fields.** SQL projections
   select exactly the granted columns — blocked fields are never
   fetched (fail closed at the repository layer too).
6. **Transform the retrieved data.** The
   :class:`~app.services.transformer.Transformer` applies the decided
   transformation to real values.
7. **Construct a safe result.**

A blocked request performs **no retrieval** and **never calls the LLM**.
Decisions, transformation events and audit records are persisted with
hashes and previews only — raw sensitive values never enter the audit
trail.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AIInteraction,
    AuditAction,
    BusinessDocument,
    Customer,
    DecisionOutcome,
    Employee,
    Order,
    OutputInspection,
    PrivacyDecision,
    PrivacyRequest,
    RequestPurpose,
    RequestStatus,
    TransformationEvent,
    TransformationType,
)
from app.repositories import (
    AuditRepository,
    BusinessDocumentRepository,
    CustomerRepository,
    EmployeeRepository,
    OrderRepository,
)
from app.repositories.protected_data_repo import MAX_ROWS
from app.services.auth_service import Principal
from app.services.context_service import (
    DEPARTMENT_TARGET_RE,
    ContextAnalyzer,
)
from app.services.policy_engine import (
    OVERALL_ALLOW,
    OVERALL_BLOCK,
    OVERALL_ESCALATION,
    OVERALL_PARTIAL,
    PolicyAction,
    PolicyEngine,
    PolicyEvaluation,
    ReasonCode,
    REASON_TEXTS,
)
from app.services.transformer import AggregateGuard, Transformer, TransformedValue

logger = logging.getLogger(__name__)

#: API contract: 1–50 fields per request (docs/api-design.md §4.6).
MAX_REQUEST_FIELDS = 50

#: Resource name → protected-data repository.
_REPOSITORY_FOR_RESOURCE = {
    "employee_records": EmployeeRepository,
    "employee_salary": EmployeeRepository,
    "employee_contact": EmployeeRepository,
    "customer_records": CustomerRepository,
    "order_records": OrderRepository,
    "financial_docs": BusinessDocumentRepository,
}

#: ORM model per resource (used to validate column names before SELECT).
_MODEL_FOR_RESOURCE = {
    "employee_records": Employee,
    "employee_salary": Employee,
    "employee_contact": Employee,
    "customer_records": Customer,
    "order_records": Order,
    "financial_docs": BusinessDocument,
}

#: Principal kinds the connector accepts.
_ALLOWED_PRINCIPAL_KINDS = frozenset({"user", "service"})


@dataclass
class SecureDataRequest:
    """Input to the connector — all client-supplied fields are untrusted."""

    resource: str
    requested_fields: Sequence[str]
    purpose: str | None
    operation: str = "read"
    purpose_detail: str | None = None
    target_entity: str | None = None
    session_id: str | None = None
    destination_kind: str | None = None
    destination_name: str | None = None
    client_metadata: Mapping[str, Any] | None = None
    include_llm_response: bool = False


@dataclass
class SecureResult:
    """The minimum-disclosure result handed back to the caller."""

    request_id: str
    overall_decision: str
    fields: dict[str, dict[str, Any]] = dataclass_field(default_factory=dict)
    records: list[dict[str, Any]] | None = None
    mosaic_warning: bool = False
    llm_response: str | None = None
    guard_triggered: bool = False
    #: Structured, secret-free LLM/guard metadata (provider, guard action,
    #: finding categories, error codes). ``None`` when no LLM was involved.
    llm: dict[str, Any] | None = None
    audit_id: str | None = None
    retrieved: bool = False
    reason_code: str | None = None
    reason: str | None = None
    timestamp: datetime = dataclass_field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict[str, Any]:
        """Response-shaped projection (docs/api-design.md §4.6)."""
        return {
            "request_id": self.request_id,
            "overall_decision": self.overall_decision,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "fields": self.fields,
            "records": self.records,
            "retrieved": self.retrieved,
            "llm_response": self.llm_response,
            "llm": self.llm,
            "guard_triggered": self.guard_triggered,
            "mosaic_warning": self.mosaic_warning,
            "audit_id": self.audit_id,
            "timestamp": self.timestamp.isoformat(),
        }


#: Optional LLM hook. Either a plain callable receiving the safe
#: (post-policy, already transformed) field map and returning text, or a
#: :class:`~app.services.llm_adapter.SafeLLMService`-like object exposing
#: ``generate_safe`` — the rich path that records guard metadata. Never
#: invoked when nothing was granted.
LLMCallback = Callable[[dict[str, Any]], Awaitable[str]]


class ProtectedDataConnector:
    """Orchestrates the seven-step secure-request pipeline."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        engine: PolicyEngine | None = None,
        analyzer: ContextAnalyzer | None = None,
        transformer: Transformer | None = None,
        aggregate_guard: AggregateGuard | None = None,
        llm: LLMCallback | None = None,
        persist: bool = True,
    ):
        self.session = session
        self.engine = engine or PolicyEngine(session)
        self.analyzer = analyzer or ContextAnalyzer(session)
        self.transformer = transformer or Transformer()
        self.aggregate_guard = aggregate_guard or AggregateGuard(
            repeat_limit=getattr(self.engine.settings, "POLICY_AGGREGATE_REPEAT_LIMIT", 5),
            window_seconds=getattr(self.engine.settings, "POLICY_AGGREGATE_WINDOW_SECONDS", 300),
        )
        self.llm = llm
        self.persist = persist
        self.audit = AuditRepository(session)

    # ── Public API ──────────────────────────────────────────────────

    async def execute(
        self, principal: Principal | None, request: SecureDataRequest
    ) -> SecureResult:
        """Run the full pipeline; never raises, always fails closed."""
        try:
            return await self._execute(principal, request)
        except Exception:  # noqa: BLE001 — fail closed on any internal error
            logger.exception("Secure request failed; returning fail-closed BLOCK")
            request_id = getattr(request, "session_id", None) or "unknown"
            return SecureResult(
                request_id=str(request_id),
                overall_decision=OVERALL_BLOCK,
                reason_code=ReasonCode.EVALUATION_ERROR.value,
                reason=REASON_TEXTS[ReasonCode.EVALUATION_ERROR],
            )

    # ── Pipeline ────────────────────────────────────────────────────

    async def _execute(
        self, principal: Principal | None, request: SecureDataRequest
    ) -> SecureResult:
        # 1. Authenticate / resolve identity — the principal is always the
        #    server-verified object; anything else fails closed.
        if (
            principal is None
            or not getattr(principal, "id", None)
            or principal.kind not in _ALLOWED_PRINCIPAL_KINDS
        ):
            return SecureResult(
                request_id="unauthenticated",
                overall_decision=OVERALL_BLOCK,
                reason_code=ReasonCode.INSUFFICIENT_ROLE.value,
                reason="no verified identity for this request",
            )

        # 2. Validate request and purpose shape.
        validation_error = self._validate_request(request)
        if validation_error is not None:
            reason_code, reason = validation_error
            return SecureResult(
                request_id=request.session_id or "invalid",
                overall_decision=OVERALL_BLOCK,
                reason_code=reason_code.value,
                reason=reason,
            )

        # 3. Evaluate authorization and policy (context → engine → guard).
        context = await self.analyzer.analyze(
            principal,
            resource=request.resource,
            operation=request.operation,
            purpose=request.purpose,
            purpose_detail=request.purpose_detail,
            requested_fields=list(request.requested_fields),
            target_entity=request.target_entity,
            destination_kind=request.destination_kind,
            destination_name=request.destination_name,
            client_metadata=request.client_metadata,
        )
        evaluation = await self.engine.evaluate(context)

        # 4. Determine permitted fields and transformation; the repeated-
        #    aggregate control can escalate field decisions here.
        mosaic_warning = self._apply_aggregate_guard(evaluation, context, request)

        # 5. Retrieve only permitted records and fields (none when blocked).
        session_key = (
            context.conversation.session_id
            or request.session_id
            or principal.id
        )
        retrieval, aggregate_values = await self._retrieve(context, evaluation)

        # 5b. Aggregate safeguards: groups below the minimum size are
        #     suppressed (GROUP_TOO_SMALL) before anything is assembled.
        aggregate_stats = self._resolve_aggregates(evaluation, aggregate_values)

        # 6. Transform the retrieved data.
        records_out, transformed = self.transformer.transform_records(
            retrieval, evaluation.entries, session_id=session_key
        )

        # 7. Construct the safe result.
        fields_out = self._assemble_fields(evaluation, aggregate_stats)
        if len(records_out) == 1:
            for name, value in records_out[0].items():
                if name in fields_out:
                    fields_out[name]["value"] = value

        llm_response: str | None = None
        llm_outcome = None
        if (
            request.include_llm_response
            and self.llm is not None
            and evaluation.overall_decision in {OVERALL_ALLOW, OVERALL_PARTIAL}
        ):
            # Only safe, already-transformed values ever reach the model, and
            # never at all when the request was blocked or pending escalation.
            llm_response, llm_outcome = await self._run_llm(
                fields_out,
                records_out,
                evaluation=evaluation,
                context=context,
                transformed=transformed,
            )

        audit_id = await self._persist(
            principal=principal,
            request=request,
            context=context,
            evaluation=evaluation,
            transformed=transformed,
            mosaic_warning=mosaic_warning,
            llm_outcome=llm_outcome,
        )

        result_decision = evaluation.overall_decision
        if llm_outcome is not None and llm_outcome.requires_escalation:
            # The output guard withheld the model response pending review;
            # reflect that in the request decision.
            result_decision = OVERALL_ESCALATION
        return SecureResult(
            request_id=context.request_id,
            overall_decision=result_decision,
            fields=fields_out,
            records=records_out or None,
            mosaic_warning=mosaic_warning,
            llm_response=llm_response,
            guard_triggered=bool(llm_outcome and llm_outcome.guard_triggered),
            llm=llm_outcome.to_dict() if llm_outcome is not None else None,
            audit_id=audit_id,
            retrieved=bool(retrieval),
            reason_code=(
                evaluation.entries[0].reason_code.value if evaluation.entries else None
            ),
        )

    # ── Steps 8–10: safe context → provider → output inspection ────

    async def _run_llm(
        self,
        fields_out: dict[str, dict[str, Any]],
        records_out: list[dict[str, Any]],
        *,
        evaluation: PolicyEvaluation,
        context: Any,
        transformed: Sequence[TransformedValue],
    ) -> tuple[str | None, Any]:
        """Invoke the LLM hook and return ``(sanctioned_text, outcome)``.

        Rich hooks (objects exposing ``generate_safe`` — e.g.
        ``SafeLLMService``) receive the permitted-disclosure set plus the
        protected source values behind masked/generalized/tokenized fields
        so the output guard can compare the model text against both. Plain
        callables keep the legacy behaviour (no guard metadata).
        """
        service = self.llm
        try:
            if service is not None and hasattr(service, "generate_safe"):
                allowed_values = self._collect_allowed_values(
                    fields_out, records_out
                )
                protected_values = [
                    outcome.source_value
                    for outcome in transformed
                    if outcome.transformation_type is not None
                    and outcome.source_value is not None
                ]
                outcome = await service.generate_safe(
                    fields_out,
                    records=records_out or None,
                    allowed_values=allowed_values,
                    protected_values=protected_values,
                    purpose=context.purpose.normalized,
                    resource=context.target.resource,
                    withheld_count=sum(
                        1 for entry in evaluation.entries if not entry.granted
                    ),
                )
                return outcome.text, outcome
            # Legacy callable hook — no structured guard metadata.
            text = await service(fields_out)  # type: ignore[misc]
            return (str(text) if text is not None else None), None
        except Exception:  # noqa: BLE001 — the disclosure already happened;
            # do not fail the whole response over the LLM stage.
            logger.warning(
                "LLM path failed for request %s",
                context.request_id,
                exc_info=True,
            )
            return None, None

    @staticmethod
    def _collect_allowed_values(
        fields_out: Mapping[str, Mapping[str, Any]],
        records_out: Sequence[Mapping[str, Any]],
    ) -> list[str]:
        """String forms of every value that was actually disclosed."""
        values: list[str] = []

        def _add(value: Any) -> None:
            if value is None:
                return
            if isinstance(value, str):
                values.append(value)
            elif isinstance(value, (int, float, bool)):
                values.append(str(value))
            elif isinstance(value, (list, tuple)):
                for item in value:
                    _add(item)

        for entry in fields_out.values():
            if not isinstance(entry, Mapping):
                continue
            if str(entry.get("action") or "").upper() in {"BLOCK", "ESCALATE"}:
                continue
            value = entry.get("value")
            if isinstance(value, Mapping):
                for item in value.values():
                    _add(item)
            else:
                _add(value)
        for record in records_out or ():
            for value in record.values():
                _add(value)
        return values

    # ── Step 2: validation ──────────────────────────────────────────

    @staticmethod
    def _validate_request(
        request: SecureDataRequest,
    ) -> tuple[ReasonCode, str] | None:
        if not request.resource or not str(request.resource).strip():
            return (
                ReasonCode.EVALUATION_ERROR,
                "request invalid: no resource specified",
            )
        fields = [str(f) for f in request.requested_fields or () if str(f).strip()]
        if not fields:
            return (
                ReasonCode.EVALUATION_ERROR,
                "request invalid: no fields requested",
            )
        if len(fields) > MAX_REQUEST_FIELDS:
            return (
                ReasonCode.EVALUATION_ERROR,
                f"request invalid: more than {MAX_REQUEST_FIELDS} fields requested",
            )
        if not request.purpose or not str(request.purpose).strip():
            return (
                ReasonCode.INVALID_PURPOSE,
                "purpose is required and must be an explicitly stated purpose",
            )
        return None

    # ── Step 4: aggregate guard ─────────────────────────────────────

    def _apply_aggregate_guard(
        self,
        evaluation: PolicyEvaluation,
        context: Any,
        request: SecureDataRequest,
    ) -> bool:
        """Escalate repeated identical aggregate queries (MOSAIC_RISK)."""
        aggregate_entries = [
            entry for entry in evaluation.entries if entry.action is PolicyAction.AGGREGATE
        ]
        if not aggregate_entries:
            return False
        session_key = context.conversation.session_id or request.session_id
        signature = AggregateGuard.signature(
            session_id=session_key,
            resource=context.target.resource,
            scope=context.target.target_entity,
            fields=[entry.field_name for entry in aggregate_entries],
        )
        if self.aggregate_guard.allow(signature):
            return False
        # Repeated-query inference control tripped: withhold the statistics
        # pending human review rather than returning them again.
        escalate_names = {entry.field_name.lower() for entry in aggregate_entries}
        evaluation.entries = [
            replace(
                entry,
                action=PolicyAction.ESCALATE,
                reason_code=ReasonCode.MOSAIC_RISK,
                reason=REASON_TEXTS[ReasonCode.MOSAIC_RISK],
            )
            if entry.field_name.lower() in escalate_names
            else entry
            for entry in evaluation.entries
        ]
        evaluation.flags.append("mosaic_guard")
        return True

    # ── Step 5: retrieval ───────────────────────────────────────────

    async def _retrieve(
        self, context: Any, evaluation: PolicyEvaluation
    ) -> tuple[list[dict[str, Any]], dict[str, list[Any]]]:
        """Fetch only the granted columns, respecting row scoping.

        Returns ``(rows, aggregate_source_values)``. Blocked requests
        produce two empty containers without touching the database.
        """
        if evaluation.blocked:
            return [], {}

        resource = context.target.resource
        repository_class = _REPOSITORY_FOR_RESOURCE.get(resource)
        model = _MODEL_FOR_RESOURCE.get(resource)
        if repository_class is None or model is None:
            return [], {}

        granted = [
            entry for entry in evaluation.entries if entry.requires_retrieval
        ]
        if not granted:
            return [], {}

        known_columns = {column.key for column in model.__mapper__.columns}
        columns: list[str] = []
        for entry in granted:
            column = entry.column_name or entry.field_name
            if column not in known_columns:
                # Fail closed: a granted field with no physical column is a
                # configuration error and must not widen the SELECT.
                logger.error(
                    "Granted field '%s' maps to unknown column '%s'",
                    entry.field_name,
                    column,
                )
                return [], {}
            if column not in columns:
                columns.append(column)

        repository = repository_class(self.session)
        filters = self._row_filters(context, resource)
        rows = await repository.fetch_permitted_records(
            columns, limit=MAX_ROWS, **filters
        )

        aggregate_sources: dict[str, list[Any]] = {}
        for entry in granted:
            if entry.action is PolicyAction.AGGREGATE:
                column = entry.column_name or entry.field_name
                aggregate_sources[entry.field_name] = [
                    row.get(column) for row in rows
                ]
        return rows, aggregate_sources

    @staticmethod
    def _row_filters(context: Any, resource: str) -> dict[str, Any]:
        """Row-level scoping predicates derived from the trusted context."""
        target = context.target.target_entity
        filters: dict[str, Any] = {}

        if context.target.ownership.checked and context.target.ownership.allowed:
            # Self-service on employee assets: enforce the ownership link in
            # SQL. Customer/order self-service falls through to the normal
            # target filters below — the ownership match already proved the
            # target record belongs to the requester.
            if resource in {"employee_records", "employee_salary", "employee_contact"}:
                filters["user_id"] = context.requester.id
                return filters
            if not target:
                # Defensive: an ownership-matched read without a target must
                # not widen into a full-table read.
                return filters

        if not target:
            return filters

        department = DEPARTMENT_TARGET_RE.match(target)
        if department is not None:
            if resource in {"employee_records", "employee_salary", "employee_contact"}:
                filters["department"] = department.group("dept").strip()
            return filters

        lowered = target.lower()
        if lowered in {"*", "all", "organization", "org", "department-all"}:
            return filters  # policy engine blocks these; no widening here

        if resource in {"employee_records", "employee_salary", "employee_contact"}:
            filters["employee_number"] = target
        elif resource == "customer_records":
            filters["customer_number"] = target
        elif resource == "order_records":
            if target.upper().startswith("ORD"):
                filters["order_number"] = target
            elif target.upper().startswith("CUS"):
                filters["customer_number"] = target
        elif resource == "financial_docs":
            filters["document_number"] = target
        return filters

    # ── Step 7: result assembly ─────────────────────────────────────

    def _resolve_aggregates(
        self,
        evaluation: PolicyEvaluation,
        aggregate_values: dict[str, list[Any]],
    ) -> dict[str, Any]:
        """Compute aggregate statistics and suppress small groups.

        Groups smaller than the configured minimum size are downgraded to
        ``BLOCK / GROUP_TOO_SMALL`` (the count itself is sensitive), which
        also updates the overall decision and what gets persisted.
        """
        stats_by_field: dict[str, Any] = {}
        suppressed: set[str] = set()
        for entry in evaluation.entries:
            if entry.action is not PolicyAction.AGGREGATE:
                continue
            stats = self.transformer.aggregate_values(
                aggregate_values.get(entry.field_name, [])
            )
            if stats is None:
                suppressed.add(entry.field_name.lower())
            else:
                stats_by_field[entry.field_name] = stats
        if suppressed:
            evaluation.entries = [
                replace(
                    entry,
                    action=PolicyAction.BLOCK,
                    reason_code=ReasonCode.GROUP_TOO_SMALL,
                    reason=REASON_TEXTS[ReasonCode.GROUP_TOO_SMALL],
                )
                if entry.field_name.lower() in suppressed
                else entry
                for entry in evaluation.entries
            ]
            evaluation.flags.append("small_group_suppressed")
        return stats_by_field

    def _assemble_fields(
        self,
        evaluation: PolicyEvaluation,
        aggregate_stats: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        """Build per-field response entries; aggregates carry statistics."""
        fields_out: dict[str, dict[str, Any]] = {}
        for entry in evaluation.entries:
            response_entry = entry.to_response_entry()
            if entry.action is PolicyAction.AGGREGATE:
                stats = aggregate_stats.get(entry.field_name)
                response_entry["value"] = stats.to_dict() if stats is not None else None
            fields_out[entry.field_name] = response_entry
        return fields_out

    # ── Audit persistence ───────────────────────────────────────────

    def _build_audit_detail(
        self,
        *,
        principal: Principal,
        request: SecureDataRequest,
        context: Any,
        evaluation: PolicyEvaluation,
        transformed: Sequence[TransformedValue],
        mosaic_warning: bool,
        llm_outcome: Any | None,
    ) -> dict[str, Any]:
        """Structured, safe audit summary for one gateway decision.

        Contains identifiers, reason codes, policy versions, transformation
        *types* and model metadata only — never raw protected values, raw
        prompts, purpose free text, credentials, or tokens.
        """
        requester: dict[str, Any] = {
            "id": principal.id,
            "kind": principal.kind,
            "name": principal.display_name,
            "authentication": context.requester.authentication,
        }
        if principal.kind == "user":
            requester["roles"] = sorted(principal.roles)
        else:
            requester["scopes"] = sorted(principal.scopes)

        correlation = {
            key: getattr(context.conversation, key)
            for key in (
                "session_id",
                "conversation_id",
                "task_id",
                "turn_index",
                "agent_name",
            )
            if getattr(context.conversation, key) is not None
        }

        transformations: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for outcome in transformed:
            if outcome.transformation_type is None:
                continue
            key = (outcome.field_name, outcome.transformation_type)
            if key in seen:
                continue
            seen.add(key)
            transformations.append(
                {
                    "field": outcome.field_name,
                    "transformation": outcome.transformation_type,
                }
            )

        detail: dict[str, Any] = {
            "request_id": context.request_id,
            "purpose": context.purpose.normalized,
            "purpose_recognized": bool(context.purpose.recognized),
            "operation": context.operation.normalized or request.operation,
            "requester": requester,
            "agent": (
                {
                    "id": context.agent.id,
                    "kind": context.agent.kind,
                    "name": context.agent.name,
                    "scopes": list(context.agent.scopes),
                }
                if context.agent is not None
                else None
            ),
            "correlation": correlation,
            "target": {
                "resource": context.target.resource,
                "resource_id": context.target.target_entity,
                "subject_scope": context.target.subject_scope,
            },
            "overall_decision": evaluation.overall_decision,
            "reason_codes": evaluation.reason_codes(),
            "flags": list(evaluation.flags),
            "decisions": [entry.to_audit_dict() for entry in evaluation.entries],
            "transformations": transformations,
            "mosaic_warning": mosaic_warning,
            "requested_fields": [entry.field_name for entry in evaluation.entries],
            "model_requested": bool(request.include_llm_response),
            "model_invoked": bool(llm_outcome is not None and llm_outcome.invoked),
        }
        if llm_outcome is not None:
            detail["llm"] = {
                "requested": llm_outcome.requested,
                "invoked": llm_outcome.invoked,
                "provider": llm_outcome.provider,
                "model": llm_outcome.model,
                "guard_triggered": llm_outcome.guard_triggered,
                "guard_action": llm_outcome.guard_action,
                "guard_reason_code": llm_outcome.guard_reason_code,
                "error_code": llm_outcome.error_code,
            }
        return detail

    async def _persist(
        self,
        *,
        principal: Principal,
        request: SecureDataRequest,
        context: Any,
        evaluation: PolicyEvaluation,
        transformed: Sequence[TransformedValue],
        mosaic_warning: bool,
        llm_outcome: Any | None = None,
    ) -> str | None:
        """Write request / decision / transformation / audit records.

        Every gateway decision — user or agent, granted or denied — produces
        one audit event (``actor_kind`` = ``"user"`` | ``"service"``) whose
        detail carries identifiers, reason codes, policy versions,
        transformation types and model metadata only.

        Full decision-graph rows (``privacy_requests`` / ``privacy_decisions``
        / ``transformation_events`` / ``ai_interactions``) reference
        ``users.id``, so they are written only for human requesters with a
        recognized purpose; agent and unrecognized-purpose activity is
        recorded as a safe audit event alone. LLM interactions are recorded
        as ``ai_interactions`` / ``output_inspections`` rows plus ``ai_query``
        and ``output_inspection`` audit events — metadata only (provider,
        model, guard action, finding categories); prompts and raw values are
        represented by hashes at most.
        """
        if not self.persist:
            return None

        audit_detail = self._build_audit_detail(
            principal=principal,
            request=request,
            context=context,
            evaluation=evaluation,
            transformed=transformed,
            mosaic_warning=mosaic_warning,
            llm_outcome=llm_outcome,
        )

        outcome_text = "success" if not evaluation.blocked else "denied"
        if evaluation.requires_escalation:
            outcome_text = "escalated"

        purpose_usable = (
            context.purpose.recognized and context.purpose.normalized is not None
        )
        if principal.kind != "user" or not purpose_usable:
            audit_event = await self.audit.log_event(
                actor_id=principal.id,
                actor_kind=principal.kind,
                action=(
                    AuditAction.DATA_ACCESS
                    if not evaluation.blocked
                    else AuditAction.DATA_DENIED
                ),
                resource=context.target.resource,
                resource_id=context.target.target_entity,
                outcome=outcome_text,
                detail=json.dumps(audit_detail),
                session_id=context.conversation.session_id,
            )
            return audit_event.id

        requested_fields = [entry.field_name for entry in evaluation.entries]
        denied_fields = [
            entry.field_name for entry in evaluation.entries if not entry.granted
        ]
        granted_fields = [
            entry.field_name for entry in evaluation.entries if entry.granted
        ]

        purpose_enum = RequestPurpose(context.purpose.normalized)
        decision_outcome = {
            "ALLOW": DecisionOutcome.ALLOW,
            "PARTIAL_ALLOW": DecisionOutcome.ALLOW_PARTIAL,
            "BLOCK": DecisionOutcome.DENY,
            "ESCALATION_NEEDED": DecisionOutcome.ESCALATE,
        }[evaluation.overall_decision]
        request_status = {
            "ALLOW": RequestStatus.APPROVED,
            "PARTIAL_ALLOW": RequestStatus.APPROVED,
            "BLOCK": RequestStatus.DENIED,
            "ESCALATION_NEEDED": RequestStatus.ESCALATED,
        }[evaluation.overall_decision]

        privacy_request = PrivacyRequest(
            requester_id=principal.id,
            resource=context.target.resource,
            action=request.operation,
            purpose=purpose_enum,
            purpose_detail=request.purpose_detail,
            status=request_status,
        )
        self.session.add(privacy_request)
        await self.session.flush()

        applied_policy_ids = {
            entry.policy_id for entry in evaluation.entries if entry.policy_id
        }
        decision = PrivacyDecision(
            request_id=privacy_request.id,
            policy_id=next(iter(applied_policy_ids), None),
            outcome=decision_outcome,
            reason=json.dumps(
                {
                    "reason_codes": evaluation.reason_codes(),
                    "flags": evaluation.flags,
                    "mosaic_warning": mosaic_warning,
                }
            ),
            allowed_fields=json.dumps(granted_fields),
            denied_fields=json.dumps(denied_fields),
            transformations_applied=json.dumps(
                [entry.to_audit_dict() for entry in evaluation.entries]
            ),
            decided_by="policy_engine",
        )
        self.session.add(decision)
        await self.session.flush()

        # One transformation event per (field, transformation); raw values
        # are represented by hashes and safe previews only.
        seen: set[tuple[str, str]] = set()
        for outcome in transformed:
            if outcome.transformation_type is None:
                continue
            key = (outcome.field_name, outcome.transformation_type)
            if key in seen:
                continue
            seen.add(key)
            self.session.add(
                TransformationEvent(
                    decision_id=decision.id,
                    field_name=outcome.field_name,
                    transformation_type=TransformationType(
                        outcome.transformation_type
                    ),
                    original_hash=outcome.original_hash,
                    transformed_preview=outcome.preview,
                )
            )

        audit_event = await self.audit.log_event(
            actor_id=principal.id,
            actor_kind="user",
            action=(
                AuditAction.DATA_ACCESS
                if not evaluation.blocked
                else AuditAction.DATA_DENIED
            ),
            resource=context.target.resource,
            resource_id=context.target.target_entity,
            outcome=outcome_text,
            detail=json.dumps(audit_detail),
            session_id=context.conversation.session_id,
        )

        if llm_outcome is not None and llm_outcome.invoked:
            await self._persist_ai_interaction(
                principal=principal,
                context=context,
                decision=decision,
                llm_outcome=llm_outcome,
            )
        return audit_event.id

    async def _persist_ai_interaction(
        self,
        *,
        principal: Principal,
        context: Any,
        decision: PrivacyDecision,
        llm_outcome: Any,
    ) -> None:
        """Record one AI interaction and its output inspection.

        The prompt is represented by ``prompt_hash`` only; finding summaries
        carry categories/rules — never matched values.
        """
        response_words = None
        if llm_outcome.text:
            response_words = len(str(llm_outcome.text).split())

        interaction = AIInteraction(
            user_id=principal.id,
            session_id=context.conversation.session_id,
            model_name=llm_outcome.model,
            prompt_hash=llm_outcome.prompt_hash,
            response_token_count=response_words,
            resources_accessed=json.dumps([context.target.resource]),
            privacy_decisions=json.dumps([decision.id]),
            completed_at=datetime.now(timezone.utc),
        )
        self.session.add(interaction)
        await self.session.flush()

        findings = list(llm_outcome.guard_findings or ())
        redacted = [f for f in findings if not f.get("permitted")]
        passed = not llm_outcome.guard_triggered
        self.session.add(
            OutputInspection(
                interaction_id=interaction.id,
                check_type="pii_scan",
                passed=passed,
                findings_summary=(
                    json.dumps(
                        {
                            "action": llm_outcome.guard_action,
                            "reason_code": llm_outcome.guard_reason_code,
                            "findings": [
                                {
                                    "category": f.get("category"),
                                    "rule": f.get("rule"),
                                    "permitted": f.get("permitted"),
                                }
                                for f in findings
                            ],
                        }
                    )
                    if findings
                    else None
                ),
                entities_detected_count=len(redacted),
                action_taken=(
                    llm_outcome.guard_action
                    if llm_outcome.guard_triggered
                    else "none"
                ),
            )
        )
        await self.session.flush()

        await self.audit.log_event(
            actor_id=principal.id,
            actor_kind=principal.kind,
            action=AuditAction.AI_QUERY,
            resource=context.target.resource,
            resource_id=context.target.target_entity,
            outcome="success" if not llm_outcome.error_code else "failed",
            detail=json.dumps(
                {
                    "request_id": context.request_id,
                    "provider": llm_outcome.provider,
                    "model": llm_outcome.model,
                    "error_code": llm_outcome.error_code,
                }
            ),
            session_id=context.conversation.session_id,
        )
        await self.audit.log_event(
            actor_id=principal.id,
            actor_kind=principal.kind,
            action=AuditAction.OUTPUT_INSPECTION,
            resource=context.target.resource,
            resource_id=context.target.target_entity,
            outcome="passed" if passed else "flagged",
            detail=json.dumps(
                {
                    "request_id": context.request_id,
                    "check_type": "pii_scan",
                    "action_taken": llm_outcome.guard_action,
                    "reason_code": llm_outcome.guard_reason_code,
                    "categories": sorted(
                        {
                            str(f.get("category"))
                            for f in redacted
                            if f.get("category")
                        }
                    ),
                }
            ),
            session_id=context.conversation.session_id,
        )

"""Request/response schemas for the secure-request API.

``POST /api/v1/privacy/secure-request`` is the public entry point of the
privacy pipeline (docs/api-design.md §4.6). The request schema validates the
*shape* of client input; everything semantic (identity, authorization,
purpose validity, policy decisions) is enforced server-side by the
deterministic pipeline in :mod:`app.services.data_connector`.

Notes on the implemented contract
=================================

* ``resource`` is required: the connector and policy engine address data by
  catalog resource (``employee_salary``, ``order_records``, …).
* ``operation`` is limited to ``read`` / ``aggregate`` — the two operations
  the minimum-disclosure pipeline implements.
* ``destination`` is deliberately **not** client-settable; destinations are
  server-declared context (docs/security-model.md §4). Clients may supply
  correlation metadata only.
* Response entries mirror the documented shape
  (``action``/``value``/``reason_code``/``policy_id``/``policy_version``)
  plus structured LLM/guard metadata — never secrets, prompts, or
  unauthorized values.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:  # pragma: no cover — typing only; avoids an import cycle
    from app.services.data_connector import SecureDataRequest, SecureResult

#: Correlation metadata only — identity/purpose claims never live here.
_CLAIM_KEY_BLOCKLIST = frozenset(
    {
        "role",
        "roles",
        "is_admin",
        "admin",
        "clearance",
        "permission",
        "permissions",
        "scope",
        "scopes",
        "user_id",
        "requester_id",
        "actor_id",
        "purpose_override",
    }
)


class SecureRequestContext(BaseModel):
    """Optional correlation + untrusted metadata accompanying the request."""

    model_config = ConfigDict(extra="ignore")

    session_id: str | None = Field(None, max_length=64)
    conversation_id: str | None = Field(None, max_length=64)
    task_id: str | None = Field(None, max_length=64)
    turn_index: int | None = Field(None, ge=0, le=100_000)
    agent_name: str | None = Field(None, max_length=100)
    #: Free-form untrusted claims. Values are recorded as metadata only and
    #: are never treated as evidence of identity or permission.
    additional_claims: dict[str, Any] = Field(default_factory=dict)

    @field_validator("session_id", "conversation_id", "task_id", "agent_name")
    @classmethod
    def _strip_optional(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("additional_claims")
    @classmethod
    def _bound_claims(cls, claims: dict[str, Any]) -> dict[str, Any]:
        if len(claims) > 50:
            raise ValueError("additional_claims may contain at most 50 keys")
        cleaned: dict[str, Any] = {}
        for raw_key, value in claims.items():
            key = str(raw_key).strip()[:100]
            if not key:
                continue
            if key.lower() in _CLAIM_KEY_BLOCKLIST:
                # Authorization-looking claims are dropped at the edge; the
                # pipeline would ignore their values anyway.
                continue
            if isinstance(value, (dict, list)):
                raise ValueError(
                    f"additional_claims['{key}'] must be a scalar value"
                )
            cleaned[key] = value
        return cleaned


class SecureRequestPayload(BaseModel):
    """Validated secure-request body (all fields untrusted)."""

    model_config = ConfigDict(extra="ignore")

    resource: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Catalog resource (e.g. employee_salary, order_records)",
    )
    data_fields: list[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Field names being requested (1–50)",
    )
    purpose: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Claimed purpose; validated server-side against policy",
    )
    operation: Literal["read", "aggregate"] = Field(
        "read", description="Retrieval operation the pipeline implements"
    )
    target_entity: str | None = Field(
        None, max_length=100, description="Record key the request targets"
    )
    purpose_detail: str | None = Field(None, max_length=500)
    context: SecureRequestContext | None = None
    include_llm_response: bool = False

    @field_validator("resource", "purpose")
    @classmethod
    def _strip_required(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("must not be blank")
        return cleaned

    @field_validator("data_fields")
    @classmethod
    def _clean_fields(cls, fields: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw in fields:
            name = str(raw).strip()
            if not name:
                raise ValueError("data_fields must not contain blank names")
            if len(name) > 200:
                raise ValueError("field names must be at most 200 characters")
            if name.lower() in seen:
                continue
            seen.add(name.lower())
            cleaned.append(name)
        if not cleaned:
            raise ValueError("at least one field must be requested")
        return cleaned

    @field_validator("target_entity")
    @classmethod
    def _strip_target(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("purpose_detail")
    @classmethod
    def _strip_detail(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    def to_connector_request(self) -> "SecureDataRequest":
        """Translate validated input into the pipeline's request object."""
        # Imported lazily: keeps the schema module free of service-layer
        # import cycles at package import time.
        from app.services.data_connector import SecureDataRequest

        context = self.context
        metadata: dict[str, Any] = {}
        session_id: str | None = None
        if context is not None:
            session_id = context.session_id
            if context.session_id:
                metadata["session_id"] = context.session_id
            if context.conversation_id:
                metadata["conversation_id"] = context.conversation_id
            if context.task_id:
                metadata["task_id"] = context.task_id
            if context.turn_index is not None:
                metadata["turn_index"] = context.turn_index
            if context.agent_name:
                metadata["agent_name"] = context.agent_name
            metadata.update(context.additional_claims)

        return SecureDataRequest(
            resource=self.resource,
            requested_fields=list(self.data_fields),
            purpose=self.purpose,
            operation=self.operation,
            purpose_detail=self.purpose_detail,
            target_entity=self.target_entity,
            session_id=session_id,
            # Destination is server-declared only; clients cannot set it.
            client_metadata=metadata or None,
            include_llm_response=self.include_llm_response,
        )


# ──────────────────────────────────────────────────────────────────────
# Response models
# ──────────────────────────────────────────────────────────────────────


class FieldDecisionResponse(BaseModel):
    """One per-field decision — safe transformation metadata included."""

    action: str
    value: Any = None
    reason_code: str | None = None
    reason: str | None = None
    policy_id: str | None = None
    policy_version: int | None = None


class GuardFindingResponse(BaseModel):
    """Guard finding metadata — category/rule/span, never matched text."""

    category: str | None = None
    rule: str | None = None
    permitted: bool = False
    start: int | None = None
    end: int | None = None
    redacted_as: str | None = None


class LLMGuardResponse(BaseModel):
    triggered: bool = False
    action: str = "none"
    reason_code: str | None = None
    findings: list[GuardFindingResponse] = Field(default_factory=list)


class LLMInfoResponse(BaseModel):
    """Structured LLM stage info (provider/model/guard/error code)."""

    requested: bool = True
    invoked: bool = False
    provider: str | None = None
    model: str | None = None
    error_code: str | None = None
    error: str | None = None
    guard: LLMGuardResponse | None = None


class SecureRequestResponse(BaseModel):
    """Secure-request result as returned to the caller (and the SDK)."""

    request_id: str
    overall_decision: str
    reason_code: str | None = None
    reason: str | None = None
    fields: dict[str, FieldDecisionResponse] = Field(default_factory=dict)
    records: list[dict[str, Any]] | None = None
    retrieved: bool = False
    llm_response: str | None = None
    llm: LLMInfoResponse | None = None
    guard_triggered: bool = False
    mosaic_warning: bool = False
    audit_id: str | None = None
    timestamp: datetime

    @classmethod
    def from_result(cls, result: "SecureResult") -> "SecureRequestResponse":
        fields: dict[str, FieldDecisionResponse] = {}
        for name, entry in (result.fields or {}).items():
            if isinstance(entry, Mapping):
                fields[str(name)] = FieldDecisionResponse(**entry)
            else:  # pragma: no cover — defensive
                fields[str(name)] = FieldDecisionResponse(action=str(entry))

        llm_info: LLMInfoResponse | None = None
        if result.llm is not None:
            llm_info = LLMInfoResponse(**dict(result.llm))

        return cls(
            request_id=result.request_id,
            overall_decision=result.overall_decision,
            reason_code=result.reason_code,
            reason=result.reason,
            fields=fields,
            records=result.records,
            retrieved=result.retrieved,
            llm_response=result.llm_response,
            llm=llm_info,
            guard_triggered=result.guard_triggered,
            mosaic_warning=result.mosaic_warning,
            audit_id=result.audit_id,
            timestamp=result.timestamp,
        )


__all__ = [
    "FieldDecisionResponse",
    "GuardFindingResponse",
    "LLMGuardResponse",
    "LLMInfoResponse",
    "SecureRequestContext",
    "SecureRequestPayload",
    "SecureRequestResponse",
]

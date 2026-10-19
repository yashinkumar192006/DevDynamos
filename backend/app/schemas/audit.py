"""Schemas for the audit trail APIs (docs/api-design.md §4.8–4.9).

The audit trail is a *safe* record by construction: events never store raw
protected values, credentials, tokens, or complete private prompts/outputs.
These schemas expose an allowlisted projection of the stored event — the
response shape is fixed here, so nothing outside it can leak even if the
underlying ``detail`` JSON grows.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AuditActorInfo(BaseModel):
    """Verified actor identity, resolved live from trusted state.

    ``kind`` is ``"user"`` (human) or ``"service"`` (agent/service account).
    Roles are shown for users, scopes for service accounts — both re-read
    from the database at query time, never from the event payload.
    """

    id: str | None = None
    kind: str = "unknown"
    name: str | None = None
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)


class AuditDecisionEntry(BaseModel):
    """One per-field policy decision as recorded at request time."""

    field: str
    action: str
    reason_code: str
    policy_id: str | None = None
    policy_version: int | None = None
    sensitivity: str | None = None
    pii_category: str | None = None


class AuditTransformationEntry(BaseModel):
    """One applied transformation — type only, never transformed values."""

    field: str
    transformation: str


class AuditLLMInfo(BaseModel):
    """Model-stage metadata: was a model invoked, and what did the guard do."""

    requested: bool = False
    invoked: bool = False
    provider: str | None = None
    model: str | None = None
    guard_triggered: bool = False
    guard_action: str | None = None
    guard_reason_code: str | None = None
    error_code: str | None = None


class AuditEventSummary(BaseModel):
    """List-item projection of one audit event."""

    id: str
    timestamp: datetime
    action: str
    outcome: str | None = None
    actor: AuditActorInfo
    request_id: str | None = None
    session_id: str | None = None
    resource: str | None = None
    resource_id: str | None = None
    overall_decision: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    policy_versions: list[int] = Field(default_factory=list)
    sensitivity_categories: list[str] = Field(default_factory=list)
    model_requested: bool = False
    model_invoked: bool = False
    guard_outcome: str | None = None
    mosaic_warning: bool = False


class AuditEventDetail(AuditEventSummary):
    """Full event projection — reason codes, decisions, and model metadata."""

    purpose: str | None = None
    purpose_recognized: bool | None = None
    operation: str | None = None
    subject_scope: str | None = None
    flags: list[str] = Field(default_factory=list)
    requested_fields: list[str] = Field(default_factory=list)
    decisions: list[AuditDecisionEntry] = Field(default_factory=list)
    transformations: list[AuditTransformationEntry] = Field(default_factory=list)
    llm: AuditLLMInfo | None = None
    guard_triggered: bool = False
    correlation: dict[str, Any] = Field(default_factory=dict)
    ip_address: str | None = None
    #: Requester snapshot as verified at request time (may differ from the
    #: live-resolved ``actor`` if roles changed since).
    requester: dict[str, Any] | None = None
    #: Verified agent identity for service-account principals, if any.
    agent: dict[str, Any] | None = None


class AuditPagination(BaseModel):
    """Offset pagination metadata for audit queries."""

    total: int
    limit: int
    offset: int
    has_more: bool


class AuditEventListResponse(BaseModel):
    """Paginated audit query result."""

    items: list[AuditEventSummary]
    pagination: AuditPagination


__all__ = [
    "AuditActorInfo",
    "AuditDecisionEntry",
    "AuditTransformationEntry",
    "AuditLLMInfo",
    "AuditEventSummary",
    "AuditEventDetail",
    "AuditPagination",
    "AuditEventListResponse",
]

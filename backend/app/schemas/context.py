"""Schemas for the analyzed request context.

:class:`AnalyzedContext` is the trusted context tuple the policy engine
consumes. Every component carries its **trust level**:

* ``trusted_components`` — resolved server-side from a validated
  credential and trusted database state (identity, roles, catalog
  lookups, authorization results, policy references).
* ``untrusted_components`` — client-supplied input (purpose claim,
  requested fields, target entity, conversation metadata). These are
  recorded, evaluated, and *never* treated as evidence of permission.

A claim such as "I am the administrator" inside a purpose string changes
nothing here: the requester block always comes from the authenticated
principal, and purpose is an input to policy evaluation, not a
replacement for permission checks.
"""

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class FlagSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"


class ContextFlag(BaseModel):
    """One observation about the request context (never raw client text)."""

    model_config = ConfigDict(extra="forbid")

    code: str
    severity: FlagSeverity
    component: str
    detail: str


class ContextRequester(BaseModel):
    """The authenticated requester — always resolved server-side."""

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str = Field(description="'user' (human) or 'service' (agent/service account)")
    display_name: str
    username: str | None = None
    roles: list[str] = Field(default_factory=list)
    department: str | None = None
    employee_id: str | None = None
    authentication: str = Field(
        default="verified_credential",
        description="How identity was established (credential + trusted DB state).",
    )


class ContextAgent(BaseModel):
    """The authenticated agent/service identity, when the caller is one."""

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str = "service_account"
    name: str
    scopes: list[str] = Field(default_factory=list)


class OperationAnalysis(BaseModel):
    """The requested operation and its authorization outcome."""

    model_config = ConfigDict(extra="forbid")

    requested: str
    normalized: str
    allowed: bool
    reason_code: str
    detail: str | None = None


class PurposeAnalysis(BaseModel):
    """Purpose claim and its *pre-check* status.

    ``binding`` is fixed: purpose is an input to policy evaluation and can
    never by itself authorize a request.
    """

    model_config = ConfigDict(extra="forbid")

    claimed: str | None = None
    claimed_hash: str | None = Field(
        default=None,
        description="SHA-256 of the raw claim for audit correlation.",
    )
    normalized: str | None = None
    recognized: bool = False
    allowed_purposes: list[str] = Field(
        default_factory=list,
        description="Union of purposes listed by active policies for the resource.",
    )
    precheck_allowed: bool | None = Field(
        default=None,
        description="RBAC-layer pre-check result; the policy engine decides.",
    )
    precheck_reason_code: str | None = None
    binding: str = "input_to_policy_engine"
    injection_suspected: bool = Field(
        default=False,
        description="Override/identity-claim language detected in the claim text.",
    )
    injection_signals: list[str] = Field(
        default_factory=list,
        description="Signal names only (e.g. 'ignore_previous'); never matched text.",
    )


class OwnershipScope(BaseModel):
    """Result of the ownership check for personal records."""

    model_config = ConfigDict(extra="forbid")

    checked: bool = False
    allowed: bool | None = None
    reason_code: str | None = None


class TargetAnalysis(BaseModel):
    """The target resource and the resolved subject scope."""

    model_config = ConfigDict(extra="forbid")

    resource: str
    resource_known: bool
    asset_type: str | None = None
    owner_department: str | None = None
    table_name: str | None = None
    target_entity: str | None = None
    subject_scope: str = Field(
        default="unknown",
        description="self | record | department | organization | unknown",
    )
    department_scope_match: bool | None = Field(
        default=None,
        description="For department-scoped targets: does it match the requester's?",
    )
    ownership: OwnershipScope = Field(default_factory=OwnershipScope)


class ContextField(BaseModel):
    """One requested field and what the catalog knows about it."""

    model_config = ConfigDict(extra="forbid")

    name: str
    known_in_asset: bool
    column_name: str | None = None
    note: str | None = None


class DestinationAnalysis(BaseModel):
    """Intended model / tool destination, as declared by the server."""

    model_config = ConfigDict(extra="forbid")

    kind: str = Field(default="unspecified", description="model | tool | service | unspecified")
    name: str | None = None
    source: str = Field(default="unspecified", description="server_declared | unspecified")
    trusted: bool = False


class ConversationMetadata(BaseModel):
    """Conversation / task identifiers — client-supplied correlation only."""

    model_config = ConfigDict(extra="forbid")

    session_id: str | None = None
    conversation_id: str | None = None
    task_id: str | None = None
    turn_index: int | None = None
    agent_name: str | None = None
    source: str = "client_supplied"
    trusted: bool = False


class PolicyReference(BaseModel):
    """An active policy covering the target resource."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    version: int
    required_role: str | None = None
    allowed_purposes: list[str] = Field(default_factory=list)


class AnalyzedContext(BaseModel):
    """The complete typed context handed to the policy engine."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    requester: ContextRequester
    agent: ContextAgent | None = None
    operation: OperationAnalysis
    purpose: PurposeAnalysis
    target: TargetAnalysis
    requested_fields: list[ContextField] = Field(default_factory=list)
    destination: DestinationAnalysis = Field(default_factory=DestinationAnalysis)
    conversation: ConversationMetadata = Field(default_factory=ConversationMetadata)
    policies: list[PolicyReference] = Field(default_factory=list)
    policy_coverage: bool = False
    flags: list[ContextFlag] = Field(default_factory=list)
    requires_clarification: bool = False
    trusted_components: list[str] = Field(default_factory=list)
    untrusted_components: list[str] = Field(default_factory=list)
    client_metadata_keys: list[str] = Field(
        default_factory=list,
        description="Names of unrecognised client metadata keys (values dropped).",
    )
    identity_claims_ignored: list[str] = Field(
        default_factory=list,
        description="Client metadata keys that looked like authorization claims.",
    )

    def flag_codes(self) -> list[str]:
        """Return the flag codes for quick assertions / logging."""
        return [flag.code for flag in self.flags]

    def policy_ids(self) -> list[str]:
        """Return the identifiers of the active policies covering the resource."""
        return [policy.id for policy in self.policies]

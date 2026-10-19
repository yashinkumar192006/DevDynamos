"""ContextShield Python SDK.

A native convenience layer over the ContextShield HTTP gateway. Every SDK
call performs ordinary HTTP requests to the same endpoints any other
language or agent framework can integrate with directly — see
``docs/integration-guide.md`` for the integration contract, and remember
that installing the SDK does not by itself protect an agent: protected
retrieval and model-invocation paths must be wrapped to go through the
gateway.

Typical usage::

    from contextshield import ContextShieldClient

    client = ContextShieldClient.from_env()   # never hardcode credentials
    result = client.secure_request(
        resource="order_records",
        data_fields=["order_id", "status"],
        purpose="order_status",
        target_entity="ORD0001",
    )
    if result.blocked:
        ...          # nothing was disclosed; reason codes in result.fields
    else:
        ...          # use result.granted_values()
"""

from .client import (
    ApiKeyAuth,
    ContextShieldClient,
    PasswordAuth,
    TokenAuth,
)
from .exceptions import (
    AuthenticationError,
    ConfigurationError,
    ContextShieldError,
    GatewayError,
    GatewayUnavailableError,
    InvalidResponseError,
    NotFoundError,
    PermissionDeniedError,
    RequestBlockedError,
    RequestEscalatedError,
    RequestTimeoutError,
    ValidationError,
)
from .models import (
    DECISION_ALLOW,
    DECISION_BLOCK,
    DECISION_ESCALATION_NEEDED,
    DECISION_PARTIAL_ALLOW,
    AuditActor,
    AuditDecision,
    AuditEvent,
    AuditEventDetail,
    AuditEventPage,
    AuditPagination,
    AuditTransformation,
    FieldDecision,
    GuardFinding,
    LLMGuard,
    LLMInfo,
    SecureRequestContext,
    SecureRequestResult,
)

__version__ = "0.1.0"

__all__ = [
    # Client & auth
    "ContextShieldClient",
    "ApiKeyAuth",
    "TokenAuth",
    "PasswordAuth",
    # Exceptions
    "ContextShieldError",
    "ConfigurationError",
    "AuthenticationError",
    "PermissionDeniedError",
    "ValidationError",
    "NotFoundError",
    "GatewayError",
    "GatewayUnavailableError",
    "RequestTimeoutError",
    "InvalidResponseError",
    "RequestBlockedError",
    "RequestEscalatedError",
    # Models
    "SecureRequestContext",
    "SecureRequestResult",
    "FieldDecision",
    "GuardFinding",
    "LLMGuard",
    "LLMInfo",
    "AuditActor",
    "AuditDecision",
    "AuditTransformation",
    "AuditEvent",
    "AuditEventDetail",
    "AuditPagination",
    "AuditEventPage",
    # Decision constants
    "DECISION_ALLOW",
    "DECISION_PARTIAL_ALLOW",
    "DECISION_BLOCK",
    "DECISION_ESCALATION_NEEDED",
    "__version__",
]

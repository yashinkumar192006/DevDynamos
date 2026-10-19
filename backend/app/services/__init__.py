"""ContextShield service layer.

Authentication: :mod:`app.services.auth_service`
Authorization: :mod:`app.services.authorization`
Context analysis: :mod:`app.services.context_service`
Sensitive-data classification: :mod:`app.services.classifier`
Database-aware classification: :mod:`app.services.classification_service`
Policy engine: :mod:`app.services.policy_engine`
Transformations: :mod:`app.services.transformer`
Protected retrieval: :mod:`app.services.data_connector`
Policy administration: :mod:`app.services.policy_admin`
LLM adapter & safe AI context: :mod:`app.services.llm_adapter`
Output privacy guard: :mod:`app.services.output_guard`
Audit trail queries: :mod:`app.services.audit_service`
"""

from .auth_service import AuthService, Principal
from .audit_service import AuditService, AuditVisibility, resolve_visibility
from .authorization import AccessDecision, AuthorizationService
from .classification_service import ClassificationService
from .classifier import SensitiveDataClassifier
from .context_service import ContextAnalyzer
from .data_connector import (
    ProtectedDataConnector,
    SecureDataRequest,
    SecureResult,
)
from .llm_adapter import (
    DEFAULT_GEMINI_MODEL,
    GeminiProvider,
    LLMOutcome,
    LLMProvider,
    LLMProviderError,
    LLMResponse,
    MockLLMProvider,
    SafeAIContext,
    SafeContextBuilder,
    SafeLLMService,
    UnsupportedProviderError,
    build_llm_provider,
    build_llm_service,
)
from .output_guard import (
    GUARD_MODES,
    GuardFinding,
    GuardResult,
    OutputPrivacyGuard,
)
from .policy_admin import (
    PolicyAdminDenied,
    PolicyAdminService,
    PolicyValidationError,
)
from .policy_engine import (
    ACTION_PRECEDENCE,
    GRANTED_ACTIONS,
    FieldDecision,
    PolicyAction,
    PolicyEngine,
    PolicyEvaluation,
    REASON_TEXTS,
    ReasonCode,
)
from .transformer import (
    AggregateGuard,
    AggregateResult,
    Transformer,
    TokenVault,
    compute_aggregate,
    generalize_value,
    mask_value,
)

__all__ = [
    "AuthService",
    "Principal",
    "AccessDecision",
    "AuthorizationService",
    "ContextAnalyzer",
    "SensitiveDataClassifier",
    "ClassificationService",
    # Policy engine
    "PolicyEngine",
    "PolicyAction",
    "PolicyEvaluation",
    "FieldDecision",
    "ReasonCode",
    "REASON_TEXTS",
    "ACTION_PRECEDENCE",
    "GRANTED_ACTIONS",
    # Transformer
    "Transformer",
    "TokenVault",
    "AggregateGuard",
    "AggregateResult",
    "compute_aggregate",
    "mask_value",
    "generalize_value",
    # Connector
    "ProtectedDataConnector",
    "SecureDataRequest",
    "SecureResult",
    # LLM adapter & output guard
    "MockLLMProvider",
    "GeminiProvider",
    "LLMProvider",
    "LLMProviderError",
    "LLMResponse",
    "LLMOutcome",
    "UnsupportedProviderError",
    "SafeAIContext",
    "SafeContextBuilder",
    "SafeLLMService",
    "build_llm_provider",
    "build_llm_service",
    "DEFAULT_GEMINI_MODEL",
    "OutputPrivacyGuard",
    "GuardResult",
    "GuardFinding",
    "GUARD_MODES",
    # Policy administration
    "PolicyAdminService",
    "PolicyAdminDenied",
    "PolicyValidationError",
    # Audit trail
    "AuditService",
    "AuditVisibility",
    "resolve_visibility",
]

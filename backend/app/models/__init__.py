"""ContextShield SQLAlchemy models.

All model classes are re-exported here for convenient import.
Example: ``from app.models import User, Role, DataAsset``

The ``Base`` metadata object is also exported for Alembic
and for creating tables in test harnesses.
"""

from .base import Base

from .identity import User, Role, Permission, UserRole
from .service_account import ServiceAccount
from .data_asset import DataAsset, DataField, DataClassification, SensitivityLevel
from .privacy import (
    PrivacyPolicy,
    PolicyStatus,
    PrivacyRequest,
    RequestPurpose,
    RequestStatus,
    RequestContext,
)
from .decision import (
    PrivacyDecision,
    DecisionOutcome,
    TransformationEvent,
    TransformationType,
    AIInteraction,
    OutputInspection,
)
from .audit import AuditEvent, AuditAction, SessionDisclosure
from .business import Employee, Customer, Order, BusinessDocument

__all__ = [
    "Base",
    # Identity
    "User",
    "Role",
    "Permission",
    "UserRole",
    "ServiceAccount",
    # Data assets
    "DataAsset",
    "DataField",
    "DataClassification",
    "SensitivityLevel",
    # Privacy
    "PrivacyPolicy",
    "PolicyStatus",
    "PrivacyRequest",
    "RequestPurpose",
    "RequestStatus",
    "RequestContext",
    # Decisions
    "PrivacyDecision",
    "DecisionOutcome",
    "TransformationEvent",
    "TransformationType",
    "AIInteraction",
    "OutputInspection",
    # Audit
    "AuditEvent",
    "AuditAction",
    "SessionDisclosure",
    # Protected business data
    "Employee",
    "Customer",
    "Order",
    "BusinessDocument",
]

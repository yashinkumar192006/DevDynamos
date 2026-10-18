"""ContextShield Repository Layer.

Public API for database queries. Import directly::

    from app.repositories import UserRepository, DataAssetRepository
"""

from .base import BaseRepository
from .user_repo import UserRepository, RoleRepository
from .service_account_repo import ServiceAccountRepository
from .data_asset_repo import DataAssetRepository, DataFieldRepository
from .policy_repo import PrivacyPolicyRepository
from .audit_repo import AuditRepository
from .decision_repo import (
    PrivacyRequestRepository,
    PrivacyDecisionRepository,
    AIInteractionRepository,
)
from .protected_data_repo import (
    EmployeeRepository,
    CustomerRepository,
    OrderRepository,
    BusinessDocumentRepository,
)

__all__ = [
    "BaseRepository",
    "UserRepository",
    "RoleRepository",
    "ServiceAccountRepository",
    "DataAssetRepository",
    "DataFieldRepository",
    "PrivacyPolicyRepository",
    "AuditRepository",
    "PrivacyRequestRepository",
    "PrivacyDecisionRepository",
    "AIInteractionRepository",
    "EmployeeRepository",
    "CustomerRepository",
    "OrderRepository",
    "BusinessDocumentRepository",
]

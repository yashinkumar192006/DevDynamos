"""Privacy policy and privacy-request models."""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .base import Base, _utcnow
import enum


class PolicyStatus(str, enum.Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    ARCHIVED = "archived"


class PrivacyPolicy(Base):
    """Versioned privacy / data-handling policy."""

    __tablename__ = "privacy_policies"

    name = Column(String(200), nullable=False, index=True)
    version = Column(Integer, nullable=False, default=1)
    description = Column(Text, nullable=True)
    policy_text = Column(Text, nullable=False)
    resource_pattern = Column(String(200), nullable=False)  # e.g. "employee_salary", "customer_*"
    required_role = Column(String(100), nullable=True)
    min_sensitivity = Column(String(20), nullable=True)  # maximum sensitivity this norm may expose
    allowed_purposes = Column(Text, nullable=True)  # JSON list
    allowed_actions = Column(Text, nullable=True)  # JSON list of request operations
    # Disclosure action this norm authorises when it matches:
    # ALLOW | MASK | TOKENIZE | GENERALIZE | AGGREGATE | ESCALATE | BLOCK.
    # NULL means a legacy read policy — treated as ALLOW by the engine.
    action = Column(String(20), nullable=True)
    # Conflict resolution: higher priority wins; ties fall back to the most
    # restrictive action (see docs/privacy-policies.md §4.2).
    priority = Column(Integer, nullable=False, default=0, server_default="0")
    status = Column(
        SAEnum(PolicyStatus, name="policy_status"),
        default=PolicyStatus.ACTIVE,
        nullable=False,
    )
    effective_from = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    effective_until = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    decisions = relationship("PrivacyDecision", back_populates="policy")

    __table_args__ = (
        Index("ix_policy_name_version", "name", "version", unique=True),
        Index("ix_policy_resource_status", "resource_pattern", "status"),
    )

    def __repr__(self) -> str:
        return f"<PrivacyPolicy {self.name} v{self.version}>"


class RequestPurpose(str, enum.Enum):
    HR_REVIEW = "hr_review"
    DEPARTMENT_STATS = "department_statistics"
    CUSTOMER_SERVICE = "customer_service"
    ORDER_STATUS = "order_status"
    COMPLIANCE = "compliance"
    ANALYTICS = "analytics"
    GENERAL = "general"


class RequestStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    ESCALATED = "escalated"


class PrivacyRequest(Base):
    """A request for access to protected data."""

    __tablename__ = "privacy_requests"

    requester_id = Column(String(32), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    resource = Column(String(200), nullable=False, index=True)
    action = Column(String(50), nullable=False)  # "read", "aggregate", "export"
    purpose = Column(
        SAEnum(RequestPurpose, name="request_purpose"),
        nullable=False,
    )
    purpose_detail = Column(Text, nullable=True)
    status = Column(
        SAEnum(RequestStatus, name="request_status"),
        default=RequestStatus.PENDING,
        nullable=False,
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    requester = relationship("User", back_populates="privacy_requests")
    context = relationship("RequestContext", back_populates="request", uselist=False, cascade="all, delete-orphan")
    decision = relationship("PrivacyDecision", back_populates="request", uselist=False, cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_privreq_requester_resource", "requester_id", "resource"),
    )

    def __repr__(self) -> str:
        return f"<PrivacyRequest {self.resource}:{self.action} by={self.requester_id}>"


class RequestContext(Base):
    """Trusted + untrusted context collected for a privacy request."""

    __tablename__ = "request_contexts"

    request_id = Column(String(32), ForeignKey("privacy_requests.id", ondelete="CASCADE"), nullable=False, unique=True)
    user_role = Column(String(100), nullable=True)
    user_department = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)
    session_id = Column(String(64), nullable=True)
    claimed_purpose = Column(Text, nullable=True)  # untrusted: user-supplied
    verified_purpose = Column(Text, nullable=True)  # trusted: server-verified
    risk_score = Column(Integer, nullable=True)
    context_flags = Column(Text, nullable=True)  # JSON flags

    # Relationships
    request = relationship("PrivacyRequest", back_populates="context")

    def __repr__(self) -> str:
        return f"<RequestContext req={self.request_id}>"

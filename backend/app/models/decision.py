"""Privacy decision, transformation, and AI interaction models."""

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


class DecisionOutcome(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    ALLOW_PARTIAL = "allow_partial"  # some fields redacted
    ESCALATE = "escalate"


class PrivacyDecision(Base):
    """The outcome of evaluating a privacy request against policies."""

    __tablename__ = "privacy_decisions"

    request_id = Column(String(32), ForeignKey("privacy_requests.id", ondelete="CASCADE"), nullable=False, unique=True)
    policy_id = Column(String(32), ForeignKey("privacy_policies.id", ondelete="SET NULL"), nullable=True, index=True)
    outcome = Column(
        SAEnum(DecisionOutcome, name="decision_outcome"),
        nullable=False,
    )
    reason = Column(Text, nullable=True)
    allowed_fields = Column(Text, nullable=True)  # JSON list of permitted field names
    denied_fields = Column(Text, nullable=True)  # JSON list of denied field names
    transformations_applied = Column(Text, nullable=True)  # JSON summary
    decided_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    decided_by = Column(String(100), nullable=False, default="policy_engine")  # "policy_engine", "admin:john"

    # Relationships
    request = relationship("PrivacyRequest", back_populates="decision")
    policy = relationship("PrivacyPolicy", back_populates="decisions")
    transformations = relationship("TransformationEvent", back_populates="decision", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<PrivacyDecision {self.outcome} for req={self.request_id}>"


class TransformationType(str, enum.Enum):
    REDACT = "redact"
    MASK = "mask"
    HASH = "hash"
    GENERALIZE = "generalize"
    AGGREGATE = "aggregate"
    TOKENIZE = "tokenize"
    SUPPRESS = "suppress"


class TransformationEvent(Base):
    """Record of a specific transformation applied to a data field."""

    __tablename__ = "transformation_events"

    decision_id = Column(String(32), ForeignKey("privacy_decisions.id", ondelete="CASCADE"), nullable=False, index=True)
    field_name = Column(String(200), nullable=False)
    transformation_type = Column(
        SAEnum(TransformationType, name="transformation_type"),
        nullable=False,
    )
    original_hash = Column(String(128), nullable=True)  # SHA-512 of original value (NOT the raw value!)
    transformed_preview = Column(String(200), nullable=True)  # e.g. "***-**-1234"

    # Relationships
    decision = relationship("PrivacyDecision", back_populates="transformations")

    def __repr__(self) -> str:
        return f"<TransformationEvent {self.field_name}:{self.transformation_type}>"


class AIInteraction(Base):
    """Record of an LLM / AI-agent interaction touching protected data."""

    __tablename__ = "ai_interactions"

    user_id = Column(String(32), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(String(64), nullable=True, index=True)
    model_name = Column(String(100), nullable=True)
    prompt_hash = Column(String(128), nullable=True)  # hash of prompt, never raw prompt
    prompt_token_count = Column(Integer, nullable=True)
    response_token_count = Column(Integer, nullable=True)
    resources_accessed = Column(Text, nullable=True)  # JSON list
    privacy_decisions = Column(Text, nullable=True)  # JSON list of decision IDs
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    user = relationship("User", back_populates="ai_interactions")
    output_inspections = relationship("OutputInspection", back_populates="interaction", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<AIInteraction session={self.session_id}>"


class OutputInspection(Base):
    """Result of inspecting an AI output for residual PII leakage."""

    __tablename__ = "output_inspections"

    interaction_id = Column(String(32), ForeignKey("ai_interactions.id", ondelete="CASCADE"), nullable=False, index=True)
    check_type = Column(String(100), nullable=False)  # "pii_scan", "policy_compliance", etc.
    passed = Column(Boolean, nullable=False, default=True)
    findings_summary = Column(Text, nullable=True)  # summary only, no raw PII
    entities_detected_count = Column(Integer, nullable=True)
    action_taken = Column(String(50), nullable=True)  # "none", "redacted", "blocked"

    # Relationships
    interaction = relationship("AIInteraction", back_populates="output_inspections")

    def __repr__(self) -> str:
        return f"<OutputInspection {self.check_type} passed={self.passed}>"

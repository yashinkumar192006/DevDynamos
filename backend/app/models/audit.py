"""Audit event and session disclosure tracking models."""

from sqlalchemy import (
    Column,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)

from .base import Base, _utcnow
import enum


class AuditAction(str, enum.Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    DATA_ACCESS = "data_access"
    DATA_DENIED = "data_denied"
    POLICY_EVALUATION = "policy_evaluation"
    TRANSFORMATION = "transformation"
    AI_QUERY = "ai_query"
    OUTPUT_INSPECTION = "output_inspection"
    ADMIN_ACTION = "admin_action"
    SEED_DATA = "seed_data"


class AuditEvent(Base):
    """Immutable audit trail entry.

    Audit events never store raw sensitive content. Fields that reference
    protected data do so by id / hash only.

    ``actor_id`` is a *polymorphic* reference — ``users.id`` for human
    principals and ``service_accounts.id`` for agent/service principals —
    discriminated by ``actor_kind`` (``"user"`` | ``"service"``). There is
    deliberately no foreign key: a single column cannot reference two
    tables, and audit rows must survive account deletion (retention), so
    they are never cascade-deleted.
    """

    __tablename__ = "audit_events"

    #: ``"user"`` (human, ``users.id``) or ``"service"`` (agent/service
    #: account, ``service_accounts.id``). ``None`` = legacy pre-actor-kind
    #: rows, treated as user actors.
    actor_kind = Column(String(20), nullable=True)
    actor_id = Column(String(32), nullable=True, index=True)
    action = Column(
        SAEnum(AuditAction, name="audit_action"),
        nullable=False,
    )
    resource = Column(String(200), nullable=True)
    resource_id = Column(String(32), nullable=True)
    outcome = Column(String(50), nullable=True)  # "success", "denied", "error"
    detail = Column(Text, nullable=True)  # structured JSON summary (no raw PII)
    ip_address = Column(String(45), nullable=True)
    session_id = Column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_audit_action_created", "action", "created_at"),
        Index("ix_audit_actor_created", "actor_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<AuditEvent {self.action} by={self.actor_id}>"


class SessionDisclosure(Base):
    """Tracks which sensitive fields were disclosed during a session.

    This enables the system to enforce minimum-necessary-disclosure per
    session and warn when cumulative exposure approaches policy limits.
    """

    __tablename__ = "session_disclosures"

    session_id = Column(String(64), nullable=False, index=True)
    user_id = Column(String(32), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    field_id = Column(String(32), ForeignKey("data_fields.id", ondelete="SET NULL"), nullable=True)
    field_name = Column(String(200), nullable=False)
    asset_name = Column(String(200), nullable=True)
    sensitivity = Column(String(20), nullable=False)
    disclosed_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    disclosure_count = Column(Integer, default=1, nullable=False)

    __table_args__ = (
        Index("ix_session_disc_session_user", "session_id", "user_id"),
    )

    def __repr__(self) -> str:
        return f"<SessionDisclosure session={self.session_id} field={self.field_name}>"

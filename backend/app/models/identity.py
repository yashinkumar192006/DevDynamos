"""Identity & access-control models: User, Role, Permission, UserRole."""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .base import Base, _new_uuid, _utcnow


class User(Base):
    """Application user (employee, analyst, admin, etc.)."""

    __tablename__ = "users"

    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(Text, nullable=False)
    department = Column(String(100), nullable=True)
    employee_id = Column(String(20), unique=True, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    user_roles = relationship(
        "UserRole",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="UserRole.user_id",
    )
    privacy_requests = relationship("PrivacyRequest", back_populates="requester", cascade="all, delete-orphan")
    ai_interactions = relationship("AIInteraction", back_populates="user", cascade="all, delete-orphan")
    # NOTE: no ``audit_events`` relationship. Audit rows are polymorphic
    # (``actor_id`` references users *or* service accounts) and must survive
    # account deletion for retention — the repository is the only access path.

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class Role(Base):
    """Named role grouping one or more permissions."""

    __tablename__ = "roles"

    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)

    # Relationships
    user_roles = relationship("UserRole", back_populates="role", cascade="all, delete-orphan")
    permissions = relationship("Permission", back_populates="role", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Role {self.name}>"


class Permission(Base):
    """Fine-grained permission attached to a role."""

    __tablename__ = "permissions"

    role_id = Column(String(32), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)
    resource = Column(String(200), nullable=False)  # e.g. "employee_salary", "customer_contact"
    action = Column(String(50), nullable=False)  # e.g. "read", "write", "aggregate"
    conditions = Column(Text, nullable=True)  # optional JSON rules string

    # Relationships
    role = relationship("Role", back_populates="permissions")

    __table_args__ = (
        Index("ix_perm_role_resource", "role_id", "resource"),
        UniqueConstraint("role_id", "resource", "action", name="uq_perm_role_resource_action"),
    )

    def __repr__(self) -> str:
        return f"<Permission {self.resource}:{self.action}>"


class UserRole(Base):
    """Association between a user and a role."""

    __tablename__ = "user_roles"

    user_id = Column(String(32), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id = Column(String(32), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)
    granted_by = Column(String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    granted_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="user_roles", foreign_keys=[user_id])
    role = relationship("Role", back_populates="user_roles")

    __table_args__ = (
        UniqueConstraint("user_id", "role_id", name="uq_user_role"),
    )

    def __repr__(self) -> str:
        return f"<UserRole user={self.user_id} role={self.role_id}>"

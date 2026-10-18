"""Service-account model for authenticating AI agents and backend services.

Trusted identity model (see ``docs/authentication.md``):

* Human users authenticate with username + password → JWT.
* AI agents and services authenticate with an API key sent in the
  ``X-API-Key`` header. An arbitrary ``X-User-Id``-style header is never
  accepted as identity evidence.

Only the SHA-256 hash of an API key is stored. The plaintext key is shown
exactly once, at creation time (``python -m app.create_service_account``).
"""

import json

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text

from .base import Base


class ServiceAccount(Base):
    """Machine identity for agents/services calling the gateway."""

    __tablename__ = "service_accounts"

    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    #: Display prefix, e.g. ``"csk_9f2c1a"`` — safe to show in admin UIs.
    key_prefix = Column(String(16), nullable=False)
    #: SHA-256 hex digest of the API key — the plaintext is never stored.
    hashed_key = Column(String(64), unique=True, nullable=False, index=True)
    #: JSON list of scopes, e.g. ``["privacy:request", "customer_records:read"]``.
    scopes = Column(Text, nullable=False, default="[]")
    is_active = Column(Boolean, default=True, nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(
        String(32),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    def scope_list(self) -> list[str]:
        """Return the parsed scope list; never raises."""
        try:
            value = json.loads(self.scopes or "[]")
        except (TypeError, json.JSONDecodeError):
            return []
        return value if isinstance(value, list) else []

    def __repr__(self) -> str:
        return f"<ServiceAccount {self.name}>"

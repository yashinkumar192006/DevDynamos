"""Base model class and common utilities for all SQLAlchemy models."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String
from sqlalchemy.orm import DeclarativeBase


def _utcnow() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    """Return a new UUID4 hex string for primary keys."""
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    """Shared declarative base for all ContextShield models.

    Every table automatically receives ``id``, ``created_at``, and
    ``updated_at`` columns unless a model explicitly overrides them.
    """

    id = Column(
        String(32),
        primary_key=True,
        default=_new_uuid,
        nullable=False,
    )
    created_at = Column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
        nullable=False,
    )

"""Schemas for the policy catalogue API (docs/api-design.md §4.7).

Policies describe the rules in effect; the projection below is an
allowlisted view of the versioned policy store. ``policy_text`` is the
human-readable rule summary that is also shipped in the project docs —
it contains no secrets, credentials, or protected data.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import Pagination


class PolicyItem(BaseModel):
    """One policy version as shown in the policy viewer."""

    id: str
    name: str
    version: int
    description: str | None = None
    policy_text: str
    resource_pattern: str
    required_role: str | None = None
    min_sensitivity: str | None = None
    allowed_purposes: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    action: str | None = None
    priority: int = 0
    status: str
    is_active: bool
    effective_from: datetime
    effective_until: datetime | None = None


class PolicyListResponse(BaseModel):
    """Paginated policy listing."""

    items: list[PolicyItem]
    pagination: Pagination


__all__ = ["PolicyItem", "PolicyListResponse"]

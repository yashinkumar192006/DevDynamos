"""Shared response schemas used across list endpoints."""

from pydantic import BaseModel


class Pagination(BaseModel):
    """Offset pagination metadata (identical shape on every list API)."""

    total: int
    limit: int
    offset: int
    has_more: bool


__all__ = ["Pagination"]

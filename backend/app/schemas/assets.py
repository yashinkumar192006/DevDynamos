"""Schemas for the data-asset catalogue API (docs/api-design.md §4.11).

Classification metadata only: asset/field names, types, sensitivity
levels, PII categories, and record *counts*. The payload never contains
row data from the backing tables — no raw values can leak through this
endpoint by construction.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.common import Pagination


class AssetField(BaseModel):
    """One field's classification metadata."""

    name: str
    column_name: str | None = None
    field_type: str
    sensitivity: str
    pii_category: str | None = None
    description: str | None = None


class DataAssetItem(BaseModel):
    """One catalog asset with its classified fields."""

    id: str
    name: str
    description: str | None = None
    asset_type: str
    owner_department: str | None = None
    table_name: str | None = None
    field_count: int = 0
    #: Counts of fields per sensitivity level (low/medium/high/restricted).
    sensitivity_summary: dict[str, int] = Field(default_factory=dict)
    #: Row count of the backing table, when it is a known demo table.
    record_count: int | None = None
    fields: list[AssetField] = Field(default_factory=list)


class DataAssetListResponse(BaseModel):
    """Paginated data-asset listing."""

    items: list[DataAssetItem]
    pagination: Pagination


__all__ = ["AssetField", "DataAssetItem", "DataAssetListResponse"]

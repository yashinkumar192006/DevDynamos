"""Data-asset catalogue (docs/api-design.md §4.11).

Classification metadata only: asset/field names, types, sensitivity
levels, PII categories, and record *counts* for known demo tables. Raw
values never pass through this service — the repository layer that reads
protected records is not involved at all.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import (
    BusinessDocument,
    Customer,
    DataAsset,
    Employee,
    Order,
    SensitivityLevel,
)
from app.schemas.assets import AssetField, DataAssetItem, DataAssetListResponse
from app.schemas.common import Pagination

#: Backing tables the catalogue reports counts for (identified by name).
_TABLE_MODELS = {
    "employees": Employee,
    "customers": Customer,
    "orders": Order,
    "business_documents": BusinessDocument,
}


class DataAssetCatalogService:
    """Read-side catalogue of assets and their field classifications."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def list_assets(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        sensitivity: SensitivityLevel | None = None,
        asset_type: str | None = None,
    ) -> DataAssetListResponse:
        result = await self.session.execute(
            select(DataAsset)
            .options(selectinload(DataAsset.fields))
            .order_by(DataAsset.name)
        )
        assets = result.scalars().all()

        items: list[DataAssetItem] = []
        for asset in assets:
            if asset_type is not None and asset.asset_type != asset_type:
                continue
            fields = sorted(asset.fields, key=lambda field: field.field_name)
            if sensitivity is not None and not any(
                field.sensitivity == sensitivity for field in fields
            ):
                continue

            summary = {level.value: 0 for level in SensitivityLevel}
            for field in fields:
                summary[field.sensitivity.value] += 1

            items.append(
                DataAssetItem(
                    id=asset.id,
                    name=asset.name,
                    description=asset.description,
                    asset_type=asset.asset_type,
                    owner_department=asset.owner_department,
                    table_name=asset.table_name,
                    field_count=len(fields),
                    sensitivity_summary=summary,
                    record_count=await self._count(asset.table_name),
                    fields=[
                        AssetField(
                            name=field.field_name,
                            column_name=field.column_name,
                            field_type=field.field_type,
                            sensitivity=field.sensitivity.value,
                            pii_category=field.pii_category,
                            description=field.description,
                        )
                        for field in fields
                    ],
                )
            )

        total = len(items)
        window = items[offset : offset + limit]
        return DataAssetListResponse(
            items=window,
            pagination=Pagination(
                total=total,
                limit=limit,
                offset=offset,
                has_more=offset + len(window) < total,
            ),
        )

    async def _count(self, table_name: str | None) -> int | None:
        """Row count of the backing table, or ``None`` for unknown tables."""
        model = _TABLE_MODELS.get(table_name or "")
        if model is None:
            return None
        count = await self.session.scalar(select(func.count()).select_from(model))
        return int(count or 0)


__all__ = ["DataAssetCatalogService"]

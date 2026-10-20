"""Data-asset catalogue API (docs/api-design.md §4.11).

Classification metadata only — field names, types, sensitivities, PII
categories, and record counts. No row data is ever exposed.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_principal
from app.core.database import get_db
from app.models import SensitivityLevel
from app.schemas.assets import DataAssetListResponse
from app.services import DataAssetCatalogService, Principal

router = APIRouter(prefix="/data", tags=["data"])


@router.get(
    "/assets",
    response_model=DataAssetListResponse,
    summary="List data assets and their field classifications",
)
async def list_data_assets(
    principal: Principal = Depends(get_current_principal),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    sensitivity: SensitivityLevel | None = Query(
        None, description="Only assets containing fields at this sensitivity"
    ),
    asset_type: str | None = Query(None, min_length=1, max_length=50),
) -> DataAssetListResponse:
    """Return the catalogue view of assets and classified fields."""
    service = DataAssetCatalogService(db)
    return await service.list_assets(
        limit=limit,
        offset=offset,
        sensitivity=sensitivity,
        asset_type=asset_type,
    )

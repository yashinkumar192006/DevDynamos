"""Dashboard overview API (docs/api-design.md §4.10).

Metrics are aggregated from recorded audit events, visibility-scoped from
the verified principal exactly like the audit trail APIs. Nothing is
fabricated: an empty trail yields zeros and the UI shows an empty state.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_principal
from app.core.database import get_db
from app.schemas.dashboard import DashboardOverview
from app.services import DashboardService, Principal

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get(
    "/overview",
    response_model=DashboardOverview,
    summary="Dashboard summary metrics (visibility-scoped)",
)
async def dashboard_overview(
    principal: Principal = Depends(get_current_principal),
    db: AsyncSession = Depends(get_db),
    window_days: int = Query(14, ge=1, le=90),
    recent_limit: int = Query(8, ge=1, le=50),
) -> DashboardOverview:
    """Return decision/recent-activity/health metrics for the caller's scope."""
    service = DashboardService(db)
    return await service.overview(
        principal, window_days=window_days, recent_limit=recent_limit
    )

"""Policy catalogue API (docs/api-design.md §4.7).

Any authenticated principal may read the active policies; inactive /
superseded versions require an administrator identity (403 otherwise).
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_principal
from app.core.database import get_db
from app.schemas.policies import PolicyListResponse
from app.services import PolicyCatalogService, Principal

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get(
    "",
    response_model=PolicyListResponse,
    summary="List privacy policies (active by default)",
)
async def list_policies(
    principal: Principal = Depends(get_current_principal),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    resource: str | None = Query(
        None,
        min_length=1,
        max_length=200,
        description="Show policies whose resource pattern matches this resource",
    ),
    role: str | None = Query(
        None, min_length=1, max_length=100, description="Filter by required role"
    ),
    include_inactive: bool = Query(
        False,
        description="Include superseded/archived versions (administrators only)",
    ),
) -> PolicyListResponse:
    """Return the policy versions visible to the caller, newest name first."""
    service = PolicyCatalogService(db)
    return await service.list_policies(
        principal,
        limit=limit,
        offset=offset,
        resource=resource,
        role=role,
        include_inactive=include_inactive,
    )

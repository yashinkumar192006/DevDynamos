"""Audit trail APIs (docs/api-design.md §4.8–4.9).

Access is scoped from the *verified* principal by
:func:`app.services.audit_service.resolve_visibility`:

* ``admin`` — full trail.
* ``hr_manager`` / ``executive`` — privacy-pipeline events for all actors.
* everyone else (including agent/service principals) — own events only.

Out-of-scope filters are rejected with 403; a direct fetch of an
out-of-scope event returns 404 so its existence is not disclosed.
Audit responses never contain raw protected values, credentials, tokens,
or complete prompts/outputs — see the schema module docstring.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_principal
from app.core.database import get_db
from app.models import AuditAction
from app.schemas.audit import AuditEventDetail, AuditEventListResponse
from app.services import AuditService, Principal

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get(
    "/events",
    response_model=AuditEventListResponse,
    summary="Query the audit trail (visibility-scoped, paginated)",
)
async def list_audit_events(
    principal: Principal = Depends(get_current_principal),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    requester_id: str | None = Query(
        None, min_length=1, max_length=32, description="Filter by actor id"
    ),
    action: AuditAction | None = Query(None),
    resource: str | None = Query(None, min_length=1, max_length=200),
    outcome: str | None = Query(None, min_length=1, max_length=50),
    session_id: str | None = Query(None, min_length=1, max_length=64),
    start_date: datetime | None = Query(None),
    end_date: datetime | None = Query(None),
) -> AuditEventListResponse:
    """Return audit events the caller is allowed to see, newest first."""
    if start_date is not None and end_date is not None and start_date > end_date:
        # Consistent with FastAPI's 422 for invalid query shapes.
        raise HTTPException(
            status_code=422, detail="start_date must not be after end_date"
        )
    service = AuditService(db)
    return await service.list_events(
        principal,
        limit=limit,
        offset=offset,
        requester_id=requester_id,
        action=action,
        resource=resource,
        outcome=outcome,
        session_id=session_id,
        start_date=start_date,
        end_date=end_date,
    )


@router.get(
    "/events/{event_id}",
    response_model=AuditEventDetail,
    summary="Full detail of one audit event (visibility-scoped)",
)
async def get_audit_event(
    event_id: str,
    principal: Principal = Depends(get_current_principal),
    db: AsyncSession = Depends(get_db),
) -> AuditEventDetail:
    """Return one event; 404 when missing *or* outside the caller's scope."""
    service = AuditService(db)
    event = await service.get_event(principal, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Audit event not found")
    return await service.describe(event)

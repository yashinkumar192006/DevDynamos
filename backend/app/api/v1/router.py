from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from ...core.config import settings
from ...core.database import get_db
from .auth import router as auth_router
from .admin import router as admin_router

router = APIRouter()
router.include_router(auth_router)
router.include_router(admin_router)

@router.get("/health", tags=["system"]) 
async def api_health_check():
    """Health endpoint under /api/v1.
    Mirrors the root health check.
    """
    return {"status": "ok"}

@router.get("/system/status", tags=["system"]) 
async def system_status(db: AsyncSession = Depends(get_db)):
    """Report status of configured providers.

    - Database: attempts a simple SELECT 1 query.
    - LLM Provider: currently only a mock provider is supported; if set to anything else, we assume reachable.
    """
    # Check database connectivity
    db_status = "unhealthy"
    try:
        result = await db.execute(text("SELECT 1"))
        # Consume result to ensure query succeeded
        _ = result.scalar_one()
        db_status = "healthy"
    except Exception as exc:
        db_status = f"unhealthy: {str(exc)}"

    # Check LLM provider (mock always healthy)
    llm_status = "healthy" if settings.LLM_PROVIDER == "mock" else "unhealthy"

    return {
        "providers": {
            "database": db_status,
            "llm": llm_status,
        }
    }

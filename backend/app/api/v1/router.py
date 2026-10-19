from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from ...core.config import settings
from ...core.database import get_db
from ...services.classification_service import ClassificationService
from ...services.llm_adapter import SafeLLMService
from .auth import router as auth_router
from .admin import router as admin_router
from .audit import router as audit_router
from .privacy import router as privacy_router

router = APIRouter()
router.include_router(auth_router)
router.include_router(admin_router)
router.include_router(audit_router)
router.include_router(privacy_router)

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

    # LLM adapter status: provider selection, model, key configuration and
    # output-guard mode. Never includes the API key itself.
    llm_status = SafeLLMService(settings_obj=settings).status()

    # Classifier configuration / conservative-policy status. Does not build
    # the NLP engine (lazy): it reports config + previous resolution only.
    classifier_status = ClassificationService(db).status()

    return {
        "providers": {
            "database": db_status,
            "llm": llm_status,
            "classifier": {
                "status": "ready" if settings.CLASSIFIER_NLP_ENABLED else "deterministic_only",
                **classifier_status,
            },
        }
    }

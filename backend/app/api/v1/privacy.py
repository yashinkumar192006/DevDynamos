"""Privacy enforcement endpoints.

``POST /api/v1/privacy/secure-request`` runs the full secure-request
pipeline (docs/architecture.md §6):

authenticate → validate → analyze context → deterministic policy evaluation
→ block/escalate → retrieve only authorized records/fields → transform →
build safe model context → invoke the configured provider only when
permitted → inspect the generated output → return the approved response →
record an audit event without raw secrets.

The route handler itself stays thin: identity comes from the verified
credential (:func:`app.api.deps.get_current_principal`), the pipeline lives
in :class:`~app.services.data_connector.ProtectedDataConnector`, and the
optional LLM stage is the provider-independent
:class:`~app.services.llm_adapter.SafeLLMService`. Validation failures on
the request *shape* produce a 422 before the pipeline runs; everything
semantic is fail-closed inside the pipeline and returned as ``BLOCK`` /
``ESCALATION_NEEDED`` decisions rather than an HTTP error.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_principal
from app.core.database import get_db
from app.schemas.privacy import SecureRequestPayload, SecureRequestResponse
from app.services import Principal
from app.services.data_connector import ProtectedDataConnector
from app.services.llm_adapter import build_llm_service

router = APIRouter(prefix="/privacy", tags=["privacy"])


@router.post(
    "/secure-request",
    response_model=SecureRequestResponse,
    summary="Run a privacy-enforced data request (policy pipeline)",
)
async def secure_request(
    payload: SecureRequestPayload,
    principal: Principal = Depends(get_current_principal),
    db: AsyncSession = Depends(get_db),
) -> SecureRequestResponse:
    """Execute the secure-request pipeline for the authenticated identity.

    The verified principal (user JWT or service API key) is the only
    identity source. The claimed purpose, target and fields are untrusted
    inputs to the deterministic policy engine — they never establish
    authorization by themselves. When ``include_llm_response`` is set, the
    configured provider is called **only** after the policy pipeline granted
    at least one field and nothing requires escalation; blocked requests are
    never retrieved and never reach a model.
    """
    connector = ProtectedDataConnector(
        db,
        llm=build_llm_service() if payload.include_llm_response else None,
    )
    result = await connector.execute(principal, payload.to_connector_request())
    return SecureRequestResponse.from_result(result)


__all__ = ["router"]

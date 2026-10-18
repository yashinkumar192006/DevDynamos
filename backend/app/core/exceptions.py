from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
import structlog

logger = structlog.get_logger("contextshield")


class AuthenticationError(HTTPException):
    """401 — the request lacks valid credentials (missing, invalid, expired).

    Always paired with a ``WWW-Authenticate: Bearer`` header so clients
    know which authentication scheme to use.
    """

    def __init__(self, detail: str = "Not authenticated"):
        super().__init__(
            status_code=401,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class AuthorizationError(HTTPException):
    """403 — the identity is authenticated but not permitted.

    Authentication answered *who* the caller is; this error means the
    caller's verified identity is not allowed to perform the operation.
    """

    def __init__(self, detail: str = "Not authorized"):
        super().__init__(status_code=403, detail=detail)


def http_exception_handler(request: Request, exc: HTTPException):
    """Return a JSON response for HTTPExceptions and log the error.

    The response format follows the stable JSON structure used across the
    application: ``{"error": {"type": ..., "detail": ...}}``.
    """
    logger.error(
        "http_exception",
        method=request.method,
        url=str(request.url),
        status_code=exc.status_code,
        detail=exc.detail,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"type": exc.__class__.__name__, "detail": exc.detail}},
        # Preserve headers such as WWW-Authenticate on 401 responses.
        headers=getattr(exc, "headers", None),
    )

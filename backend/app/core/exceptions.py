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


class RateLimitError(HTTPException):
    """429 — too many failed attempts on a throttled surface.

    Carries a ``Retry-After`` header (whole seconds, rounded up) so
    well-behaved clients back off instead of hammering the endpoint.
    """

    def __init__(
        self,
        retry_after_seconds: float,
        detail: str = "Too many failed attempts. Try again later.",
    ):
        from app.core.rate_limit import retry_after_header_seconds

        super().__init__(
            status_code=429,
            detail=detail,
            headers={"Retry-After": str(retry_after_header_seconds(retry_after_seconds))},
        )


def _request_id(request: Request) -> str | None:
    """Correlation id attached by ``RequestIDMiddleware`` (if installed)."""
    return getattr(request.state, "request_id", None)


def http_exception_handler(request: Request, exc: HTTPException):
    """Return a JSON response for HTTPExceptions and log the error.

    The response format follows the stable JSON structure used across the
    application: ``{"error": {"type": ..., "detail": ...}}``. The
    correlation id travels in the ``X-Request-ID`` response header, not in
    the body.
    """
    logger.error(
        "http_exception",
        method=request.method,
        url=str(request.url),
        status_code=exc.status_code,
        detail=exc.detail,
        request_id=_request_id(request),
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"type": exc.__class__.__name__, "detail": exc.detail}},
        # Preserve headers such as WWW-Authenticate on 401 responses.
        headers=getattr(exc, "headers", None),
    )


async def unhandled_exception_handler(request: Request, exc: Exception):
    """500 — log the failure server-side, return a generic body.

    The client never receives the exception type, message, or traceback;
    only the stable error shape and (when middleware is active) the
    ``X-Request-ID`` header for support correlation. Nothing about the
    exception beyond its class name is logged.
    """
    logger.error(
        "unhandled_exception",
        method=request.method,
        url=str(request.url),
        error_type=type(exc).__name__,
        request_id=_request_id(request),
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "type": "InternalServerError",
                "detail": "Internal server error",
            }
        },
    )

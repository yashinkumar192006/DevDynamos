"""HTTP request correlation.

Every request handled by the application receives a server-generated
``X-Request-ID`` (32 hex characters, never derived from client input) that
is:

* set on ``request.state`` so exception handlers can log it,
* exposed via a ``contextvar`` for structured-log correlation,
* echoed in the ``X-Request-ID`` response header (and exposed to browser
  clients through the CORS ``expose_headers`` configuration).

A request id is an operational correlation handle — it carries no
authority and is deliberately not accepted from the client, so it can
never be used to spoof log correlation.
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp

#: Correlation id of the request currently being handled (if any).
request_id_var: ContextVar[str | None] = ContextVar(
    "contextshield_request_id", default=None
)


def current_request_id() -> str | None:
    """Return the active request id, or ``None`` outside a request."""
    return request_id_var.get()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attaches a fresh correlation id to every request/response."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        request_id = uuid.uuid4().hex
        request.state.request_id = request_id
        token = request_id_var.set(request_id)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = request_id
        return response

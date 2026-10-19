"""Typed exceptions raised by the ContextShield SDK.

All SDK errors derive from :class:`ContextShieldError` so callers can catch
one base class and still branch on the specific failure mode:

* :class:`ConfigurationError`  — client is missing/invalid configuration
  (e.g. no credentials supplied for an authenticated call).
* :class:`AuthenticationError` — the gateway rejected the credential (401).
* :class:`PermissionDeniedError` — the verified identity is not allowed to
  perform the operation (403), or the audit scope forbids the query.
* :class:`ValidationError`     — the gateway rejected the request shape
  (400/422); ``details`` carries the structured ``detail`` payload.
* :class:`NotFoundError`       — the addressed resource does not exist, or
  exists but is outside the caller's scope (404).
* :class:`GatewayError`        — the gateway returned a 5xx or an unexpected
  status.
* :class:`GatewayUnavailableError` — the connection could not be established
  (gateway down, DNS failure, TLS failure).
* :class:`RequestTimeoutError` — the request exceeded the configured timeout.
* :class:`InvalidResponseError` — the gateway response was not valid JSON or
  did not match the expected contract.
* :class:`RequestBlockedError` / :class:`RequestEscalatedError` — raised only
  by explicit opt-in helpers (:meth:`SecureRequestResult.raise_if_blocked`):
  a BLOCK / ESCALATION_NEEDED decision is a *normal outcome*, not a
  transport failure, and is returned to the caller as a typed result.
"""

from __future__ import annotations

from typing import Any


class ContextShieldError(Exception):
    """Base class for every error raised by the SDK."""

    def __init__(
        self,
        message: str,
        *,
        request_id: str | None = None,
        status_code: int | None = None,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.request_id = request_id
        self.status_code = status_code
        self.details = details

    def __str__(self) -> str:  # pragma: no cover — trivial
        return self.message


class ConfigurationError(ContextShieldError):
    """The client was used without required configuration (e.g. credentials)."""


class AuthenticationError(ContextShieldError):
    """The gateway rejected the presented credential (HTTP 401)."""


class PermissionDeniedError(ContextShieldError):
    """The verified identity is not permitted to perform the operation (403)."""


class ValidationError(ContextShieldError):
    """The request shape was rejected by the gateway (400/422)."""


class NotFoundError(ContextShieldError):
    """The addressed resource does not exist (or is out of scope; 404)."""


class GatewayError(ContextShieldError):
    """The gateway returned a 5xx or an unexpected response status."""


class GatewayUnavailableError(ContextShieldError):
    """The gateway could not be reached (connection/DNS/TLS failure)."""


class RequestTimeoutError(ContextShieldError):
    """The request exceeded the configured timeout."""


class InvalidResponseError(ContextShieldError):
    """The gateway response was not valid JSON or violated the contract."""


class RequestBlockedError(ContextShieldError):
    """A BLOCK decision raised via :meth:`SecureRequestResult.raise_if_blocked`."""

    def __init__(
        self,
        message: str,
        *,
        request_id: str | None = None,
        reason_codes: list[str] | None = None,
    ) -> None:
        super().__init__(message, request_id=request_id)
        self.reason_codes = list(reason_codes or [])


class RequestEscalatedError(ContextShieldError):
    """An ESCALATION_NEEDED decision raised via ``raise_if_blocked``."""

    def __init__(
        self,
        message: str,
        *,
        request_id: str | None = None,
        reason_codes: list[str] | None = None,
    ) -> None:
        super().__init__(message, request_id=request_id)
        self.reason_codes = list(reason_codes or [])


__all__ = [
    "ContextShieldError",
    "ConfigurationError",
    "AuthenticationError",
    "PermissionDeniedError",
    "ValidationError",
    "NotFoundError",
    "GatewayError",
    "GatewayUnavailableError",
    "RequestTimeoutError",
    "InvalidResponseError",
    "RequestBlockedError",
    "RequestEscalatedError",
]

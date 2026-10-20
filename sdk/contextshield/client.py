"""Synchronous Python client for the ContextShield privacy gateway.

The SDK is a **native convenience layer over the HTTP API** — every method
performs ordinary HTTP calls to the same endpoints any other language or
agent framework can call. Installing the SDK does not, by itself, protect
an application: protected data retrieval and model invocation paths must be
wrapped so they call the gateway (see ``docs/integration-guide.md``).

Authentication
--------------

Exactly one credential form may be configured, in this precedence order:

1. Explicit constructor arguments (``api_key`` / ``token`` /
   ``username`` + ``password`` / ``auth``).
2. Supported credential providers (``api_key_provider`` /
   ``token_provider`` callables — for key rotation and secret managers).
3. Environment variables (``CONTEXTSHIELD_API_KEY``,
   ``CONTEXTSHIELD_TOKEN``, ``CONTEXTSHIELD_USERNAME`` +
   ``CONTEXTSHIELD_PASSWORD``, ``CONTEXTSHIELD_BASE_URL``).

Credentials are never logged and never stored anywhere except memory.

Logging
-------

The logger is named ``contextshield`` and logs method, path, status code,
duration and (when known) the gateway ``request_id``. Request/response
bodies, headers and credentials are never logged.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

import httpx

from .exceptions import (
    AuthenticationError,
    ConfigurationError,
    ContextShieldError,
    GatewayError,
    GatewayUnavailableError,
    InvalidResponseError,
    NotFoundError,
    PermissionDeniedError,
    RequestTimeoutError,
    ValidationError,
)
from .models import (
    AuditEventDetail,
    AuditEventPage,
    SecureRequestContext,
    SecureRequestResult,
)

__all__ = ["ContextShieldClient", "ApiKeyAuth", "TokenAuth", "PasswordAuth"]

logger = logging.getLogger("contextshield")

DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_TIMEOUT = 10.0
DEFAULT_USER_AGENT = "contextshield-python/0.1.0"

_API_PREFIX = "/api/v1"
_SECURE_REQUEST_PATH = f"{_API_PREFIX}/privacy/secure-request"
_LOGIN_PATH = f"{_API_PREFIX}/auth/login"
_AUDIT_EVENTS_PATH = f"{_API_PREFIX}/audit/events"
_HEALTH_PATH = f"{_API_PREFIX}/health"
_STATUS_PATH = f"{_API_PREFIX}/system/status"

ENV_BASE_URL = "CONTEXTSHIELD_BASE_URL"
ENV_API_KEY = "CONTEXTSHIELD_API_KEY"
ENV_TOKEN = "CONTEXTSHIELD_TOKEN"
ENV_USERNAME = "CONTEXTSHIELD_USERNAME"
ENV_PASSWORD = "CONTEXTSHIELD_PASSWORD"


@dataclass(frozen=True)
class ApiKeyAuth:
    """Service-account / agent credential, sent as ``X-API-Key``."""

    api_key: str


@dataclass(frozen=True)
class TokenAuth:
    """Bearer access token (already issued)."""

    token: str


@dataclass(frozen=True)
class PasswordAuth:
    """Username/password login — the SDK exchanges it for a short-lived JWT."""

    username: str
    password: str


class ContextShieldClient:
    """Privacy gateway client.

    Example (credentials from the environment — never hardcode them)::

        from contextshield import ContextShieldClient

        client = ContextShieldClient.from_env()
        result = client.secure_request(
            resource="employee_salary",
            data_fields=["base_salary"],
            purpose="hr_review",
            target_entity="EMP001",
        )
        if result.blocked:
            ...
        else:
            for name, decision in result.fields.items():
                print(name, decision.action, decision.value)

    The client is reusable; call :meth:`close` (or use it as a context
    manager) to release the underlying HTTP connection pool.
    """

    def __init__(
        self,
        base_url: str | None = None,
        *,
        api_key: str | None = None,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        auth: ApiKeyAuth | TokenAuth | PasswordAuth | None = None,
        api_key_provider: Callable[[], str] | None = None,
        token_provider: Callable[[], str] | None = None,
        timeout: float | httpx.Timeout | None = None,
        max_retries: int = 0,
        retry_backoff: float = 0.2,
        verify: bool | str = True,
        user_agent: str = DEFAULT_USER_AGENT,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        resolved_base = (
            base_url or os.environ.get(ENV_BASE_URL) or DEFAULT_BASE_URL
        ).strip()
        if not resolved_base:
            raise ConfigurationError("base_url must not be empty")
        self.base_url = resolved_base.rstrip("/")

        if timeout is None:
            self.timeout: httpx.Timeout = httpx.Timeout(DEFAULT_TIMEOUT)
        elif isinstance(timeout, httpx.Timeout):
            self.timeout = timeout
        else:
            self.timeout = httpx.Timeout(float(timeout))
        if max_retries < 0:
            raise ConfigurationError("max_retries must be >= 0")
        self.max_retries = int(max_retries)
        self.retry_backoff = max(0.0, float(retry_backoff))

        self._auth_kind, self._credential = self._resolve_auth(
            api_key=api_key,
            token=token,
            username=username,
            password=password,
            auth=auth,
            api_key_provider=api_key_provider,
            token_provider=token_provider,
        )
        self._bearer_token: str | None = (
            self._credential if self._auth_kind == "token" else None
        )
        self._password_auth: PasswordAuth | None = (
            self._credential if self._auth_kind == "password" else None
        )
        self._api_key_provider: Callable[[], str] | None = (
            self._credential if self._auth_kind == "api_key_provider" else None
        )
        self._token_provider: Callable[[], str] | None = (
            self._credential if self._auth_kind == "token_provider" else None
        )
        self._static_api_key: str | None = (
            self._credential if self._auth_kind == "api_key" else None
        )

        self._http = httpx.Client(
            timeout=self.timeout,
            verify=verify,
            transport=transport,
            headers={"User-Agent": user_agent, "Accept": "application/json"},
        )

    # ── Construction helpers ───────────────────────────────────────

    @classmethod
    def from_env(cls, **overrides: Any) -> "ContextShieldClient":
        """Build a client from ``CONTEXTSHIELD_*`` environment variables.

        Explicit keyword arguments override the environment.
        """
        return cls(**overrides)

    @staticmethod
    def _resolve_auth(
        *,
        api_key: str | None,
        token: str | None,
        username: str | None,
        password: str | None,
        auth: ApiKeyAuth | TokenAuth | PasswordAuth | None,
        api_key_provider: Callable[[], str] | None,
        token_provider: Callable[[], str] | None,
    ) -> tuple[str, Any]:
        """Pick exactly one credential source (explicit > auth > env)."""
        choices: list[tuple[str, Any]] = []

        if api_key:
            choices.append(("api_key", api_key))
        if token:
            choices.append(("token", token))
        if username or password:
            if not (username and password):
                raise ConfigurationError(
                    "username and password must be provided together"
                )
            choices.append(("password", PasswordAuth(username, password)))
        if isinstance(auth, ApiKeyAuth):
            choices.append(("api_key", auth.api_key))
        elif isinstance(auth, TokenAuth):
            choices.append(("token", auth.token))
        elif isinstance(auth, PasswordAuth):
            choices.append(("password", auth))
        if api_key_provider is not None:
            choices.append(("api_key_provider", api_key_provider))
        if token_provider is not None:
            choices.append(("token_provider", token_provider))

        if not choices:
            env_api_key = os.environ.get(ENV_API_KEY)
            env_token = os.environ.get(ENV_TOKEN)
            env_username = os.environ.get(ENV_USERNAME)
            env_password = os.environ.get(ENV_PASSWORD)
            if env_api_key:
                choices.append(("api_key", env_api_key))
            if env_token:
                choices.append(("token", env_token))
            if env_username or env_password:
                if not (env_username and env_password):
                    raise ConfigurationError(
                        f"{ENV_USERNAME} and {ENV_PASSWORD} must be set together"
                    )
                choices.append(
                    ("password", PasswordAuth(env_username, env_password))
                )

        if not choices:
            # Anonymous clients are allowed: health/status are public, and
            # authenticated calls fail closed with ConfigurationError.
            return ("none", None)
        if len(choices) > 1:
            raise ConfigurationError(
                "Configure exactly one credential (api_key, token, "
                "username/password, or a credential provider)"
            )
        return choices[0]

    # ── Lifecycle ──────────────────────────────────────────────────

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._http.close()

    def __enter__(self) -> "ContextShieldClient":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # ── Public API ─────────────────────────────────────────────────

    def secure_request(
        self,
        *,
        resource: str,
        data_fields: Sequence[str],
        purpose: str,
        operation: str = "read",
        target_entity: str | None = None,
        purpose_detail: str | None = None,
        context: SecureRequestContext | Mapping[str, Any] | None = None,
        session_id: str | None = None,
        conversation_id: str | None = None,
        task_id: str | None = None,
        agent_name: str | None = None,
        include_llm_response: bool = False,
    ) -> SecureRequestResult:
        """Submit a request through the full privacy pipeline.

        ``BLOCK`` and ``ESCALATION_NEEDED`` decisions are normal outcomes
        returned as typed results — they never raise. Transport, auth and
        validation failures raise :class:`~contextshield.exceptions.ContextShieldError`
        subclasses.

        ``context`` carries correlation metadata only (session id, agent
        name, etc.); it is never identity or authorization evidence. The
        convenience keyword arguments are merged into it.
        """
        if not resource or not str(resource).strip():
            raise ConfigurationError("resource must not be empty")
        fields = [str(field).strip() for field in data_fields if str(field).strip()]
        if not fields:
            raise ConfigurationError("data_fields must contain at least one field")
        if not purpose or not str(purpose).strip():
            raise ConfigurationError("purpose must not be empty")

        ctx: dict[str, Any] = {}
        if isinstance(context, SecureRequestContext):
            ctx.update(context.to_dict())
        elif context is not None:
            ctx.update(dict(context))
        for key, value in (
            ("session_id", session_id),
            ("conversation_id", conversation_id),
            ("task_id", task_id),
            ("agent_name", agent_name),
        ):
            if value is not None:
                ctx[key] = str(value)[:64]

        payload: dict[str, Any] = {
            "resource": str(resource).strip(),
            "data_fields": fields,
            "purpose": str(purpose).strip(),
            "operation": operation,
            "include_llm_response": bool(include_llm_response),
        }
        if target_entity is not None:
            payload["target_entity"] = str(target_entity).strip()
        if purpose_detail is not None:
            payload["purpose_detail"] = str(purpose_detail)
        if ctx:
            payload["context"] = ctx

        data = self._request("POST", _SECURE_REQUEST_PATH, json_body=payload)
        result = SecureRequestResult.from_dict(data)
        logger.debug(
            "secure_request decision=%s request_id=%s audit_id=%s",
            result.overall_decision,
            result.request_id,
            result.audit_id,
        )
        return result

    def audit_events(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        requester_id: str | None = None,
        action: str | None = None,
        resource: str | None = None,
        outcome: str | None = None,
        session_id: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> AuditEventPage:
        """Query the audit trail (visibility-scoped server-side)."""
        params: dict[str, Any] = {"limit": int(limit), "offset": int(offset)}
        for key, value in (
            ("requester_id", requester_id),
            ("action", action),
            ("resource", resource),
            ("outcome", outcome),
            ("session_id", session_id),
            ("start_date", start_date),
            ("end_date", end_date),
        ):
            if value is not None:
                params[key] = value
        data = self._request("GET", _AUDIT_EVENTS_PATH, params=params)
        return AuditEventPage.from_dict(data)

    def audit_event(self, event_id: str) -> AuditEventDetail:
        """Fetch full detail of one audit event (404 when out of scope)."""
        event_id = str(event_id).strip()
        if not event_id:
            raise ConfigurationError("event_id must not be empty")
        data = self._request("GET", f"{_AUDIT_EVENTS_PATH}/{event_id}")
        return AuditEventDetail.from_dict(data)

    def health(self) -> dict[str, Any]:
        """Gateway health check (no authentication required)."""
        return self._request("GET", _HEALTH_PATH, auth_required=False)

    def status(self) -> dict[str, Any]:
        """System/provider status (requires authentication)."""
        return self._request("GET", _STATUS_PATH)

    # ── Transport internals ────────────────────────────────────────

    def _auth_headers(self, auth_required: bool) -> dict[str, str]:
        if auth_required:
            self._ensure_credentials()
        if self._static_api_key:
            return {"X-API-Key": self._static_api_key}
        if self._api_key_provider is not None:
            key = str(self._api_key_provider())
            if not key:
                raise ConfigurationError("api_key_provider returned an empty key")
            return {"X-API-Key": key}
        if self._token_provider is not None:
            token = str(self._token_provider())
            if not token:
                raise ConfigurationError("token_provider returned an empty token")
            return {"Authorization": f"Bearer {token}"}
        if self._password_auth is not None:
            self._ensure_token()
            return (
                {"Authorization": f"Bearer {self._bearer_token}"}
                if self._bearer_token
                else {}
            )
        if self._bearer_token:
            return {"Authorization": f"Bearer {self._bearer_token}"}
        return {}

    def _ensure_credentials(self) -> None:
        if self._auth_kind == "none":
            raise ConfigurationError(
                "No credentials configured. Provide api_key/token/username+"
                "password (or CONTEXTSHIELD_* environment variables)."
            )

    def _ensure_token(self) -> None:
        """Log in lazily (and only once per token lifetime)."""
        if self._bearer_token:
            return
        if self._password_auth is None:  # pragma: no cover — defensive
            raise ConfigurationError("password authentication is not configured")
        try:
            response = self._send(
                "POST",
                _LOGIN_PATH,
                json_body={
                    "username": self._password_auth.username,
                    "password": self._password_auth.password,
                },
                headers={},
            )
        except httpx.HTTPError as exc:
            # Login is a transport call like any other: callers must get the
            # SDK's typed errors (timeout/gateway-unavailable), never raw httpx.
            raise self._transport_exception(exc, "POST", _LOGIN_PATH) from exc
        if response.status_code == 401:
            raise AuthenticationError(
                "login failed: invalid username or password",
                status_code=401,
            )
        if response.status_code >= 400:
            raise GatewayError(
                f"login failed with status {response.status_code}",
                status_code=response.status_code,
                details=_error_detail(response),
            )
        payload = _decode_json(response)
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise InvalidResponseError("login response is missing 'access_token'")
        self._bearer_token = token
        logger.debug("authenticated against %s as %s", self.base_url, self._password_auth.username)

    def _transport_exception(
        self, exc: httpx.HTTPError, method: str, path: str
    ) -> ContextShieldError:
        """Map an httpx transport failure to the SDK's public error types."""
        if isinstance(exc, httpx.TimeoutException):
            return RequestTimeoutError(
                f"Request to {method} {path} timed out "
                f"(timeout={self.timeout.connect}s)",
            )
        if isinstance(exc, httpx.TransportError):
            return GatewayUnavailableError(
                f"Could not reach the ContextShield gateway at "
                f"{self.base_url} ({type(exc).__name__})",
            )
        return ContextShieldError(
            f"HTTP error while calling the gateway: {exc}"
        )

    def _send(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        url = f"{self.base_url}{path}"
        return self._http.request(
            method,
            url,
            json=json_body,
            params=dict(params) if params else None,
            headers=dict(headers) if headers is not None else None,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: Mapping[str, Any] | None = None,
        auth_required: bool = True,
    ) -> dict[str, Any]:
        attempt = 0
        relogin_attempted = False
        while True:
            headers = self._auth_headers(auth_required)
            started = time.monotonic()
            try:
                response = self._send(
                    method, path, json_body=json_body, params=params, headers=headers
                )
            except httpx.TimeoutException as exc:
                raise self._transport_exception(exc, method, path) from exc
            except httpx.TransportError as exc:
                if attempt < self.max_retries:
                    attempt += 1
                    time.sleep(self.retry_backoff * attempt)
                    continue
                raise self._transport_exception(exc, method, path) from exc
            except httpx.HTTPError as exc:  # pragma: no cover — defensive
                raise self._transport_exception(exc, method, path) from exc

            duration_ms = int((time.monotonic() - started) * 1000)
            logger.debug(
                "%s %s -> %s (%d ms)", method, path, response.status_code, duration_ms
            )

            if response.status_code == 401 and auth_required:
                if (
                    self._password_auth is not None
                    and not relogin_attempted
                ):
                    # Access token may have expired; re-authenticate once.
                    self._bearer_token = None
                    relogin_attempted = True
                    continue
                raise AuthenticationError(
                    "gateway rejected the credential (401)",
                    status_code=401,
                    details=_error_detail(response),
                )
            if response.status_code == 403:
                raise PermissionDeniedError(
                    "not permitted by the gateway (403)",
                    status_code=403,
                    details=_error_detail(response),
                )
            if response.status_code in (400, 422):
                raise ValidationError(
                    f"request rejected by the gateway ({response.status_code})",
                    status_code=response.status_code,
                    details=_error_detail(response),
                )
            if response.status_code == 404:
                raise NotFoundError(
                    "resource not found (404)",
                    status_code=404,
                    details=_error_detail(response),
                )
            if response.status_code >= 400:
                raise GatewayError(
                    f"unexpected status {response.status_code} from the gateway",
                    status_code=response.status_code,
                    details=_error_detail(response),
                )

            payload = _decode_json(response)
            request_id = payload.get("request_id")
            if isinstance(request_id, str) and request_id:
                logger.debug("%s %s request_id=%s", method, path, request_id)
            return payload


def _decode_json(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as exc:
        raise InvalidResponseError(
            "gateway response was not valid JSON",
            status_code=response.status_code,
        ) from exc
    if not isinstance(payload, dict):
        raise InvalidResponseError(
            "gateway response must be a JSON object",
            status_code=response.status_code,
        )
    return payload


def _error_detail(response: httpx.Response) -> Any:
    """Best-effort structured error detail (safe: never includes secrets)."""
    try:
        payload = response.json()
    except ValueError:
        text = response.text or ""
        return text[:500]
    if isinstance(payload, dict) and "detail" in payload:
        return payload["detail"]
    return payload

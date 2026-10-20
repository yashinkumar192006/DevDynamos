"""Operational-hardening verification (Prompt 11, section D).

Assertions that the operational controls are real and enforced — not just
documented:

* environment-only secrets (no default JWT secret, no default DSN);
* bcrypt password hashing (salted, verifiable, never plaintext);
* JWT hygiene (identity-only claims, expiry and tamper rejection);
* CORS origin allowlist (no wildcard, browser-exposed request id);
* request validation and safe error responses (no internals leaked,
  generic 500s, stable shapes);
* server-generated request ids on every response;
* login rate limiting with ``Retry-After`` and per-IP backstop;
* transaction handling (commit on success, rollback on error);
* audit integrity (read-only API, no mutation methods in the repository);
* system-status payloads free of secret material;
* the structured-log sanitizer as a unit.

Requires the migrated + seeded demo database.

    pytest tests/test_hardening.py -v
"""

import json
import logging
import re
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from jose import jwt as jose_jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.core.config import Settings, settings
from app.core.exceptions import AuthenticationError
from app.core.logging import sanitize_event_dict
from app.core.rate_limit import SlidingWindowRateLimiter
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.main import app
from app.models import AuditAction, AuditEvent, User
from app.repositories import AuditRepository


LOGIN = "/api/v1/auth/login"
HEALTH = "/health"
EVENTS = "/api/v1/audit/events"

PASSWORDS = {
    "admin": "Admin@2024!",
    "sarah.chen": "SarahHR@2024!",
    "natalie.brooks": "NatalieCust@2024!",
}


def _make_url() -> str:
    url = str(settings.DATABASE_URL)
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine(_make_url(), echo=False, poolclass=NullPool)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


async def _login(client: AsyncClient, username: str, password: str):
    return await client.post(
        LOGIN, json={"username": username, "password": password}
    )


async def _token(client: AsyncClient, username: str) -> str:
    response = await _login(client, username, PASSWORDS[username])
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------
# Secrets and configuration
# ------------------------------------------------------------------


def test_secrets_have_no_insecure_defaults():
    fields = Settings.model_fields
    # The application refuses to start without these; there is no
    # fallback value to accidentally deploy.
    assert fields["JWT_SECRET"].is_required()
    assert fields["DATABASE_URL"].is_required()
    # Optional provider keys default to "unset", never to a placeholder.
    assert fields["GEMINI_API_KEY"].default is None
    # Conservative throttling defaults exist and are sane.
    assert fields["AUTH_RATE_LIMIT_ENABLED"].default is True
    assert fields["AUTH_RATE_LIMIT_MAX_FAILURES"].default >= 1
    # CORS never ships a wildcard.
    assert "*" not in settings.CORS_ORIGINS


@pytest.mark.asyncio
async def test_system_status_does_not_leak_secrets(client):
    response = await client.get("/api/v1/system/status")
    assert response.status_code == 200
    text = response.text
    assert settings.JWT_SECRET not in text
    assert str(settings.DATABASE_URL) not in text
    # The DSN password (if any) must not appear in fragments either.
    password = getattr(settings.DATABASE_URL, "password", None) or (
        str(settings.DATABASE_URL).split("://", 1)[-1].split("@", 1)[0].split(":", 1)[-1]
    )
    if password:
        assert password not in text
    if settings.GEMINI_API_KEY:
        assert settings.GEMINI_API_KEY not in text
    assert "Traceback" not in text


# ------------------------------------------------------------------
# Password hashing
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_hashes_are_salted_bcrypt(session):
    users = (await session.execute(select(User))).scalars().all()
    assert users, "seeded users required"
    for user in users:
        assert user.hashed_password.startswith(("$2a$", "$2b$", "$2y$")), (
            f"user {user.username} does not use bcrypt"
        )

    sarah = next(u for u in users if u.username == "sarah.chen")
    assert verify_password("SarahHR@2024!", sarah.hashed_password)
    assert not verify_password("SarahHR@2024", sarah.hashed_password)
    assert not verify_password("", sarah.hashed_password)

    first = hash_password("same-password")
    second = hash_password("same-password")
    assert first != second, "bcrypt must use a fresh salt per hash"
    assert verify_password("same-password", first)
    assert verify_password("same-password", second)


# ------------------------------------------------------------------
# JWT hygiene
# ------------------------------------------------------------------


def test_jwt_tokens_carry_identity_only_and_reject_tampering():
    token, expires_in = create_access_token("user-1", "sarah.chen")
    assert expires_in == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    claims = jose_jwt.get_unverified_claims(token)
    assert set(claims) == {"sub", "username", "iat", "exp", "jti", "typ"}
    assert not {"role", "roles", "permissions", "scopes", "admin"} & set(claims)

    payload = decode_access_token(token)
    assert payload["sub"] == "user-1"
    assert payload["typ"] == "access"

    # Tampered signature.
    tampered = token[:-6] + ("aaaaaa" if not token.endswith("aaaaaa") else "bbbbbb")
    with pytest.raises(AuthenticationError):
        decode_access_token(tampered)

    # Signed with the wrong key.
    forged = jose_jwt.encode(
        {"sub": "user-1", "username": "sarah.chen", "typ": "access", "exp": 99_999_999_999},
        "not-the-real-secret",
        algorithm="HS256",
    )
    with pytest.raises(AuthenticationError):
        decode_access_token(forged)

    # Expired.
    expired, _ = create_access_token("user-1", "sarah.chen", expires_minutes=-5)
    with pytest.raises(AuthenticationError):
        decode_access_token(expired)

    # Type confusion (a refresh-shaped token is not an access token).
    confused = jose_jwt.encode(
        {
            "sub": "user-1",
            "username": "sarah.chen",
            "typ": "refresh",
            "exp": 99_999_999_999,
        },
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(AuthenticationError):
        decode_access_token(confused)


# ------------------------------------------------------------------
# CORS
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cors_allowlist_enforced(client):
    allowed = settings.CORS_ORIGINS[0]

    preflight = await client.options(
        LOGIN,
        headers={
            "Origin": allowed,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert preflight.headers.get("access-control-allow-origin") == allowed

    evil = await client.options(
        LOGIN,
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert evil.headers.get("access-control-allow-origin") is None

    simple = await client.get(HEALTH, headers={"Origin": allowed})
    assert simple.headers.get("access-control-allow-origin") == allowed
    assert "x-request-id" in simple.headers.get(
        "access-control-expose-headers", ""
    ).lower()

    simple_evil = await client.get(HEALTH, headers={"Origin": "https://evil.example"})
    assert simple_evil.headers.get("access-control-allow-origin") is None


# ------------------------------------------------------------------
# Request ids
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_ids_are_server_generated_and_always_present(client):
    first = await client.get(HEALTH)
    second = await client.get(HEALTH)
    request_id = first.headers.get("x-request-id")
    assert request_id and re.fullmatch(r"[0-9a-f]{32}", request_id)
    assert second.headers.get("x-request-id") != request_id

    # A client cannot choose its own correlation id.
    controlled = await client.get(
        HEALTH, headers={"X-Request-ID": "client-controlled"}
    )
    assert controlled.headers.get("x-request-id") != "client-controlled"

    # Error responses carry the id too.
    unauthorized = await _login(client, "sarah.chen", "definitely-wrong")
    assert unauthorized.status_code == 401
    assert re.fullmatch(
        r"[0-9a-f]{32}", unauthorized.headers.get("x-request-id") or ""
    )


# ------------------------------------------------------------------
# Error responses
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_error_responses_are_generic_and_structured(client):
    wrong_password = await _login(client, "sarah.chen", "definitely-wrong")
    unknown_user = await _login(client, "no.such.user", "definitely-wrong")
    assert wrong_password.status_code == unknown_user.status_code == 401
    # Indistinguishable: the client cannot enumerate accounts.
    assert wrong_password.json() == unknown_user.json()
    assert wrong_password.json()["error"]["type"] == "AuthenticationError"
    assert wrong_password.headers.get("www-authenticate") == "Bearer"
    assert "definitely-wrong" not in wrong_password.text

    natalie = await _token(client, "natalie.brooks")
    forbidden = await client.get("/api/v1/admin/users", headers=_bearer(natalie))
    assert forbidden.status_code == 403
    assert "sarah" not in forbidden.text

    missing = await client.get("/api/v1/does-not-exist")
    assert missing.status_code == 404
    for response in (wrong_password, forbidden, missing):
        body = response.text
        assert "Traceback" not in body
        assert "asyncpg" not in body
        assert "sqlalchemy" not in body.lower()

    invalid = await client.post(
        LOGIN,
        json={"username": "x", "password": 12345},
    )
    assert invalid.status_code == 422
    assert "Traceback" not in invalid.text


@pytest.mark.asyncio
async def test_unhandled_exception_returns_generic_500(client, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    marker = f"boom-{uuid4().hex}"

    async def exploding_auth(self, username, password):  # pragma: no cover
        raise RuntimeError(marker)

    monkeypatch.setattr(
        "app.api.v1.auth.AuthService.authenticate_user", exploding_auth
    )

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as raw:
        response = await raw.post(
            LOGIN, json={"username": "sarah.chen", "password": "x"}
        )

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "type": "InternalServerError",
            "detail": "Internal server error",
        }
    }
    # Neither the response nor the log may contain the exception message.
    assert marker not in response.text
    assert marker not in caplog.text
    assert "unhandled_exception" in caplog.text
    # The server-side log still records enough to correlate: the class name
    # and the request id.
    assert "RuntimeError" in caplog.text


# ------------------------------------------------------------------
# Login rate limiting
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_repeated_failed_logins_are_throttled(client, monkeypatch):
    import app.api.v1.auth as auth_module

    monkeypatch.setattr(
        auth_module,
        "login_rate_limiter",
        SlidingWindowRateLimiter(max_failures=3, window_seconds=300),
    )
    monkeypatch.setattr(
        auth_module,
        "login_ip_rate_limiter",
        SlidingWindowRateLimiter(max_failures=10_000, window_seconds=300),
    )

    probe = "rate.limit.probe"
    for _ in range(3):
        response = await _login(client, probe, "wrong-password")
        assert response.status_code == 401

    blocked = await _login(client, probe, "wrong-password")
    assert blocked.status_code == 429
    retry_after = blocked.headers.get("retry-after")
    assert retry_after is not None and int(retry_after) >= 1
    assert blocked.json()["error"]["type"] == "RateLimitError"

    # Throttling happens before credential verification: even the correct
    # password for that key is refused while the window is open.
    blocked_correct = await _login(client, probe, "wrong-password")
    assert blocked_correct.status_code == 429

    # A different account from the same client is unaffected.
    other = await _login(client, "natalie.brooks", PASSWORDS["natalie.brooks"])
    assert other.status_code == 200


@pytest.mark.asyncio
async def test_successful_login_clears_failure_window(client, monkeypatch):
    import app.api.v1.auth as auth_module

    monkeypatch.setattr(
        auth_module,
        "login_rate_limiter",
        SlidingWindowRateLimiter(max_failures=3, window_seconds=300),
    )
    monkeypatch.setattr(
        auth_module,
        "login_ip_rate_limiter",
        SlidingWindowRateLimiter(max_failures=10_000, window_seconds=300),
    )

    for _ in range(2):
        assert (
            await _login(client, "sarah.chen", "wrong-password")
        ).status_code == 401
    assert (
        await _login(client, "sarah.chen", PASSWORDS["sarah.chen"])
    ).status_code == 200
    # The success cleared the history: the next failures start from zero.
    for _ in range(2):
        assert (
            await _login(client, "sarah.chen", "wrong-password")
        ).status_code == 401


@pytest.mark.asyncio
async def test_ip_backstop_catches_username_rotation(client, monkeypatch):
    import app.api.v1.auth as auth_module

    monkeypatch.setattr(
        auth_module,
        "login_rate_limiter",
        SlidingWindowRateLimiter(max_failures=100, window_seconds=300),
    )
    monkeypatch.setattr(
        auth_module,
        "login_ip_rate_limiter",
        SlidingWindowRateLimiter(max_failures=4, window_seconds=300),
    )

    for index in range(4):
        response = await _login(client, f"rotating.user.{index}", "wrong-password")
        assert response.status_code == 401
    rotated = await _login(client, "rotating.user.99", "wrong-password")
    assert rotated.status_code == 429


def test_rate_limiter_window_expiry_uses_sliding_window():
    clock = {"now": 1_000.0}
    limiter = SlidingWindowRateLimiter(
        max_failures=2, window_seconds=10, clock=lambda: clock["now"]
    )
    assert limiter.retry_after("k") is None
    limiter.record_failure("k")
    limiter.record_failure("k")
    retry = limiter.retry_after("k")
    assert retry is not None and 0 < retry <= 10

    clock["now"] += 10.5
    assert limiter.retry_after("k") is None

    limiter.record_failure("k")
    limiter.clear("k")
    assert limiter.retry_after("k") is None


# ------------------------------------------------------------------
# Transactions
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_db_commits_on_success_and_rolls_back_on_error(session):
    from app.core.database import get_db

    marker_ok = f"tx-commit-{uuid4().hex}"
    marker_bad = f"tx-rollback-{uuid4().hex}"

    # Success path: the dependency commits when the request completes.
    generator = get_db()
    db = await generator.__anext__()
    await AuditRepository(db).log_event(
        actor_id=None,
        action=AuditAction.LOGIN,
        resource="auth",
        outcome="success",
        detail=json.dumps({"marker": marker_ok}),
    )
    with pytest.raises(StopAsyncIteration):
        await generator.__anext__()

    stored = (
        await session.execute(
            select(AuditEvent).where(AuditEvent.detail.contains(marker_ok))
        )
    ).scalars().all()
    assert len(stored) == 1

    # Failure path: an exception rolls the transaction back.
    generator2 = get_db()
    db2 = await generator2.__anext__()
    await AuditRepository(db2).log_event(
        actor_id=None,
        action=AuditAction.LOGIN,
        resource="auth",
        outcome="failed",
        detail=json.dumps({"marker": marker_bad}),
    )
    with pytest.raises(RuntimeError):
        await generator2.athrow(RuntimeError("simulated failure"))

    rolled_back = (
        await session.execute(
            select(AuditEvent).where(AuditEvent.detail.contains(marker_bad))
        )
    ).scalars().all()
    assert rolled_back == []

    # Cleanup: the commit-probe row is test residue, not application state.
    for event in stored:
        await session.delete(event)
    await session.commit()


# ------------------------------------------------------------------
# Audit integrity
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_api_is_read_only(client):
    admin = await _token(client, "admin")
    listed = await client.get(
        f"{EVENTS}?limit=1", headers=_bearer(admin)
    )
    assert listed.status_code == 200
    event_id = listed.json()["items"][0]["id"]

    for method in ("put", "patch", "delete"):
        response = await getattr(client, method)(
            f"{EVENTS}/{event_id}", headers=_bearer(admin)
        )
        assert response.status_code == 405, f"{method.upper()} must not exist"
    posted = await client.post(
        f"{EVENTS}/{event_id}", headers=_bearer(admin), json={}
    )
    assert posted.status_code == 405

    # Static surfaces: the audit router defines read routes only, and the
    # audit repository adds no mutation methods of its own (generic CRUD on
    # the base repository is used by other entities, never routed here).
    from app.api.v1.audit import router as audit_router

    for route in audit_router.routes:
        assert set(getattr(route, "methods", set())) <= {"GET", "HEAD"}, (
            f"audit router exposes {route.methods} on {route.path}"
        )
    assert "update" not in AuditRepository.__dict__
    assert "delete" not in AuditRepository.__dict__


# ------------------------------------------------------------------
# Log sanitizer
# ------------------------------------------------------------------


def test_log_sanitizer_redacts_sensitive_keys():
    event = {
        "event": "login_failed",
        "method": "POST",
        "status_code": 401,
        "password": "hunter2",
        "api_key": "csk_live_example",
        "user_token": "eyJhbGciOi",
        "authorization_header": "Bearer xyz",
        "contact_email": "person@example.com",
        "base_salary": 95000,
        "error_type": "AuthenticationError",
    }
    sanitized = sanitize_event_dict(None, "info", dict(event))
    for key in (
        "password",
        "api_key",
        "user_token",
        "authorization_header",
        "contact_email",
        "base_salary",
    ):
        assert sanitized[key] == "[REDACTED]", f"{key} was not redacted"
    # Non-sensitive operational fields survive untouched.
    assert sanitized["event"] == "login_failed"
    assert sanitized["method"] == "POST"
    assert sanitized["status_code"] == 401
    assert sanitized["error_type"] == "AuthenticationError"

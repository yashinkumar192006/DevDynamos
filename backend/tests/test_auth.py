"""Tests for authentication, JWT handling, trusted identity, and RBAC.

Covers (Prompt 5, section F): valid and invalid login, incorrect
passwords, expired and invalid tokens, missing authentication, forbidden
roles, identity spoofing, and resource ownership.

Requires the migrated + seeded demo database (see docs/database-setup.md).
Run with::

    pytest tests/test_auth.py -v
"""

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.main import app


# ------------------------------------------------------------------
# Fixtures & helpers
# ------------------------------------------------------------------


def _make_url() -> str:
    from app.core.config import settings

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
        "/api/v1/auth/login", json={"username": username, "password": password}
    )


async def _token(client: AsyncClient, username: str, password: str) -> str:
    response = await _login(client, username, password)
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _principal_for_user(session: AsyncSession, username: str):
    """Build the same Principal shape AuthService would resolve."""
    from app.repositories import UserRepository
    from app.services import Principal

    repo = UserRepository(session)
    user = await repo.get_by_username(username)
    assert user is not None, f"seed user '{username}' not found"
    roles = frozenset(r.name for r in await repo.get_user_roles(user.id))
    return Principal(
        id=user.id,
        kind="user",
        display_name=user.full_name,
        username=user.username,
        roles=roles,
        user=user,
    )


async def _create_temp_user(session: AsyncSession, username: str, *, is_active: bool = True):
    from app.core.security import hash_password
    from app.models import User

    user = User(
        username=username,
        email=f"{username}@test.contextshield.dev",
        full_name="Temporary Test User",
        hashed_password=hash_password("TempPass@2024!"),
        is_active=is_active,
    )
    session.add(user)
    await session.commit()
    return user


async def _delete_temp_user(session: AsyncSession, user) -> None:
    await session.delete(user)
    await session.commit()


async def _create_service_account(
    session: AsyncSession,
    *,
    scopes=(),
    is_active: bool = True,
    expires_at=None,
):
    from app.core.security import generate_api_key
    from app.models import ServiceAccount

    plaintext, hashed, prefix = generate_api_key()
    account = ServiceAccount(
        name=f"pytest-agent-{uuid4().hex[:10]}",
        description="pytest temporary service account",
        key_prefix=prefix,
        hashed_key=hashed,
        scopes=json.dumps(list(scopes)),
        is_active=is_active,
        expires_at=expires_at,
    )
    session.add(account)
    await session.commit()
    return account, plaintext


async def _delete_service_account(session: AsyncSession, account) -> None:
    await session.delete(account)
    await session.commit()


# ------------------------------------------------------------------
# A. Login
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_success_returns_token_and_profile(client):
    response = await _login(client, "admin", "Admin@2024!")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["expires_in"] > 0
    assert body["user"]["username"] == "admin"
    assert "admin" in {r["name"] for r in body["user"]["roles"]}
    assert any(p["resource"] == "*" for p in body["user"]["permissions"])
    # Hashes must never appear in API output.
    assert "hashed_password" not in response.text


@pytest.mark.asyncio
async def test_login_wrong_password_rejected(client):
    response = await _login(client, "admin", "wrong-password")
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["type"] == "AuthenticationError"
    assert "WWW-Authenticate" in response.headers


@pytest.mark.asyncio
async def test_login_unknown_user_rejected(client):
    response = await _login(client, "does.not.exist", "whatever")
    assert response.status_code == 401
    assert response.json()["error"]["detail"] == "Invalid username or password"


@pytest.mark.asyncio
async def test_login_inactive_user_rejected(client, session):
    username = f"pytest-inactive-{uuid4().hex[:8]}"
    user = await _create_temp_user(session, username, is_active=False)
    try:
        response = await _login(client, username, "TempPass@2024!")
        assert response.status_code == 401
        # Same generic message — account state is not disclosed.
        assert response.json()["error"]["detail"] == "Invalid username or password"
    finally:
        await _delete_temp_user(session, user)


@pytest.mark.asyncio
async def test_login_missing_fields_validation_error(client):
    response = await client.post("/api/v1/auth/login", json={"username": "admin"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_success_updates_last_login(client, session):
    from app.repositories import UserRepository

    await _login(client, "sarah.chen", "SarahHR@2024!")
    user = await UserRepository(session).get_by_username("sarah.chen")
    assert user is not None
    assert user.last_login is not None


# ------------------------------------------------------------------
# B. Token validation (/auth/me)
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_me_returns_authenticated_profile(client):
    token = await _token(client, "sarah.chen", "SarahHR@2024!")
    response = await client.get("/api/v1/auth/me", headers=_bearer(token))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["username"] == "sarah.chen"
    assert body["department"] == "Human Resources"
    assert "hr_manager" in {r["name"] for r in body["roles"]}
    resources = {(p["resource"], p["action"]) for p in body["permissions"]}
    assert ("employee_salary", "read") in resources


@pytest.mark.asyncio
async def test_me_without_token_is_401(client):
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["error"]["type"] == "AuthenticationError"
    assert "WWW-Authenticate" in response.headers


@pytest.mark.asyncio
async def test_me_with_non_bearer_scheme_is_401(client):
    response = await client.get(
        "/api/v1/auth/me", headers={"Authorization": "Basic YWRtaW46YWRtaW4="}
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_with_invalid_token_is_401(client):
    response = await client.get(
        "/api/v1/auth/me", headers=_bearer("this-is-not-a-jwt")
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_with_tampered_token_is_401(client, session):
    token = await _token(client, "admin", "Admin@2024!")
    header, payload, signature = token.split(".")
    position = len(payload) // 2
    flipped = "A" if payload[position] != "A" else "B"
    tampered_payload = payload[:position] + flipped + payload[position + 1 :]
    tampered = f"{header}.{tampered_payload}.{signature}"
    response = await client.get("/api/v1/auth/me", headers=_bearer(tampered))
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_with_expired_token_is_401(client, session):
    from app.core.security import create_access_token

    sarah = await _principal_for_user(session, "sarah.chen")
    expired, _ = create_access_token(
        subject=sarah.id, username="sarah.chen", expires_minutes=-5
    )
    response = await client.get("/api/v1/auth/me", headers=_bearer(expired))
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_with_non_access_token_type_is_401(client, session):
    from datetime import datetime, timezone

    from jose import jwt

    from app.core.config import settings

    sarah = await _principal_for_user(session, "sarah.chen")
    now = datetime.now(timezone.utc)
    forged = jwt.encode(
        {
            "sub": sarah.id,
            "username": "sarah.chen",
            "typ": "refresh",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
        },
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    response = await client.get("/api/v1/auth/me", headers=_bearer(forged))
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_with_token_for_nonexistent_user_is_401(client):
    from app.core.security import create_access_token

    ghost, _ = create_access_token(subject="f" * 32, username="ghost")
    response = await client.get("/api/v1/auth/me", headers=_bearer(ghost))
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_with_deactivated_user_token_is_401(client, session):
    from app.core.security import create_access_token

    username = f"pytest-deact-{uuid4().hex[:8]}"
    user = await _create_temp_user(session, username)
    try:
        token, _ = create_access_token(subject=user.id, username=username)
        # Token works while active…
        assert (
            await client.get("/api/v1/auth/me", headers=_bearer(token))
        ).status_code == 200
        # …and stops working the moment the account is deactivated.
        user.is_active = False
        await session.commit()
        response = await client.get("/api/v1/auth/me", headers=_bearer(token))
        assert response.status_code == 401
    finally:
        await _delete_temp_user(session, user)


@pytest.mark.asyncio
async def test_me_rejects_service_principal(client, session):
    account, api_key = await _create_service_account(session, scopes=["privacy:request"])
    try:
        response = await client.get("/api/v1/auth/me", headers={"X-API-Key": api_key})
        assert response.status_code == 403
        assert response.json()["error"]["type"] == "AuthorizationError"
    finally:
        await _delete_service_account(session, account)


# ------------------------------------------------------------------
# C. Role enforcement (server-side RBAC)
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_endpoint_allows_admin(client):
    token = await _token(client, "admin", "Admin@2024!")
    response = await client.get("/api/v1/admin/users", headers=_bearer(token))
    assert response.status_code == 200, response.text
    usernames = {u["username"] for u in response.json()}
    assert {"admin", "sarah.chen", "eve.johnson", "mia.torres"}.issubset(usernames)


@pytest.mark.asyncio
async def test_admin_endpoint_forbids_non_admin(client):
    token = await _token(client, "lisa.wang", "LisaMkt@2024!")
    response = await client.get("/api/v1/admin/users", headers=_bearer(token))
    assert response.status_code == 403
    body = response.json()
    assert body["error"]["type"] == "AuthorizationError"


@pytest.mark.asyncio
async def test_admin_endpoint_requires_authentication(client):
    response = await client.get("/api/v1/admin/users")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_hr_manager_is_not_admin(client):
    """An authenticated user does not automatically get admin access."""
    token = await _token(client, "sarah.chen", "SarahHR@2024!")
    response = await client.get("/api/v1/admin/users", headers=_bearer(token))
    assert response.status_code == 403


# ------------------------------------------------------------------
# D. Identity spoofing
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_spoofed_identity_headers_are_ignored(client, session):
    """X-User-Id / X-Role / X-Is-Admin headers must never influence identity."""
    from app.repositories import UserRepository

    admin = await UserRepository(session).get_by_username("admin")
    assert admin is not None

    lisa_token = await _token(client, "lisa.wang", "LisaMkt@2024!")
    spoof_headers = {
        **_bearer(lisa_token),
        "X-User-Id": admin.id,
        "X-Username": "admin",
        "X-Role": "admin",
        "X-Is-Admin": "true",
    }

    # Identity stays Lisa…
    me = await client.get("/api/v1/auth/me", headers=spoof_headers)
    assert me.status_code == 200
    assert me.json()["username"] == "lisa.wang"

    # …and the forged admin role grants nothing.
    admin_route = await client.get("/api/v1/admin/users", headers=spoof_headers)
    assert admin_route.status_code == 403


@pytest.mark.asyncio
async def test_login_body_cannot_inject_roles(client):
    """Extra authorization fields in the login body are ignored."""
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "username": "mia.torres",
            "password": "MiaIntern@2024!",
            "role": "admin",
            "roles": ["admin"],
            "is_admin": True,
            "user_id": "0" * 32,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert {r["name"] for r in body["user"]["roles"]} == {"marketing_intern"}
    assert all(p["resource"] != "*" for p in body["user"]["permissions"])


# ------------------------------------------------------------------
# E. Service accounts (AI agent identity)
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_whoami_for_user(client):
    token = await _token(client, "eve.johnson", "EveSupport@2024!")
    response = await client.get("/api/v1/auth/whoami", headers=_bearer(token))
    assert response.status_code == 200
    body = response.json()
    assert body["kind"] == "user"
    assert body["username"] == "eve.johnson"
    assert body["roles"] == ["support_agent"]


@pytest.mark.asyncio
async def test_service_account_authenticates_via_api_key(client, session):
    account, api_key = await _create_service_account(
        session, scopes=["privacy:request", "customer_records:read"]
    )
    try:
        response = await client.get(
            "/api/v1/auth/whoami", headers={"X-API-Key": api_key}
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["kind"] == "service"
        assert body["display_name"] == account.name
        assert body["scopes"] == ["customer_records:read", "privacy:request"]
    finally:
        await _delete_service_account(session, account)


@pytest.mark.asyncio
async def test_service_account_invalid_key_rejected(client):
    response = await client.get(
        "/api/v1/auth/whoami", headers={"X-API-Key": "csk_not-a-real-key"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["type"] == "AuthenticationError"


@pytest.mark.asyncio
async def test_service_account_inactive_and_expired_rejected(client, session):
    inactive, inactive_key = await _create_service_account(
        session, scopes=["privacy:request"], is_active=False
    )
    expired, expired_key = await _create_service_account(
        session,
        scopes=["privacy:request"],
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    try:
        r1 = await client.get("/api/v1/auth/whoami", headers={"X-API-Key": inactive_key})
        r2 = await client.get("/api/v1/auth/whoami", headers={"X-API-Key": expired_key})
        assert r1.status_code == 401
        assert r2.status_code == 401
    finally:
        await _delete_service_account(session, inactive)
        await _delete_service_account(session, expired)


@pytest.mark.asyncio
async def test_service_scope_gates_admin_endpoint(client, session):
    privileged, privileged_key = await _create_service_account(
        session, scopes=["role:admin"]
    )
    limited, limited_key = await _create_service_account(
        session, scopes=["privacy:request"]
    )
    try:
        allowed = await client.get(
            "/api/v1/admin/users", headers={"X-API-Key": privileged_key}
        )
        denied = await client.get(
            "/api/v1/admin/users", headers={"X-API-Key": limited_key}
        )
        assert allowed.status_code == 200
        assert denied.status_code == 403
    finally:
        await _delete_service_account(session, privileged)
        await _delete_service_account(session, limited)


@pytest.mark.asyncio
async def test_both_credentials_rejected(client, session):
    """Presenting a JWT and an API key together is ambiguous — reject it."""
    token = await _token(client, "admin", "Admin@2024!")
    account, api_key = await _create_service_account(session, scopes=["*"])
    try:
        response = await client.get(
            "/api/v1/auth/whoami",
            headers={**_bearer(token), "X-API-Key": api_key},
        )
        assert response.status_code == 401
    finally:
        await _delete_service_account(session, account)


# ------------------------------------------------------------------
# F. AuthorizationService — resource, field, ownership, purpose
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resource_access_user_permissions(session):
    from app.services import AuthorizationService

    authz = AuthorizationService(session)
    sarah = await _principal_for_user(session, "sarah.chen")
    lisa = await _principal_for_user(session, "lisa.wang")
    admin = await _principal_for_user(session, "admin")
    eve = await _principal_for_user(session, "eve.johnson")
    mia = await _principal_for_user(session, "mia.torres")

    # HR manager: salary read granted.
    d = await authz.check_resource_access(sarah, "employee_salary", "read")
    assert d.allowed and d.reason_code == "PERMISSION_GRANTED"

    # Viewer: same request denied — role alone proves nothing.
    d = await authz.check_resource_access(lisa, "employee_salary", "read")
    assert not d.allowed and d.reason_code == "NO_MATCHING_PERMISSION"

    # Admin wildcard.
    d = await authz.check_resource_access(admin, "anything_at_all", "delete")
    assert d.allowed

    # Support agent: customer records read granted, aggregates not.
    d = await authz.check_resource_access(eve, "customer_records", "read")
    assert d.allowed
    d = await authz.check_resource_access(eve, "customer_records", "aggregate")
    assert not d.allowed

    # Marketing intern: aggregates only, no raw reads.
    d = await authz.check_resource_access(mia, "customer_records", "aggregate")
    assert d.allowed
    d = await authz.check_resource_access(mia, "customer_records", "read")
    assert not d.allowed


@pytest.mark.asyncio
async def test_resource_access_service_scopes(session):
    from app.services import AuthorizationService, Principal

    authz = AuthorizationService(session)
    agent = Principal(
        id="0" * 32,
        kind="service",
        display_name="test-agent",
        scopes=frozenset({"customer_records:read"}),
    )
    d = await authz.check_resource_access(agent, "customer_records", "read")
    assert d.allowed and d.reason_code == "SCOPE_GRANTED"
    d = await authz.check_resource_access(agent, "customer_records", "aggregate")
    assert not d.allowed and d.reason_code == "NO_MATCHING_SCOPE"


@pytest.mark.asyncio
async def test_allowed_operations(session):
    from app.services import AuthorizationService

    authz = AuthorizationService(session)

    lisa = await _principal_for_user(session, "lisa.wang")
    assert await authz.allowed_operations(lisa, "employee_records") == {"read"}
    assert await authz.allowed_operations(lisa, "employee_salary") == set()

    mia = await _principal_for_user(session, "mia.torres")
    assert await authz.allowed_operations(mia, "customer_records") == {"aggregate"}

    admin = await _principal_for_user(session, "admin")
    assert "delete" in await authz.allowed_operations(admin, "customer_records")


@pytest.mark.asyncio
async def test_field_access(session):
    from app.services import AuthorizationService

    authz = AuthorizationService(session)
    sarah = await _principal_for_user(session, "sarah.chen")
    lisa = await _principal_for_user(session, "lisa.wang")

    # Sarah may read the full_name field of employee_records…
    d = await authz.check_field_access(sarah, "employee_records", "full_name")
    assert d.allowed and d.reason_code == "FIELD_PERMITTED"

    # …Lisa has the same asset-level permission.
    d = await authz.check_field_access(lisa, "employee_records", "email")
    assert d.allowed

    # Lisa may not read salary fields at all.
    d = await authz.check_field_access(lisa, "employee_salary", "base_salary")
    assert not d.allowed and d.reason_code == "NO_MATCHING_PERMISSION"

    # Unknown fields fail closed even with permission.
    d = await authz.check_field_access(sarah, "employee_records", "nonexistent_field")
    assert not d.allowed and d.reason_code == "FIELD_NOT_FOUND"


@pytest.mark.asyncio
async def test_filter_fields_partitions(session):
    from app.services import AuthorizationService

    authz = AuthorizationService(session)
    sarah = await _principal_for_user(session, "sarah.chen")

    permitted, denied = await authz.filter_fields(
        sarah, "employee_records", ["full_name", "salary", "not_a_field"]
    )
    assert permitted == ["full_name"]
    assert denied == ["salary", "not_a_field"]

    lisa = await _principal_for_user(session, "lisa.wang")
    permitted, denied = await authz.filter_fields(
        lisa, "employee_salary", ["base_salary"]
    )
    assert permitted == []
    assert denied == ["base_salary"]


@pytest.mark.asyncio
async def test_data_ownership(session):
    from app.services import AuthorizationService, Principal

    authz = AuthorizationService(session)
    sarah = await _principal_for_user(session, "sarah.chen")

    # Sarah owns EMP001 (linked via employees.user_id)…
    d = await authz.check_data_ownership(sarah, "employee_records", "EMP001")
    assert d.allowed and d.reason_code == "OWNER_MATCH"

    # …but not John Park's record.
    d = await authz.check_data_ownership(sarah, "employee_records", "EMP010")
    assert not d.allowed and d.reason_code == "NOT_OWNER"

    # Service principals can never own personal records.
    agent = Principal(id="0" * 32, kind="service", display_name="test-agent")
    d = await authz.check_data_ownership(agent, "employee_records", "EMP001")
    assert not d.allowed and d.reason_code == "NOT_OWNER"

    # Ownership is independent of RBAC: Lisa (viewer) still owns her record.
    lisa = await _principal_for_user(session, "lisa.wang")
    d = await authz.check_data_ownership(lisa, "employee_salary", "EMP007")
    assert d.allowed

    # Unknown record keys fail closed.
    d = await authz.check_data_ownership(sarah, "employee_records", "EMP999")
    assert not d.allowed and d.reason_code == "RECORD_NOT_FOUND"


@pytest.mark.asyncio
async def test_purpose_restrictions(session):
    from app.services import AuthorizationService

    authz = AuthorizationService(session)
    sarah = await _principal_for_user(session, "sarah.chen")
    alex = await _principal_for_user(session, "alex.kumar")
    lisa = await _principal_for_user(session, "lisa.wang")

    # HR manager + hr_review on salary — allowed by the active v2 policy.
    d = await authz.check_purpose(sarah, "employee_salary", "hr_review")
    assert d.allowed and d.reason_code == "PURPOSE_ALLOWED"

    # HR manager + analytics on salary — not a permitted purpose.
    d = await authz.check_purpose(sarah, "employee_salary", "analytics")
    assert not d.allowed and d.reason_code == "PURPOSE_NOT_ALLOWED"

    # Analyst + department statistics — allowed by the aggregate policy.
    d = await authz.check_purpose(
        alex, "employee_salary", "department_statistics"
    )
    assert d.allowed

    # Lisa + hr_review on salary — policy requires hr_manager.
    d = await authz.check_purpose(lisa, "employee_salary", "hr_review")
    assert not d.allowed

    # Resource with no active policy — fail closed.
    d = await authz.check_purpose(sarah, "nonexistent_dataset", "hr_review")
    assert not d.allowed and d.reason_code == "NO_POLICY_FOR_RESOURCE"

    # employee_records gained self-service coverage in phase 7.
    d = await authz.check_purpose(lisa, "employee_records", "general")
    assert d.allowed and d.reason_code == "PURPOSE_ALLOWED"

    # Unknown purposes are rejected outright.
    d = await authz.check_purpose(sarah, "employee_salary", "just_because")
    assert not d.allowed and d.reason_code == "INVALID_PURPOSE"


# ------------------------------------------------------------------
# G. Audit trail
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_writes_audit_events(client, session):
    from app.models import AuditAction, AuditEvent

    count_stmt = (
        select(func.count())
        .select_from(AuditEvent)
        .where(AuditEvent.action == AuditAction.LOGIN)
    )
    before = (await session.execute(count_stmt)).scalar_one()

    await _login(client, "admin", "Admin@2024!")
    await _login(client, f"nobody-{uuid4().hex[:8]}", "wrong")

    after = (await session.execute(count_stmt)).scalar_one()
    assert after >= before + 2

    failed_stmt = (
        select(AuditEvent)
        .where(
            AuditEvent.action == AuditAction.LOGIN,
            AuditEvent.outcome == "failed",
            AuditEvent.actor_id.is_(None),
        )
        .order_by(AuditEvent.created_at.desc())
        .limit(1)
    )
    failed = (await session.execute(failed_stmt)).scalars().first()
    assert failed is not None
    # Detail identifies the attempted username but never the password.
    assert "wrong" not in (failed.detail or "")

"""Tests for the policy catalogue API (Prompt 10 backend support).

Covers:

* authentication required;
* any authenticated principal reads the *active* policies;
* inactive/superseded history is administrator-only (403 otherwise);
* resource / role filters use policy-engine matching semantics;
* pagination metadata;
* validation errors.

Requires the migrated + seeded demo database. Run with::

    pytest tests/test_policies_api.py -v
"""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.main import app

pytestmark = pytest.mark.asyncio

POLICIES_URL = "/api/v1/policies"

PASSWORDS = {
    "admin": "Admin@2024!",
    "sarah.chen": "SarahHR@2024!",
    "natalie.brooks": "NatalieCust@2024!",
}


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


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _token(client: AsyncClient, username: str) -> str:
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": PASSWORDS[username]},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


async def _list(client: AsyncClient, headers: dict, **params) -> tuple[int, dict]:
    response = await client.get(POLICIES_URL, params=params, headers=headers)
    return response.status_code, (response.json() if response.content else {})


# ------------------------------------------------------------------
# Access control
# ------------------------------------------------------------------


async def test_policies_require_authentication(client):
    response = await client.get(POLICIES_URL)
    assert response.status_code == 401


async def test_any_authenticated_user_reads_active_policies(client):
    token = await _token(client, "natalie.brooks")
    status, body = await _list(client, _bearer(token))
    assert status == 200, body

    assert body["items"], "seeded demo policies must be visible"
    assert body["pagination"]["total"] >= len(body["items"])

    for item in body["items"]:
        assert item["is_active"] is True
        assert item["status"] == "active"
        assert item["name"]
        assert item["policy_text"]
        assert isinstance(item["allowed_purposes"], list)
        assert isinstance(item["allowed_actions"], list)
        assert isinstance(item["priority"], int)
        assert item["effective_from"]


async def test_inactive_history_is_admin_only(client):
    natalie = _bearer(await _token(client, "natalie.brooks"))
    status, body = await _list(client, natalie, include_inactive="true")
    assert status == 403, body

    admin = _bearer(await _token(client, "admin"))
    status, body = await _list(client, admin, include_inactive="true", limit=100)
    assert status == 200, body
    assert body["items"]
    assert all(
        item["status"] in ("active", "superseded", "archived", "draft")
        for item in body["items"]
    )


# ------------------------------------------------------------------
# Filters & pagination
# ------------------------------------------------------------------


async def test_resource_filter_uses_engine_matching(client):
    token = await _token(client, "natalie.brooks")
    status, body = await _list(client, _bearer(token), resource="employee_salary")
    assert status == 200
    assert body["pagination"]["total"] >= 2
    for item in body["items"]:
        pattern = item["resource_pattern"]
        assert pattern == "employee_salary" or (
            pattern.endswith("*") and "employee_salary".startswith(pattern[:-1])
        )
    names = {item["name"] for item in body["items"]}
    assert "salary_access_policy" in names


async def test_role_filter_and_pagination(client):
    token = await _token(client, "natalie.brooks")
    headers = _bearer(token)

    status, body = await _list(client, headers, role="hr_manager", limit=100)
    assert status == 200
    assert body["items"]
    assert all(
        item["required_role"] == "hr_manager" for item in body["items"]
    )

    status, page1 = await _list(client, headers, limit=1)
    assert status == 200
    assert len(page1["items"]) == 1
    assert page1["pagination"]["total"] >= 2
    assert page1["pagination"]["has_more"] is True

    status, page2 = await _list(client, headers, limit=1, offset=1)
    assert status == 200
    assert page2["items"][0]["id"] != page1["items"][0]["id"]


async def test_query_validation(client):
    admin = _bearer(await _token(client, "admin"))
    for params in (
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"resource": ""},
        {"include_inactive": "not-a-bool"},
    ):
        response = await client.get(POLICIES_URL, params=params, headers=admin)
        assert response.status_code == 422, (params, response.text)

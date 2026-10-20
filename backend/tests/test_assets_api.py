"""Tests for the data-asset catalogue API (Prompt 10 backend support).

Covers:

* authentication required;
* assets and field classifications from the seeded catalogue;
* record counts match the actual backing tables;
* sensitivity filtering and pagination;
* the payload is metadata only — no raw protected values, no row data.

Requires the migrated + seeded demo database. Run with::

    pytest tests/test_assets_api.py -v
"""

import json

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.main import app
from app.models import Employee

pytestmark = pytest.mark.asyncio

ASSETS_URL = "/api/v1/data/assets"

PASSWORDS = {
    "admin": "Admin@2024!",
    "natalie.brooks": "NatalieCust@2024!",
}

SENSITIVITY_LEVELS = {"low", "medium", "high", "restricted"}


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
    response = await client.get(ASSETS_URL, params=params, headers=headers)
    return response.status_code, (response.json() if response.content else {})


# ------------------------------------------------------------------
# Access & content
# ------------------------------------------------------------------


async def test_assets_require_authentication(client):
    response = await client.get(ASSETS_URL)
    assert response.status_code == 401


async def test_assets_catalogue_shape(client, session):
    token = await _token(client, "natalie.brooks")
    status, body = await _list(client, _bearer(token), limit=100)
    assert status == 200, body

    by_name = {item["name"]: item for item in body["items"]}
    assert {"employee_records", "employee_salary", "customer_records",
            "order_records", "financial_docs"} <= set(by_name)

    for item in body["items"]:
        assert item["asset_type"]
        assert item["field_count"] == len(item["fields"])
        assert set(item["sensitivity_summary"]) == SENSITIVITY_LEVELS
        assert sum(item["sensitivity_summary"].values()) == item["field_count"]
        for field in item["fields"]:
            assert field["name"]
            assert field["sensitivity"] in SENSITIVITY_LEVELS
            assert field["field_type"]

    # The restricted salary field is classified and carries its PII category.
    salary = by_name["employee_salary"]
    restricted = {
        f["name"]: f
        for f in salary["fields"]
        if f["sensitivity"] == "restricted"
    }
    assert "base_salary" in restricted
    assert restricted["base_salary"]["pii_category"] == "salary"


async def test_record_counts_match_backing_tables(client, session):
    token = await _token(client, "natalie.brooks")
    status, body = await _list(client, _bearer(token), limit=100)
    assert status == 200

    by_name = {item["name"]: item for item in body["items"]}
    expected_employees = await session.scalar(
        select(func.count()).select_from(Employee)
    )
    assert by_name["employee_records"]["record_count"] == expected_employees
    assert expected_employees and expected_employees >= 1
    # All demo assets report a count (their tables are seeded).
    assert all(
        item["record_count"] is not None for item in body["items"]
    )


async def test_payload_is_metadata_only(client):
    token = await _token(client, "natalie.brooks")
    status, body = await _list(client, _bearer(token), limit=100)
    assert status == 200

    text = json.dumps(body)
    # No raw protected values (synthetic demo data) can appear.
    assert "Acme" not in text
    assert "98000" not in text
    assert "@contextshield.dev" not in text
    assert "Jane" not in text
    # Only metadata keys are present on fields.
    allowed_keys = {
        "name", "column_name", "field_type", "sensitivity",
        "pii_category", "description",
    }
    for item in body["items"]:
        for field in item["fields"]:
            assert set(field) <= allowed_keys


# ------------------------------------------------------------------
# Filters & pagination
# ------------------------------------------------------------------


async def test_sensitivity_filter(client):
    token = await _token(client, "natalie.brooks")
    status, body = await _list(client, _bearer(token), sensitivity="restricted",
                               limit=100)
    assert status == 200
    assert body["items"]
    for item in body["items"]:
        assert item["sensitivity_summary"]["restricted"] >= 1


async def test_asset_type_filter_and_pagination(client):
    token = await _token(client, "natalie.brooks")
    headers = _bearer(token)

    status, body = await _list(client, headers, asset_type="customer_records")
    assert status == 200
    assert body["items"]
    assert all(item["asset_type"] == "customer_records" for item in body["items"])

    status, page1 = await _list(client, headers, limit=1)
    assert status == 200
    assert len(page1["items"]) == 1
    assert page1["pagination"]["total"] >= 5
    assert page1["pagination"]["has_more"] is True

    status, page2 = await _list(client, headers, limit=1, offset=1)
    assert status == 200
    assert page2["items"][0]["id"] != page1["items"][0]["id"]


async def test_query_validation(client):
    token = _bearer(await _token(client, "admin"))
    for params in (
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"sensitivity": "top-secret"},
    ):
        response = await client.get(ASSETS_URL, params=params, headers=token)
        assert response.status_code == 422, (params, response.text)

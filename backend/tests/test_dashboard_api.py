"""Tests for the dashboard overview API (Prompt 10 backend support).

Covers:

* authentication required, window/recent validation;
* visibility scopes mirror the audit trail (``own`` / ``privacy_trail`` /
  ``full``);
* real aggregation: counters move exactly when real decisions are recorded
  (delta checks) — never fabricated;
* transformation / model-invocation / guard counters;
* health, daily series, and policy stats.

Requires the migrated + seeded demo database. Run with::

    pytest tests/test_dashboard_api.py -v
"""

from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.main import app
from app.models import User
from app.services.llm_adapter import LLMResponse, SafeLLMService

pytestmark = pytest.mark.asyncio

DASHBOARD_URL = "/api/v1/dashboard/overview"
SECURE_URL = "/api/v1/privacy/secure-request"

PASSWORDS = {
    "admin": "Admin@2024!",
    "sarah.chen": "SarahHR@2024!",
    "eve.johnson": "EveSupport@2024!",
    "natalie.brooks": "NatalieCust@2024!",
}

DECISION_KEYS = {"ALLOW", "PARTIAL_ALLOW", "BLOCK", "ESCALATION_NEEDED"}


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


async def _secure(
    client: AsyncClient,
    token: str,
    *,
    resource: str,
    fields: list[str],
    purpose: str,
    target: str | None = None,
    session_id: str | None = None,
    include_llm: bool = False,
) -> dict:
    payload: dict = {
        "resource": resource,
        "data_fields": fields,
        "purpose": purpose,
        "include_llm_response": include_llm,
    }
    if target is not None:
        payload["target_entity"] = target
    if session_id is not None:
        payload["context"] = {"session_id": session_id}
    response = await client.post(SECURE_URL, json=payload, headers=_bearer(token))
    assert response.status_code == 200, response.text
    return response.json()


async def _overview(client: AsyncClient, headers: dict, **params) -> dict:
    response = await client.get(DASHBOARD_URL, params=params, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


async def _user_id(session: AsyncSession, username: str) -> str:
    return (
        await session.execute(select(User.id).where(User.username == username))
    ).scalar_one()


class _RecordingProvider:
    """Deterministic provider; output carries no PII so the guard passes."""

    name = "recording"
    model = "recording-1"

    async def generate(self, *, system: str, prompt: str) -> LLMResponse:
        return LLMResponse(
            text="Customer contact details summarised safely.",
            provider=self.name,
            model=self.model,
        )


def _install_llm(monkeypatch) -> None:
    service = SafeLLMService(provider=_RecordingProvider())
    monkeypatch.setattr("app.api.v1.privacy.build_llm_service", lambda: service)


# ------------------------------------------------------------------
# Access & validation
# ------------------------------------------------------------------


async def test_dashboard_requires_authentication(client):
    response = await client.get(DASHBOARD_URL)
    assert response.status_code == 401


async def test_query_validation(client):
    admin = _bearer(await _token(client, "admin"))
    for params in (
        {"window_days": 0},
        {"window_days": 91},
        {"recent_limit": 0},
        {"recent_limit": 51},
    ):
        response = await client.get(DASHBOARD_URL, params=params, headers=admin)
        assert response.status_code == 422, (params, response.text)


# ------------------------------------------------------------------
# Own scope — counters move exactly with real decisions
# ------------------------------------------------------------------


async def test_own_scope_counts_move_only_with_real_decisions(client, session):
    natalie_token = await _token(client, "natalie.brooks")
    natalie_id = await _user_id(session, "natalie.brooks")
    headers = _bearer(natalie_token)

    before = await _overview(client, headers, window_days=1)
    assert before["scope"] == "own"
    assert set(before["summary"]["decisions"]) == DECISION_KEYS
    assert all(
        item["actor"]["id"] == natalie_id for item in before["recent_decisions"]
    )

    sid = f"dash-{uuid4().hex[:12]}"
    allowed = await _secure(
        client, natalie_token,
        resource="order_records", fields=["order_id", "status"],
        purpose="order_status", target="ORD0001", session_id=sid,
    )
    assert allowed["overall_decision"] == "ALLOW"
    blocked = await _secure(
        client, natalie_token,
        resource="customer_records", fields=["contact_email"],
        purpose="order_status", target="CUS002", session_id=sid,
    )
    assert blocked["overall_decision"] == "BLOCK"

    after = await _overview(client, headers, window_days=1)
    b, a = before["summary"], after["summary"]
    assert a["total_requests"] == b["total_requests"] + 2
    assert a["decisions"]["ALLOW"] == b["decisions"]["ALLOW"] + 1
    assert a["decisions"]["BLOCK"] == b["decisions"]["BLOCK"] + 1
    assert a["decisions"]["PARTIAL_ALLOW"] == b["decisions"]["PARTIAL_ALLOW"]
    assert a["decisions"]["ESCALATION_NEEDED"] == b["decisions"]["ESCALATION_NEEDED"]

    # Recent decisions carry the audit projection of the requests just made.
    assert all(
        item["actor"]["id"] == natalie_id for item in after["recent_decisions"]
    )
    request_ids = {item["request_id"] for item in after["recent_decisions"]}
    assert allowed["request_id"] in request_ids
    assert blocked["request_id"] in request_ids

    # The daily series covers the window and includes the new decisions.
    assert len(after["daily"]) == 1
    assert after["daily"][0]["total"] >= 2
    assert after["daily"][0]["block"] >= 1


# ------------------------------------------------------------------
# Transformation / model / guard counters
# ------------------------------------------------------------------


async def test_transformation_and_model_counters(client, monkeypatch):
    _install_llm(monkeypatch)
    eve_token = await _token(client, "eve.johnson")
    headers = _bearer(eve_token)

    before = await _overview(client, headers, window_days=1)
    assert before["scope"] == "own"

    sid = f"dash-{uuid4().hex[:12]}"
    result = await _secure(
        client, eve_token,
        resource="customer_records", fields=["contact_email", "contact_phone"],
        purpose="customer_service", target="CUS003", session_id=sid,
        include_llm=True,
    )
    assert result["overall_decision"] in ("ALLOW", "PARTIAL_ALLOW")
    assert result["llm_response"]

    after = await _overview(client, headers, window_days=1)
    b, a = before["summary"], after["summary"]
    assert (
        a["requests_with_transformations"]
        == b["requests_with_transformations"] + 1
    )
    assert a["model_invocations"] == b["model_invocations"] + 1
    # The recording provider returns clean text: the guard must not fire.
    assert a["guard_triggered"] == b["guard_triggered"]


# ------------------------------------------------------------------
# Visibility scopes & live configuration
# ------------------------------------------------------------------


async def test_hr_manager_scope_is_privacy_trail(client):
    sarah = _bearer(await _token(client, "sarah.chen"))
    body = await _overview(client, sarah, window_days=7)
    assert body["scope"] == "privacy_trail"
    # Recent decisions are decision events by definition — never auth or
    # admin events, which stay outside the compliance scope.
    for item in body["recent_decisions"]:
        assert item["action"] in ("data_access", "data_denied")


async def test_admin_scope_health_and_policy_stats(client):
    admin = _bearer(await _token(client, "admin"))
    body = await _overview(client, admin, window_days=7)

    assert body["scope"] == "full"
    assert len(body["daily"]) == 7
    dates = [point["date"] for point in body["daily"]]
    assert dates == sorted(dates)

    health = body["health"]
    assert health["database"] == "healthy"
    assert isinstance(health["database_latency_ms"], (int, float))
    assert health["llm"]["provider"] == "mock"
    assert health["llm"]["configured"] is True
    assert health["classifier"]["status"] in ("ready", "deterministic_only")

    assert body["policy_stats"]["active_policies"] >= 1

    for item in body["recent_decisions"]:
        assert item["action"] in ("data_access", "data_denied")
        assert "actor" in item
        assert item["timestamp"]

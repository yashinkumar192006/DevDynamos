"""Tests for the audit & explainability APIs (Prompt 9, part A).

Covers:

* access scopes — admin (full trail), hr_manager/executive (privacy trail),
  every other principal (own events only), agent/service principals;
* out-of-scope filters → 403, out-of-scope / unknown event ids → 404;
* filters (action, requester_id, resource, outcome, session_id, date range)
  and pagination (limit/offset/total/has_more);
* recorded content — request/correlation ids, verified requester and agent
  identifiers, resource identifiers, decision + reason codes, policy
  versions, transformations, model invocation, inspection outcome;
* audit responses never contain raw protected values, credentials, tokens,
  service API keys, purpose free text, or prompts.

Requires the migrated + seeded demo database. Run with::

    pytest tests/test_audit_api.py -v
"""

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.core.security import generate_api_key
from app.main import app
from app.models import AuditEvent, ServiceAccount, User
from app.services.audit_service import PRIVACY_TRAIL_ACTIONS
from app.services.llm_adapter import LLMResponse, SafeLLMService

pytestmark = pytest.mark.asyncio

EVENTS_URL = "/api/v1/audit/events"
SECURE_URL = "/api/v1/privacy/secure-request"

PASSWORDS = {
    "admin": "Admin@2024!",
    "sarah.chen": "SarahHR@2024!",
    "eve.johnson": "EveSupport@2024!",
    "mia.torres": "MiaIntern@2024!",
    "natalie.brooks": "NatalieCust@2024!",
}

PRIVACY_ACTION_VALUES = {action.value for action in PRIVACY_TRAIL_ACTIONS}


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
    purpose_detail: str | None = None,
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
    if purpose_detail is not None:
        payload["purpose_detail"] = purpose_detail
    if session_id is not None:
        payload["context"] = {"session_id": session_id}
    response = await client.post(SECURE_URL, json=payload, headers=_bearer(token))
    assert response.status_code == 200, response.text
    return response.json()


async def _api_key_secure(
    client: AsyncClient,
    api_key: str,
    *,
    resource: str,
    fields: list[str],
    purpose: str,
    target: str,
    session_id: str,
) -> dict:
    response = await client.post(
        SECURE_URL,
        json={
            "resource": resource,
            "data_fields": fields,
            "purpose": purpose,
            "target_entity": target,
            "context": {"session_id": session_id},
        },
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _get_events(client: AsyncClient, headers: dict, **params) -> tuple[int, dict]:
    response = await client.get(EVENTS_URL, params=params, headers=headers)
    return response.status_code, (
        response.json() if response.content else {}
    )


async def _get_detail(
    client: AsyncClient, headers: dict, event_id: str
) -> tuple[int, dict]:
    response = await client.get(f"{EVENTS_URL}/{event_id}", headers=headers)
    return response.status_code, (response.json() if response.content else {})


async def _event_row(
    session: AsyncSession,
    *,
    session_id: str,
    actor_id: str | None = None,
) -> AuditEvent:
    stmt = select(AuditEvent).where(AuditEvent.session_id == session_id)
    if actor_id is not None:
        stmt = stmt.where(AuditEvent.actor_id == actor_id)
    rows = (await session.execute(stmt)).scalars().all()
    assert rows, f"no audit event for session {session_id!r}"
    return rows[0]


async def _user_id(session: AsyncSession, username: str) -> str:
    return (
        await session.execute(select(User.id).where(User.username == username))
    ).scalar_one()


async def _create_service_account(
    session: AsyncSession, *, scopes: list[str], label: str
) -> tuple[ServiceAccount, str]:
    plaintext, hashed, prefix = generate_api_key()
    account = ServiceAccount(
        name=f"audit-test-{label}-{uuid4().hex[:10]}",
        description="Prompt-9 audit tests",
        key_prefix=prefix,
        hashed_key=hashed,
        scopes=json.dumps(scopes),
        is_active=True,
    )
    session.add(account)
    await session.commit()
    return account, plaintext


class _RecordingProvider:
    """Deterministic provider; output carries no PII so the guard passes."""

    name = "recording"
    model = "recording-1"

    async def generate(self, *, system: str, prompt: str) -> LLMResponse:
        return LLMResponse(
            text="Quarterly compensation summary generated.",
            provider=self.name,
            model=self.model,
        )


def _install_llm(monkeypatch) -> None:
    service = SafeLLMService(provider=_RecordingProvider())
    monkeypatch.setattr("app.api.v1.privacy.build_llm_service", lambda: service)


# ------------------------------------------------------------------
# Authentication / basic access
# ------------------------------------------------------------------


async def test_audit_endpoints_require_authentication(client):
    response = await client.get(EVENTS_URL)
    assert response.status_code == 401
    response = await client.get(f"{EVENTS_URL}/{'a' * 32}")
    assert response.status_code == 401


async def test_unknown_event_id_returns_404(client):
    token = await _token(client, "admin")
    status, _ = await _get_detail(client, _bearer(token), uuid4().hex)
    assert status == 404


# ------------------------------------------------------------------
# Scopes — admin / hr_manager / regular user
# ------------------------------------------------------------------


async def test_admin_reads_the_full_trail_across_actors(client):
    sid = f"audit-{uuid4().hex[:12]}"
    sarah_token = await _token(client, "sarah.chen")
    natalie_token = await _token(client, "natalie.brooks")
    mia_token = await _token(client, "mia.torres")

    await _secure(
        client, sarah_token,
        resource="employee_salary", fields=["employee_id", "base_salary"],
        purpose="hr_review", target="EMP001", session_id=sid,
    )
    await _secure(
        client, natalie_token,
        resource="order_records", fields=["order_id", "status"],
        purpose="order_status", target="ORD0001", session_id=sid,
    )
    await _secure(
        client, mia_token,
        resource="employee_salary", fields=["base_salary"],
        purpose="hr_review", target="EMP002", session_id=sid,
    )

    admin_token = await _token(client, "admin")
    status, body = await _get_events(client, _bearer(admin_token), session_id=sid)
    assert status == 200, body
    items = body["items"]
    assert body["pagination"]["total"] == 3
    # The admin sees events from three different actors.
    assert len({item["actor"]["id"] for item in items}) == 3
    decisions = {item["action"]: item["overall_decision"] for item in items}
    assert decisions["data_access"] == "ALLOW"      # sarah, natalie
    assert decisions["data_denied"] == "BLOCK"      # mia
    for item in items:
        assert item["request_id"]
        assert item["timestamp"]
    # Reason codes and metadata are exposed per the recorded decisions.
    denied = next(i for i in items if i["action"] == "data_denied")
    assert denied["reason_codes"]


async def test_hr_manager_sees_privacy_trail_but_not_auth_or_admin_events(
    client,
):
    sid = f"audit-{uuid4().hex[:12]}"
    natalie_token = await _token(client, "natalie.brooks")
    await _secure(
        client, natalie_token,
        resource="order_records", fields=["order_id", "status"],
        purpose="order_status", target="ORD0001", session_id=sid,
    )

    sarah_token = await _token(client, "sarah.chen")
    status, body = await _get_events(client, _bearer(sarah_token), session_id=sid)
    assert status == 200
    assert body["pagination"]["total"] >= 1
    assert all(item["action"] in PRIVACY_ACTION_VALUES for item in body["items"])

    # An unfiltered page can never contain authentication/admin events.
    status, page = await _get_events(client, _bearer(sarah_token), limit=100)
    assert status == 200
    assert all(item["action"] in PRIVACY_ACTION_VALUES for item in page["items"])

    # Explicitly requesting an out-of-scope action class is rejected.
    status, _ = await _get_events(client, _bearer(sarah_token), action="login")
    assert status == 403
    status, _ = await _get_events(client, _bearer(sarah_token), action="admin_action")
    assert status == 403
    status, _ = await _get_events(client, _bearer(sarah_token), action="seed_data")
    assert status == 403

    # Privacy-trail actions stay queryable.
    status, filtered = await _get_events(
        client, _bearer(sarah_token), session_id=sid, action="data_access"
    )
    assert status == 200
    assert filtered["pagination"]["total"] >= 1


async def test_regular_user_reads_only_their_own_events(client, session):
    sid = f"audit-{uuid4().hex[:12]}"
    sarah_token = await _token(client, "sarah.chen")
    await _secure(
        client, sarah_token,
        resource="employee_salary", fields=["employee_id", "base_salary"],
        purpose="hr_review", target="EMP001", session_id=sid,
    )
    natalie_token = await _token(client, "natalie.brooks")
    await _secure(
        client, natalie_token,
        resource="order_records", fields=["order_id", "status"],
        purpose="order_status", target="ORD0001", session_id=sid,
    )

    natalie_id = await _user_id(session, "natalie.brooks")
    sarah_id = await _user_id(session, "sarah.chen")

    status, body = await _get_events(client, _bearer(natalie_token), session_id=sid)
    assert status == 200
    assert body["pagination"]["total"] == 1
    assert body["items"][0]["actor"]["id"] == natalie_id

    # Asking for someone else's events is denied outright.
    status, _ = await _get_events(
        client, _bearer(natalie_token), requester_id=sarah_id
    )
    assert status == 403

    # Direct fetch of another actor's event is a 404 (existence not revealed).
    sarah_event = await _event_row(session, session_id=sid, actor_id=sarah_id)
    assert sarah_event.actor_id == sarah_id
    status, _ = await _get_detail(client, _bearer(natalie_token), sarah_event.id)
    assert status == 404

    # Her own event is readable, and the detail shows the verified requester.
    natalie_event = await _event_row(session, session_id=sid, actor_id=natalie_id)
    status, detail = await _get_detail(
        client, _bearer(natalie_token), natalie_event.id
    )
    assert status == 200
    assert detail["requester"]["id"] == natalie_id
    assert detail["requester"]["kind"] == "user"
    assert detail["actor"]["kind"] == "user"


# ------------------------------------------------------------------
# Agent / service principals
# ------------------------------------------------------------------


async def test_agent_activity_is_recorded_and_self_scoped(client, session):
    account, api_key = await _create_service_account(
        session,
        scopes=["privacy:request", "order_records:read", "role:support_agent"],
        label="agent",
    )
    sid = f"audit-{uuid4().hex[:12]}"
    try:
        result = await _api_key_secure(
            client, api_key,
            resource="order_records", fields=["order_id", "status"],
            purpose="order_status", target="ORD0005", session_id=sid,
        )
        assert result["overall_decision"] == "ALLOW"
        assert result["audit_id"]

        headers = {"X-API-Key": api_key}
        # The agent reads its own event trail.
        status, body = await _get_events(client, headers, session_id=sid)
        assert status == 200
        assert body["pagination"]["total"] >= 1
        assert all(item["actor"]["id"] == account.id for item in body["items"])
        assert all(item["actor"]["kind"] == "service" for item in body["items"])

        # ... but cannot read other actors' events.
        sarah_id = await _user_id(session, "sarah.chen")
        status, _ = await _get_events(client, headers, requester_id=sarah_id)
        assert status == 403

        # Admin sees the agent event with the verified agent identity.
        admin_token = await _token(client, "admin")
        status, admin_body = await _get_events(
            client, _bearer(admin_token), session_id=sid
        )
        assert status == 200
        agent_item = next(
            item for item in admin_body["items"] if item["actor"]["id"] == account.id
        )
        assert agent_item["actor"]["kind"] == "service"
        assert agent_item["actor"]["name"] == account.name
        assert "order_records:read" in agent_item["actor"]["scopes"]
        assert agent_item["model_invoked"] is False

        status, detail = await _get_detail(
            client, _bearer(admin_token), agent_item["id"]
        )
        assert status == 200
        assert detail["requester"]["kind"] == "service"
        assert detail["requester"]["id"] == account.id
        assert detail["agent"]["id"] == account.id
        assert detail["subject_scope"]
        assert detail["decisions"], "agent decisions must be explainable"
    finally:
        await session.delete(account)
        await session.commit()


async def test_service_account_with_admin_scope_sees_full_trail(client, session):
    sid = f"audit-{uuid4().hex[:12]}"
    natalie_token = await _token(client, "natalie.brooks")
    await _secure(
        client, natalie_token,
        resource="order_records", fields=["order_id", "status"],
        purpose="order_status", target="ORD0001", session_id=sid,
    )

    account, api_key = await _create_service_account(
        session, scopes=["*"], label="ops"
    )
    try:
        status, body = await _get_events(
            client, {"X-API-Key": api_key}, session_id=sid
        )
        assert status == 200
        assert body["pagination"]["total"] >= 1
        # The ops agent sees the human's events, not just its own.
        assert any(item["actor"]["kind"] == "user" for item in body["items"])
    finally:
        await session.delete(account)
        await session.commit()


# ------------------------------------------------------------------
# Filters & pagination
# ------------------------------------------------------------------


async def test_filters_and_pagination(client, monkeypatch):
    _install_llm(monkeypatch)
    sid = f"audit-{uuid4().hex[:12]}"
    sarah_token = await _token(client, "sarah.chen")
    mia_token = await _token(client, "mia.torres")

    allowed = await _secure(
        client, sarah_token,
        resource="employee_salary", fields=["employee_id", "base_salary"],
        purpose="hr_review", target="EMP001", session_id=sid, include_llm=True,
    )
    await _secure(
        client, mia_token,
        resource="employee_salary", fields=["base_salary"],
        purpose="hr_review", target="EMP002", session_id=sid,
    )

    admin = _bearer(await _token(client, "admin"))

    # All events in the test session (sarah: data_access + ai_query +
    # output_inspection; mia: data_denied).
    status, body = await _get_events(client, admin, session_id=sid, limit=100)
    assert status == 200
    total = body["pagination"]["total"]
    assert total == 4

    # Pagination: one item per page, stable totals and has_more flag.
    status, page1 = await _get_events(client, admin, session_id=sid, limit=1)
    assert status == 200
    assert len(page1["items"]) == 1
    assert page1["pagination"]["total"] == total
    assert page1["pagination"]["has_more"] is True

    status, page2 = await _get_events(
        client, admin, session_id=sid, limit=1, offset=1
    )
    assert page2["items"][0]["id"] != page1["items"][0]["id"]

    status, last = await _get_events(
        client, admin, session_id=sid, limit=1, offset=total - 1
    )
    assert last["pagination"]["has_more"] is False

    # Filter by action.
    status, denied = await _get_events(
        client, admin, session_id=sid, action="data_denied"
    )
    assert status == 200
    assert denied["pagination"]["total"] == 1
    item = denied["items"][0]
    assert item["overall_decision"] == "BLOCK"
    assert item["outcome"] == "denied"
    assert item["resource"] == "employee_salary"
    assert item["resource_id"] == "EMP002"

    # Filter by outcome.
    status, failed = await _get_events(client, admin, session_id=sid, outcome="denied")
    assert failed["pagination"]["total"] == 1

    # Filter by requester (admin only).
    sarah_id = await _user_id_http(client, admin, sid)
    assert sarah_id
    status, sarah_events = await _get_events(
        client, admin, session_id=sid, requester_id=sarah_id
    )
    assert sarah_events["pagination"]["total"] == 3
    assert all(i["actor"]["id"] == sarah_id for i in sarah_events["items"])
    # The governed request and the model interaction correlate by request id.
    request_ids = {i["request_id"] for i in sarah_events["items"]}
    assert allowed["request_id"] in request_ids

    # Filter by resource.
    status, by_resource = await _get_events(
        client, admin, session_id=sid, resource="employee_salary"
    )
    assert by_resource["pagination"]["total"] == 4

    # Date range: a window around now includes everything...
    now = datetime.now(timezone.utc)
    status, in_window = await _get_events(
        client, admin,
        session_id=sid,
        start_date=(now - timedelta(minutes=10)).isoformat(),
        end_date=(now + timedelta(minutes=10)).isoformat(),
    )
    assert in_window["pagination"]["total"] == total
    # ... while a future window is empty.
    status, empty = await _get_events(
        client, admin, session_id=sid,
        start_date=(now + timedelta(hours=1)).isoformat(),
    )
    assert empty["pagination"]["total"] == 0
    assert empty["items"] == []


async def _user_id_http(client: AsyncClient, admin_headers: dict, sid: str) -> str:
    """Resolve sarah.chen's actor id via her event in this session."""
    status, body = await _get_events(
        client, admin_headers, session_id=sid, action="data_access"
    )
    assert status == 200
    assert body["items"]
    return body["items"][0]["actor"]["id"]


# ------------------------------------------------------------------
# Validation
# ------------------------------------------------------------------


async def test_query_validation_errors(client):
    admin = _bearer(await _token(client, "admin"))
    for params in (
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"action": "not_an_action"},
        {"requester_id": ""},
    ):
        response = await client.get(EVENTS_URL, params=params, headers=admin)
        assert response.status_code == 422, (params, response.text)

    now = datetime.now(timezone.utc)
    response = await client.get(
        EVENTS_URL,
        params={
            "start_date": (now + timedelta(hours=1)).isoformat(),
            "end_date": now.isoformat(),
        },
        headers=admin,
    )
    assert response.status_code == 422


# ------------------------------------------------------------------
# Recorded content — explainability without raw values
# ------------------------------------------------------------------


async def test_detail_records_decisions_versions_and_model_metadata(
    client, session, monkeypatch
):
    _install_llm(monkeypatch)
    sid = f"audit-{uuid4().hex[:12]}"
    sarah_token = await _token(client, "sarah.chen")
    purpose_detail = "Compensation review Q4 for the employee record"
    result = await _secure(
        client, sarah_token,
        resource="employee_salary", fields=["employee_id", "base_salary"],
        purpose="hr_review", target="EMP001", session_id=sid,
        purpose_detail=purpose_detail, include_llm=True,
    )
    assert result["overall_decision"] == "ALLOW"

    admin = _bearer(await _token(client, "admin"))
    status, body = await _get_events(client, admin, session_id=sid, limit=100)
    assert status == 200

    # The governed request event and the model-stage events are all present.
    by_action = {item["action"]: item for item in body["items"]}
    assert "data_access" in by_action
    assert "ai_query" in by_action
    assert "output_inspection" in by_action

    access = by_action["data_access"]
    assert access["request_id"] == result["request_id"]
    assert access["session_id"] == sid
    assert access["overall_decision"] == "ALLOW"
    assert access["model_requested"] is True
    assert access["model_invoked"] is True
    assert access["guard_outcome"] == "none"
    assert access["policy_versions"], "policy versions must be recorded"
    assert access["sensitivity_categories"]

    status, detail = await _get_detail(client, admin, access["id"])
    assert status == 200
    assert detail["purpose"] == "hr_review"
    assert detail["purpose_recognized"] is True
    assert detail["operation"] == "read"
    assert detail["subject_scope"] == "self"
    assert set(detail["requested_fields"]) == {"employee_id", "base_salary"}
    decision_by_field = {d["field"]: d for d in detail["decisions"]}
    salary = decision_by_field["base_salary"]
    assert salary["action"] == "ALLOW"
    assert salary["reason_code"] == "NORM_MATCHED"
    assert isinstance(salary["policy_version"], int)
    assert salary["policy_id"]
    assert detail["llm"]["invoked"] is True
    assert detail["llm"]["model"] == "recording-1"
    assert detail["guard_triggered"] is False
    assert detail["actor"]["roles"], "verified roles are shown for user actors"

    # The model-stage events correlate back to the same request id.
    assert by_action["ai_query"]["request_id"] == result["request_id"]
    assert by_action["output_inspection"]["outcome"] == "passed"

    # ── No raw values, credentials, or free text in any audit payload ──
    text = json.dumps(body) + json.dumps(detail)
    assert "98000" not in text                  # sarah's raw salary value
    assert "SarahHR@2024!" not in text          # her password
    assert "Admin@2024!" not in text            # the admin password
    assert "eyJ" not in text                    # no JWT material
    assert "Authorization" not in text
    assert purpose_detail not in text           # purpose free text is not stored
    assert "Quarterly compensation summary generated." not in text  # model output


async def test_audit_payloads_never_contain_service_api_keys(client, session):
    account, api_key = await _create_service_account(
        session,
        scopes=["privacy:request", "order_records:read", "role:support_agent"],
        label="secret",
    )
    sid = f"audit-{uuid4().hex[:12]}"
    try:
        await _api_key_secure(
            client, api_key,
            resource="order_records", fields=["order_id", "status"],
            purpose="order_status", target="ORD0005", session_id=sid,
        )
        admin = _bearer(await _token(client, "admin"))
        status, body = await _get_events(client, admin, session_id=sid, limit=100)
        assert status == 200

        text = json.dumps(body)
        assert api_key not in text
        assert account.hashed_key not in text
        assert "hashed_key" not in text
        assert account.name in text  # the safe display name is recorded
    finally:
        await session.delete(account)
        await session.commit()

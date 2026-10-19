"""SDK tests: authentication, results, errors, timeouts, logging, retries.

Prompt 9 (part E) verification: successful and denied requests, timeouts,
invalid responses, and gateway unavailability — all against a simulated
gateway (``httpx.MockTransport``), plus audit-endpoint parsing.
"""

import json
import logging

import httpx
import pytest

from contextshield import (
    AuditEvent,
    AuthenticationError,
    ContextShieldClient,
    ConfigurationError,
    GatewayError,
    GatewayUnavailableError,
    InvalidResponseError,
    NotFoundError,
    PermissionDeniedError,
    RequestBlockedError,
    RequestEscalatedError,
    RequestTimeoutError,
    ValidationError,
)
from contextshield.models import AuditEventPage, SecureRequestResult

BASE = "http://gateway.test"
SECURE_PATH = "/api/v1/privacy/secure-request"
LOGIN_PATH = "/api/v1/auth/login"
AUDIT_PATH = "/api/v1/audit/events"

API_KEY = "csk_test_abc123"  # noqa: S105 — clearly fake test credential
PASSWORD = "Demo-Pass-123!"  # noqa: S105 — clearly fake test credential

SUCCESS_PAYLOAD = {
    "request_id": "1" * 32,
    "overall_decision": "ALLOW",
    "reason_code": "NORM_MATCHED",
    "reason": "Access authorised by policy: employee salary review",
    "fields": {
        "base_salary": {
            "action": "ALLOW",
            "value": 98000.0,
            "reason_code": "NORM_MATCHED",
            "reason": "Access authorised by policy",
            "policy_id": "pol-123",
            "policy_version": 4,
        }
    },
    "records": [{"base_salary": 98000.0}],
    "retrieved": True,
    "llm_response": None,
    "llm": None,
    "guard_triggered": False,
    "mosaic_warning": False,
    "audit_id": "aud-00000000000000000000000000000001",
    "timestamp": "2026-10-19T12:00:00.123456+00:00",
}

BLOCK_PAYLOAD = {
    "request_id": "2" * 32,
    "overall_decision": "BLOCK",
    "reason_code": "INSUFFICIENT_ROLE",
    "reason": "No matching policy grants access",
    "fields": {
        "base_salary": {
            "action": "BLOCK",
            "value": None,
            "reason_code": "INSUFFICIENT_ROLE",
            "reason": "No matching policy grants access",
            "policy_id": None,
            "policy_version": None,
        }
    },
    "records": None,
    "retrieved": False,
    "llm_response": None,
    "llm": None,
    "guard_triggered": False,
    "mosaic_warning": False,
    "audit_id": "aud-00000000000000000000000000000002",
    "timestamp": "2026-10-19T12:00:00.123456+00:00",
}

ESCALATION_PAYLOAD = {
    **BLOCK_PAYLOAD,
    "request_id": "3" * 32,
    "overall_decision": "ESCALATION_NEEDED",
    "fields": {
        "base_salary": {
            "action": "ESCALATE",
            "value": None,
            "reason_code": "REPEATED_ACCESS",
            "reason": "Repeated aggregate access requires review",
        }
    },
}


def _json_response(payload, status=200):
    return httpx.Response(status, json=payload)


def _client(handler, **kwargs):
    transport = httpx.MockTransport(handler)
    kwargs.setdefault("api_key", API_KEY)
    return ContextShieldClient(base_url=BASE, transport=transport, **kwargs)


def _capture(handler):
    """Wrap a handler, capturing every request for assertions."""
    requests: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return handler(request)

    return wrapped, requests


def _request_body(request: httpx.Request) -> dict:
    return json.loads(request.content.decode("utf-8"))


# ------------------------------------------------------------------
# Successful requests
# ------------------------------------------------------------------


def test_secure_request_success_is_typed():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == SECURE_PATH
        body = _request_body(request)
        assert body["resource"] == "employee_salary"
        assert body["data_fields"] == ["base_salary"]
        assert body["purpose"] == "hr_review"
        assert body["target_entity"] == "EMP001"
        assert body["include_llm_response"] is False
        assert "context" not in body
        return _json_response(SUCCESS_PAYLOAD)

    with _client(handler) as client:
        result = client.secure_request(
            resource="employee_salary",
            data_fields=["base_salary"],
            purpose="hr_review",
            target_entity="EMP001",
        )

    assert isinstance(result, SecureRequestResult)
    assert result.allowed and not result.blocked and not result.escalated
    assert result.request_id == "1" * 32
    assert result.audit_id
    assert result.timestamp is not None
    decision = result.field("BASE_SALARY")  # case-insensitive lookup
    assert decision is not None
    assert decision.action == "ALLOW"
    assert decision.granted
    assert decision.value == 98000.0
    assert decision.policy_version == 4
    assert result.granted_values() == {"base_salary": 98000.0}
    assert result.raise_if_blocked() is None  # no-op for allowed requests


def test_api_key_is_sent_in_x_api_key_header():
    captured, requests = _capture(lambda r: _json_response(SUCCESS_PAYLOAD))
    with _client(captured) as client:
        client.secure_request(
            resource="employee_salary", data_fields=["base_salary"], purpose="hr_review"
        )
    assert requests[0].headers["X-API-Key"] == API_KEY
    assert "Authorization" not in requests[0].headers


def test_token_auth_sends_bearer_header():
    captured, requests = _capture(lambda r: _json_response(SUCCESS_PAYLOAD))
    with ContextShieldClient(
        base_url=BASE, token="jwt-token-123", transport=httpx.MockTransport(captured)
    ) as client:
        client.secure_request(
            resource="order_records", data_fields=["status"], purpose="order_status"
        )
    assert requests[0].headers["Authorization"] == "Bearer jwt-token-123"


def test_context_and_session_convenience_kwargs_are_merged():
    captured, requests = _capture(lambda r: _json_response(SUCCESS_PAYLOAD))
    with _client(captured) as client:
        client.secure_request(
            resource="order_records",
            data_fields=["status"],
            purpose="order_status",
            context={"conversation_id": "conv-1", "additional_claims": {"x": 1}},
            session_id="sess-9",
            agent_name="host-agent",
        )
    body = _request_body(requests[0])
    assert body["context"]["session_id"] == "sess-9"
    assert body["context"]["conversation_id"] == "conv-1"
    assert body["context"]["agent_name"] == "host-agent"
    assert body["context"]["additional_claims"] == {"x": 1}


# ------------------------------------------------------------------
# Blocked / escalated requests (normal outcomes, explicit handling)
# ------------------------------------------------------------------


def test_blocked_request_returns_typed_result_and_raises_only_on_request():
    with _client(lambda r: _json_response(BLOCK_PAYLOAD)) as client:
        result = client.secure_request(
            resource="employee_salary",
            data_fields=["base_salary"],
            purpose="hr_review",
            target_entity="EMP002",
        )
        assert result.blocked and not result.allowed
        assert result.records is None
        assert result.retrieved is False
        assert result.field("base_salary").action == "BLOCK"
        assert result.field("base_salary").granted is False
        assert result.granted_values() == {}
        with pytest.raises(RequestBlockedError) as excinfo:
            result.raise_if_blocked()

    assert excinfo.value.request_id == "2" * 32
    assert "INSUFFICIENT_ROLE" in excinfo.value.reason_codes


def test_escalated_request_raises_escalation_error_on_request():
    with _client(lambda r: _json_response(ESCALATION_PAYLOAD)) as client:
        result = client.secure_request(
            resource="employee_salary",
            data_fields=["base_salary"],
            purpose="department_statistics",
            operation="aggregate",
            target_entity="department-Engineering",
        )
    assert result.escalated and not result.allowed and not result.blocked
    with pytest.raises(RequestEscalatedError):
        result.raise_if_blocked()


def test_guard_metadata_is_parsed():
    payload = {
        **SUCCESS_PAYLOAD,
        "llm_response": "S***@example.com",
        "guard_triggered": True,
        "llm": {
            "requested": True,
            "invoked": True,
            "provider": "mock",
            "model": "mock-deterministic",
            "error_code": None,
            "error": None,
            "guard": {
                "triggered": True,
                "action": "redact",
                "reason_code": "SENSITIVE_OUTPUT_REDACTED",
                "findings": [
                    {
                        "category": "email",
                        "rule": "regex.email",
                        "permitted": False,
                        "start": 0,
                        "end": 11,
                        "redacted_as": "S***@example.com",
                    }
                ],
            },
        },
    }
    with _client(lambda r: _json_response(payload)) as client:
        result = client.secure_request(
            resource="customer_records", data_fields=["contact_email"], purpose="customer_service"
        )
    assert result.guard_triggered is True
    assert result.llm is not None and result.llm.invoked is True
    assert result.llm.guard is not None
    assert result.llm.guard.triggered is True
    assert result.llm.guard.findings[0].category == "email"
    assert result.llm.guard.findings[0].permitted is False
    assert result.llm_response == "S***@example.com"


# ------------------------------------------------------------------
# Authentication flows
# ------------------------------------------------------------------


def test_password_login_flow_caches_the_token():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == LOGIN_PATH:
            body = _request_body(request)
            assert body == {"username": "natalie.brooks", "password": PASSWORD}
            return _json_response(
                {"access_token": "tok-1", "token_type": "bearer", "expires_in": 3600}
            )
        if request.url.path == SECURE_PATH:
            assert request.headers["Authorization"] == "Bearer tok-1"
            return _json_response(SUCCESS_PAYLOAD)
        raise AssertionError(f"unexpected path {request.url.path}")

    with ContextShieldClient(
        base_url=BASE,
        username="natalie.brooks",
        password=PASSWORD,
        transport=httpx.MockTransport(handler),
    ) as client:
        client.secure_request(
            resource="order_records", data_fields=["status"], purpose="order_status"
        )
        client.secure_request(
            resource="order_records", data_fields=["order_id"], purpose="order_status"
        )

    # One login for two requests — the token is cached.
    assert calls == [LOGIN_PATH, SECURE_PATH, SECURE_PATH]


def test_password_login_failure_raises_authentication_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "Invalid username or password"})

    with ContextShieldClient(
        base_url=BASE,
        username="natalie.brooks",
        password="wrong-password",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(AuthenticationError):
            client.secure_request(
                resource="order_records", data_fields=["status"], purpose="order_status"
            )


def test_expired_token_triggers_one_relogin_and_retry():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == LOGIN_PATH:
            return _json_response(
                {"access_token": f"tok-{calls.count(LOGIN_PATH)}", "token_type": "bearer"}
            )
        if request.url.path == SECURE_PATH:
            auth = request.headers.get("Authorization")
            if auth == "Bearer tok-1":
                return httpx.Response(401, json={"detail": "Token expired"})
            return _json_response(SUCCESS_PAYLOAD)
        raise AssertionError(f"unexpected path {request.url.path}")

    with ContextShieldClient(
        base_url=BASE,
        username="natalie.brooks",
        password=PASSWORD,
        transport=httpx.MockTransport(handler),
    ) as client:
        result = client.secure_request(
            resource="order_records", data_fields=["status"], purpose="order_status"
        )

    assert result.allowed
    assert calls == [LOGIN_PATH, SECURE_PATH, LOGIN_PATH, SECURE_PATH]


def test_invalid_static_token_raises_authentication_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "Could not validate credentials"})

    with ContextShieldClient(
        base_url=BASE, token="stale", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(AuthenticationError) as excinfo:
            client.secure_request(
                resource="order_records", data_fields=["status"], purpose="order_status"
            )
    assert excinfo.value.status_code == 401


def test_missing_credentials_fail_closed_but_health_works():
    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response({"status": "ok"})

    with ContextShieldClient(
        base_url=BASE, transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(ConfigurationError):
            client.secure_request(
                resource="order_records", data_fields=["status"], purpose="order_status"
            )
        # Public endpoints remain reachable without credentials.
        assert client.health() == {"status": "ok"}


def test_conflicting_credentials_are_rejected():
    with pytest.raises(ConfigurationError):
        ContextShieldClient(base_url=BASE, api_key="k", token="t")
    with pytest.raises(ConfigurationError):
        ContextShieldClient(base_url=BASE, username="u")  # password missing


def test_from_env_reads_configuration_and_kwargs_override(monkeypatch):
    monkeypatch.setenv("CONTEXTSHIELD_BASE_URL", "http://env-gateway.test")
    monkeypatch.setenv("CONTEXTSHIELD_API_KEY", "csk_env_key")

    captured, requests = _capture(lambda r: _json_response(SUCCESS_PAYLOAD))
    with ContextShieldClient.from_env(transport=httpx.MockTransport(captured)) as client:
        assert client.base_url == "http://env-gateway.test"
        client.secure_request(
            resource="order_records", data_fields=["status"], purpose="order_status"
        )
    assert requests[0].headers["X-API-Key"] == "csk_env_key"

    # Explicit keyword arguments take precedence over the environment.
    explicit, requests2 = _capture(lambda r: _json_response(SUCCESS_PAYLOAD))
    with ContextShieldClient.from_env(
        api_key="csk_explicit", transport=httpx.MockTransport(explicit)
    ) as client:
        client.secure_request(
            resource="order_records", data_fields=["status"], purpose="order_status"
        )
    assert requests2[0].headers["X-API-Key"] == "csk_explicit"


def test_api_key_provider_is_called_per_request():
    keys = iter(["csk_rotated_1", "csk_rotated_2"])
    captured, requests = _capture(lambda r: _json_response(SUCCESS_PAYLOAD))
    with ContextShieldClient(
        base_url=BASE,
        api_key_provider=lambda: next(keys),
        transport=httpx.MockTransport(captured),
    ) as client:
        for _ in range(2):
            client.secure_request(
                resource="order_records", data_fields=["status"], purpose="order_status"
            )
    assert requests[0].headers["X-API-Key"] == "csk_rotated_1"
    assert requests[1].headers["X-API-Key"] == "csk_rotated_2"


# ------------------------------------------------------------------
# Error handling
# ------------------------------------------------------------------


def test_403_raises_permission_denied():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403, json={"detail": "You may only read your own audit events"}
        )

    with _client(handler) as client:
        with pytest.raises(PermissionDeniedError) as excinfo:
            client.audit_event("x" * 32)
    assert excinfo.value.status_code == 403
    assert "own audit events" in str(excinfo.value.details)


def test_422_raises_validation_error_with_details():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={"detail": [{"loc": ["body", "purpose"], "msg": "Field required"}]},
        )

    with _client(handler) as client:
        with pytest.raises(ValidationError) as excinfo:
            client.secure_request(
                resource="order_records", data_fields=["status"], purpose="p"
            )
    assert isinstance(excinfo.value.details, list)


def test_404_raises_not_found():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "Audit event not found"})

    with _client(handler) as client:
        with pytest.raises(NotFoundError):
            client.audit_event("f" * 32)


def test_500_raises_gateway_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    with _client(handler) as client:
        with pytest.raises(GatewayError) as excinfo:
            client.secure_request(
                resource="order_records", data_fields=["status"], purpose="order_status"
            )
    assert excinfo.value.status_code == 500


def test_timeout_raises_request_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    with _client(handler) as client:
        with pytest.raises(RequestTimeoutError):
            client.secure_request(
                resource="order_records", data_fields=["status"], purpose="order_status"
            )


def test_gateway_unavailable_raises_transport_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with _client(handler) as client:
        with pytest.raises(GatewayUnavailableError) as excinfo:
            client.secure_request(
                resource="order_records", data_fields=["status"], purpose="order_status"
            )
    assert BASE in str(excinfo.value)


def test_retries_on_transport_error_when_configured():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("flaky network")
        return _json_response(SUCCESS_PAYLOAD)

    with _client(handler, max_retries=1, retry_backoff=0.0) as client:
        result = client.secure_request(
            resource="order_records", data_fields=["status"], purpose="order_status"
        )
    assert result.allowed
    assert calls["n"] == 2


def test_no_retry_by_default():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        raise httpx.ConnectError("connection refused")

    with _client(handler) as client:
        with pytest.raises(GatewayUnavailableError):
            client.secure_request(
                resource="order_records", data_fields=["status"], purpose="order_status"
            )
    assert calls["n"] == 1


def test_invalid_json_raises_invalid_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not json</html>")

    with _client(handler) as client:
        with pytest.raises(InvalidResponseError):
            client.secure_request(
                resource="order_records", data_fields=["status"], purpose="order_status"
            )


def test_response_missing_contract_field_raises_invalid_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response({"overall_decision": "ALLOW"})  # no request_id

    with _client(handler) as client:
        with pytest.raises(InvalidResponseError):
            client.secure_request(
                resource="order_records", data_fields=["status"], purpose="order_status"
            )


def test_local_parameter_validation():
    with _client(lambda r: _json_response(SUCCESS_PAYLOAD)) as client:
        with pytest.raises(ConfigurationError):
            client.secure_request(resource="", data_fields=["status"], purpose="p")
        with pytest.raises(ConfigurationError):
            client.secure_request(resource="order_records", data_fields=[], purpose="p")
        with pytest.raises(ConfigurationError):
            client.secure_request(resource="order_records", data_fields=["s"], purpose="")
        with pytest.raises(ConfigurationError):
            client.audit_event("   ")


# ------------------------------------------------------------------
# Safe logging
# ------------------------------------------------------------------


def test_logging_is_safe_and_never_contains_credentials(caplog):
    caplog.set_level(logging.DEBUG, logger="contextshield")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == LOGIN_PATH:
            return _json_response({"access_token": "tok-secret-value"})
        return _json_response(SUCCESS_PAYLOAD)

    with ContextShieldClient(
        base_url=BASE,
        username="natalie.brooks",
        password=PASSWORD,
        transport=httpx.MockTransport(handler),
    ) as client:
        client.secure_request(
            resource="order_records", data_fields=["status"], purpose="order_status"
        )

    text = caplog.text
    assert SECURE_PATH in text  # requests are observable
    assert PASSWORD not in text
    assert "tok-secret-value" not in text
    assert "Authorization" not in text

    caplog.clear()
    with _client(lambda r: _json_response(SUCCESS_PAYLOAD)) as client:
        client.secure_request(
            resource="order_records", data_fields=["status"], purpose="order_status"
        )
    assert API_KEY not in caplog.text
    assert "X-API-Key" not in caplog.text


# ------------------------------------------------------------------
# Audit endpoints
# ------------------------------------------------------------------


def test_audit_events_query_and_parsing():
    page = {
        "items": [
            {
                "id": "evt-1",
                "timestamp": "2026-10-19T12:00:00+00:00",
                "action": "data_denied",
                "outcome": "denied",
                "actor": {
                    "id": "user-1",
                    "kind": "user",
                    "name": "Mia Torres",
                    "roles": ["marketing_intern"],
                    "scopes": [],
                },
                "request_id": "a" * 32,
                "session_id": "sess-1",
                "resource": "employee_salary",
                "resource_id": "EMP002",
                "overall_decision": "BLOCK",
                "reason_codes": ["INSUFFICIENT_ROLE"],
                "policy_versions": [4],
                "sensitivity_categories": ["financial"],
                "model_requested": False,
                "model_invoked": False,
                "guard_outcome": None,
                "mosaic_warning": False,
            }
        ],
        "pagination": {"total": 1, "limit": 20, "offset": 0, "has_more": False},
    }
    captured, requests = _capture(lambda r: _json_response(page))
    with _client(captured) as client:
        result = client.audit_events(
            action="data_denied", resource="employee_salary", limit=20
        )

    assert isinstance(result, AuditEventPage)
    assert result.pagination.total == 1
    assert len(result.items) == 1
    event = result.items[0]
    assert isinstance(event, AuditEvent)
    assert event.action == "data_denied"
    assert event.actor.kind == "user"
    assert event.actor.roles == ("marketing_intern",)
    assert event.reason_codes == ("INSUFFICIENT_ROLE",)
    assert event.policy_versions == (4,)
    assert event.sensitivity_categories == ("financial",)
    params = requests[0].url.params
    assert params["action"] == "data_denied"
    assert params["resource"] == "employee_salary"


def test_audit_event_detail_parsing():
    detail = {
        "id": "evt-1",
        "timestamp": "2026-10-19T12:00:00+00:00",
        "action": "data_access",
        "outcome": "success",
        "actor": {"id": "svc-1", "kind": "service", "name": "agent-1", "scopes": ["privacy:request"]},
        "request_id": "b" * 32,
        "session_id": None,
        "resource": "order_records",
        "resource_id": "ORD0005",
        "overall_decision": "ALLOW",
        "reason_codes": ["NORM_MATCHED"],
        "policy_versions": [2],
        "sensitivity_categories": ["contact"],
        "model_requested": False,
        "model_invoked": False,
        "guard_outcome": None,
        "mosaic_warning": False,
        "purpose": "order_status",
        "purpose_recognized": True,
        "operation": "read",
        "subject_scope": "record",
        "flags": [],
        "requested_fields": ["order_id", "status"],
        "decisions": [
            {
                "field": "order_id",
                "action": "ALLOW",
                "reason_code": "NORM_MATCHED",
                "policy_id": "pol-9",
                "policy_version": 2,
                "sensitivity": "low",
                "pii_category": None,
            }
        ],
        "transformations": [],
        "llm": None,
        "guard_triggered": False,
        "correlation": {"session_id": "sess-2"},
        "ip_address": "127.0.0.1",
        "requester": {"id": "svc-1", "kind": "service", "name": "agent-1"},
        "agent": {"id": "svc-1", "kind": "service_account", "name": "agent-1"},
    }
    captured, requests = _capture(lambda r: _json_response(detail))
    with _client(captured) as client:
        event = client.audit_event("evt-1")

    assert event.id == "evt-1"
    assert event.actor.kind == "service"
    assert event.decisions[0].field == "order_id"
    assert event.decisions[0].policy_version == 2
    assert event.requester["kind"] == "service"
    assert event.agent["id"] == "svc-1"
    assert event.correlation == {"session_id": "sess-2"}
    assert requests[0].url.path == f"{AUDIT_PATH}/evt-1"


def test_audit_event_missing_id_raises_invalid_response():
    with _client(lambda r: _json_response({"action": "login"})) as client:
        with pytest.raises(InvalidResponseError):
            client.audit_event("whatever")

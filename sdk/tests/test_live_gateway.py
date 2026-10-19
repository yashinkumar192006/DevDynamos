"""Opt-in live integration tests against a running ContextShield gateway.

These tests are skipped unless ``CONTEXTSHIELD_LIVE_GATEWAY_URL`` is set.
Credentials may be provided as ``CONTEXTSHIELD_LIVE_API_KEY`` /
``CONTEXTSHIELD_LIVE_TOKEN`` or ``CONTEXTSHIELD_LIVE_USERNAME`` +
``CONTEXTSHIELD_LIVE_PASSWORD``.

Example (against the seeded demo database, as the self-service customer)::

    $env:CONTEXTSHIELD_LIVE_GATEWAY_URL = "http://localhost:8000"
    $env:CONTEXTSHIELD_LIVE_USERNAME = "natalie.brooks"
    $env:CONTEXTSHIELD_LIVE_PASSWORD = "<seeded demo password>"
    pytest tests/test_live_gateway.py -v

The default probe reads Natalie Brooks's own order (ALLOW with the seed
data); override with ``CONTEXTSHIELD_LIVE_RESOURCE`` / ``_FIELDS`` /
``_PURPOSE`` / ``_TARGET`` to exercise other flows.
"""

import os

import pytest

from contextshield import ContextShieldClient

pytestmark = pytest.mark.skipif(
    not os.environ.get("CONTEXTSHIELD_LIVE_GATEWAY_URL"),
    reason="set CONTEXTSHIELD_LIVE_GATEWAY_URL to run live gateway tests",
)

VALID_DECISIONS = {"ALLOW", "PARTIAL_ALLOW", "BLOCK", "ESCALATION_NEEDED"}


def _client() -> ContextShieldClient:
    base_url = os.environ["CONTEXTSHIELD_LIVE_GATEWAY_URL"]
    kwargs: dict = {}
    if os.environ.get("CONTEXTSHIELD_LIVE_API_KEY"):
        kwargs["api_key"] = os.environ["CONTEXTSHIELD_LIVE_API_KEY"]
    elif os.environ.get("CONTEXTSHIELD_LIVE_TOKEN"):
        kwargs["token"] = os.environ["CONTEXTSHIELD_LIVE_TOKEN"]
    else:
        username = os.environ.get("CONTEXTSHIELD_LIVE_USERNAME")
        password = os.environ.get("CONTEXTSHIELD_LIVE_PASSWORD")
        if not (username and password):
            pytest.skip("live credentials not configured")
        kwargs.update(username=username, password=password)
    return ContextShieldClient(base_url, timeout=15.0, **kwargs)


def test_live_health():
    with _client() as client:
        assert client.health().get("status") == "ok"


def test_live_secure_request_returns_typed_result():
    with _client() as client:
        result = client.secure_request(
            resource=os.environ.get("CONTEXTSHIELD_LIVE_RESOURCE", "order_records"),
            data_fields=os.environ.get(
                "CONTEXTSHIELD_LIVE_FIELDS", "order_id,status"
            ).split(","),
            purpose=os.environ.get("CONTEXTSHIELD_LIVE_PURPOSE", "order_status"),
            target_entity=os.environ.get("CONTEXTSHIELD_LIVE_TARGET", "ORD0001"),
        )
    assert result.request_id
    assert result.overall_decision in VALID_DECISIONS
    if result.allowed:
        # Approved results carry per-field decisions and an audit reference.
        assert result.fields
        assert result.audit_id

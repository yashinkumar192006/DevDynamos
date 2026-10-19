# ContextShield Python SDK

A **native convenience layer** over the ContextShield HTTP gateway. Every SDK
call performs ordinary HTTP requests to the same endpoints any other language
or agent framework can integrate with directly.

> **The SDK does not protect an agent by itself.** Protection applies when the
> agent's *protected data retrieval* and *model invocation* paths actually go
> through the gateway. See [`docs/integration-guide.md`](../docs/integration-guide.md)
> for how to wrap or replace those paths.

## Install (development)

From the repository root:

```powershell
pip install -e sdk
```

Distribution via a package registry is prepared (`pyproject.toml`, typed
package with `py.typed`) but not yet published.

## Quick start

Credentials come from the environment — **never hardcode them**:

```python
from contextshield import ContextShieldClient

client = ContextShieldClient.from_env()  # CONTEXTSHIELD_API_KEY / _TOKEN / _USERNAME+_PASSWORD

result = client.secure_request(
    resource="order_records",
    data_fields=["order_id", "status"],
    purpose="order_status",
    target_entity="ORD0001",
)

if result.blocked:
    print("Nothing disclosed:", [d.reason_code for d in result.fields.values()])
else:
    print(result.granted_values())   # already transformed / authorized values
```

Environment variables:

| Variable                     | Purpose                                    |
|------------------------------|--------------------------------------------|
| `CONTEXTSHIELD_BASE_URL`     | Gateway URL (default `http://localhost:8000`) |
| `CONTEXTSHIELD_API_KEY`      | Service-account API key (`X-API-Key`)      |
| `CONTEXTSHIELD_TOKEN`        | Pre-issued JWT access token                |
| `CONTEXTSHIELD_USERNAME` + `CONTEXTSHIELD_PASSWORD` | Login flow (JWT obtained and refreshed lazily) |

## Authentication modes

```python
ContextShieldClient(base_url, api_key="csk_...")            # agent/service identity
ContextShieldClient(base_url, token="eyJ...")               # pre-issued JWT
ContextShieldClient(base_url, username="...", password="...")  # login flow
ContextShieldClient(base_url, token_provider=my_rotation_fn)    # credential provider
ContextShieldClient(base_url, api_key_provider=read_from_secret_manager)
```

Exactly one credential form may be configured; conflicting configuration
raises `ConfigurationError`. Anonymous clients can call `health()` only —
authenticated calls fail closed with `ConfigurationError`.

## Handling decisions

`BLOCK` and `ESCALATION_NEEDED` are **normal outcomes**, returned as typed
results — they never raise:

```python
result = client.secure_request(...)

result.overall_decision   # "ALLOW" | "PARTIAL_ALLOW" | "BLOCK" | "ESCALATION_NEEDED"
result.allowed            # bool
result.blocked            # bool
result.escalated          # bool
result.fields             # dict[str, FieldDecision]  (action, value, reason_code, policy_id, …)
result.records            # tuple of approved rows, or None
result.granted_values()   # field -> value for every granted field
result.audit_id           # audit-trail reference on the gateway

result.raise_if_blocked() # opt-in: raises RequestBlockedError / RequestEscalatedError
```

## Errors

All errors derive from `ContextShieldError`:

| Exception                 | Meaning                                            |
|---------------------------|----------------------------------------------------|
| `ConfigurationError`      | Client used without required configuration         |
| `AuthenticationError`     | Gateway rejected the credential (401)              |
| `PermissionDeniedError`   | Verified identity not permitted (403)              |
| `ValidationError`         | Request shape rejected (400/422); `.details`       |
| `NotFoundError`           | Missing or out-of-scope resource (404)             |
| `GatewayError`            | 5xx / unexpected status; `.status_code`            |
| `GatewayUnavailableError` | Gateway unreachable (connect/DNS/TLS)              |
| `RequestTimeoutError`     | Request exceeded the configured timeout            |
| `InvalidResponseError`    | Response was not valid JSON or off-contract        |

## Audit queries

```python
page = client.audit_events(action="data_denied", limit=20)
for event in page.items:
    print(event.actor.kind, event.action, event.overall_decision, event.reason_codes)

detail = client.audit_event(page.items[0].id)   # decisions, policy versions, model metadata
```

Visibility is enforced server-side: admins see the full trail, compliance
roles the privacy trail, everyone else only their own events.

## Timeouts, retries, logging

```python
client = ContextShieldClient(base_url, api_key=..., timeout=5.0, max_retries=1)
```

* `timeout` accepts seconds or an `httpx.Timeout`.
* `max_retries` applies to **transport errors only** (connection/timeout) and
  is `0` by default. Retried requests may appear as duplicate attempts in the
  gateway audit trail.
* Logging (logger name `contextshield`) records method, path, status,
  duration and `request_id` — never credentials, headers, or bodies.

## Tests

```powershell
cd sdk
..\backend\.venv\Scripts\python.exe -m pytest tests -q
```

The suite is self-contained (simulated gateway via `httpx.MockTransport`).
Opt-in live tests run against a real gateway when
`CONTEXTSHIELD_LIVE_GATEWAY_URL` (+ live credentials) is set — see
`tests/test_live_gateway.py`.

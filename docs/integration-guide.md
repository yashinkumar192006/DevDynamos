# ContextShield — Integration Guide

> **Version:** 2.0.0
> **Status:** Matches the implemented gateway (Prompts 1–9) — verified against
> the API, the Python SDK (`sdk/`), and the runnable examples (`examples/`).
> **Last Updated:** 2026-10-19

---

## 1. Overview

ContextShield sits between your AI agent and the data it uses. The agent does
**not** read protected data or call a model on protected data directly;
instead it asks the gateway, which verifies identity, evaluates policy, applies
minimum-disclosure transforms, optionally runs an inspected model stage, and
records an audit event for every decision.

There are two integration methods, and they are the same contract:

1. **Python SDK** (`sdk/`, package `contextshield`) — a thin, typed HTTP client
   for Python agents.
2. **HTTP REST API** — language-agnostic JSON endpoints (works with Node.js,
   Go, Java, .NET, curl, anything).

> **The SDK is convenience, not protection.** Protection applies exactly to
> the code paths that go through the gateway. If your agent can still query
> the database directly, or send raw data to a model, nothing is enforced.
> See §7 “Honest security boundary”.

Everything in this guide is backed by runnable code:

| Integration pattern | Example |
|---|---|
| A simple existing Python agent | [`examples/simple_agent.py`](../examples/simple_agent.py) |
| An agent with a tool / data connector | [`examples/tool_connector_agent.py`](../examples/tool_connector_agent.py) |
| Gateway pre-flight before your own LLM | [`examples/llm_precheck_agent.py`](../examples/llm_precheck_agent.py) |
| Generic HTTP (non-Python agents) | [`examples/http/README.md`](../examples/http/README.md) |
| End-to-end: BLOCK handling + approved result | [`examples/demo_end_to_end.py`](../examples/demo_end_to_end.py) |

---

## 2. Prerequisites

1. **Gateway running** against the migrated + seeded demo database:

   ```powershell
   cd backend
   .venv\Scripts\python.exe -m alembic upgrade head
   .venv\Scripts\python.exe -m app.seed
   .venv\Scripts\uvicorn.exe app.main:app --port 8000
   ```

2. **A credential.** Two kinds exist:

   * **Human users** — `POST /api/v1/auth/login` with username/password
     returns a short-lived JWT. Use a seeded demo user
     (`backend/app/seed.py`: `natalie.brooks`, `sarah.chen`, `eve.johnson`,
     `mia.torres`, `admin`) or a real account.
   * **Agents / services** — create a service account once; the API key is
     printed exactly once and only its hash is stored:

     ```powershell
     cd backend
     .venv\Scripts\python.exe -m app.create_service_account --name support-copilot `
         --scopes privacy:request,customer_records:read
     ```

     Present it as `X-API-Key: <key>`. Scopes gate what the agent may do
     (`privacy:request`, `resource:action`, `role:<name>`, or `*`).

> **Never trust client-supplied identity or purpose.** The gateway resolves
> identity from the credential and re-reads roles/scopes from the database on
> every request. The `purpose` field is an *input to policy evaluation*, not
> proof — free text can never grant access.

---

## 3. The HTTP contract

Base URL: `http://localhost:8000` (configurable). All payloads are JSON.

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/v1/auth/login` | — | Exchange username/password for a JWT |
| `POST /api/v1/privacy/secure-request` | Bearer **or** `X-API-Key` | The governed pipeline (the core call) |
| `GET /api/v1/audit/events` | Bearer **or** `X-API-Key` | Query the audit trail (visibility-scoped) |
| `GET /api/v1/audit/events/{id}` | Bearer **or** `X-API-Key` | Full explainability for one event |
| `GET /api/v1/health`, `/health` | — | Liveness |

### 3.1 Secure request

```http
POST /api/v1/privacy/secure-request
Authorization: Bearer <token>          # or: X-API-Key: <agent key>
Content-Type: application/json

{
  "resource": "order_records",
  "data_fields": ["order_id", "status"],
  "purpose": "order_status",
  "operation": "read",
  "target_entity": "ORD0001",
  "purpose_detail": null,
  "include_llm_response": false,
  "context": {"session_id": "run-42", "agent_name": "my-agent"}
}
```

* `resource` — catalog resource (`employee_salary`, `order_records`,
  `customer_records`, …); never a SQL table or free-form query.
* `data_fields` — requested fields; at least one.
* `purpose` — required policy input (`hr_review`, `order_status`,
  `customer_service`, `self_service`, …).
* `operation` — `read` or `aggregate`.
* `target_entity` — the record/scope being addressed (e.g. `EMP001`,
  `CUS003`, `department-Engineering`); omit only for un-scoped requests.
* `context` — correlation metadata only (session/conversation/task ids, agent
  name). Treated as untrusted labels; never identity or authorization.
* `include_llm_response` — request a governed model stage (the default
  provider is a deterministic **mock**, so nothing leaves the deployment).

Response:

```jsonc
{
  "request_id": "8f1e…",                 // correlation id (also on every audit event)
  "overall_decision": "ALLOW",           // ALLOW | PARTIAL_ALLOW | BLOCK | ESCALATION_NEEDED
  "reason_code": "NORM_MATCHED",
  "reason": "Access authorised by policy: …",
  "fields": {
    "order_id":  {"action": "ALLOW", "value": "ORD0001", "reason_code": "NORM_MATCHED",
                  "policy_id": "…", "policy_version": 3},
    "status":    {"action": "ALLOW", "value": "delivered", "reason_code": "NORM_MATCHED"}
  },
  "records": [ {"order_id": "ORD0001", "status": "delivered"} ],  // approved rows only; null when blocked
  "retrieved": true,
  "llm_response": null,                  // present only when permitted + requested
  "llm": null,                           // model-stage metadata (provider/model/guard)
  "guard_triggered": false,              // output privacy guard outcome
  "mosaic_warning": false,               // cumulative-disclosure risk flag
  "audit_id": "9a0d…",                   // the recorded audit event for this decision
  "timestamp": "2026-10-19T11:30:00.123456+00:00"
}
```

Field actions: `ALLOW`, `MASK`, `TOKENIZE`, `GENERALIZE`, `AGGREGATE`, `BLOCK`,
`ESCALATE`. Values are **already transformed** when released — a `MASK` field
carries the masked value, an `AGGREGATE` field carries statistics only.

### 3.2 Decision semantics

| `overall_decision` | Meaning | What the caller must do |
|---|---|---|
| `ALLOW` | Everything requested was granted | Use `fields` / `records` as-is |
| `PARTIAL_ALLOW` | Some fields were denied or transformed | Use per-field values; never backfill from the source |
| `BLOCK` | Nothing was disclosed; no model ran | Surface the refusal; do not retry with tweaked fields |
| `ESCALATION_NEEDED` | A review is required before any disclosure | Hand off to a human process; disclose nothing |

`BLOCK` and `ESCALATION_NEEDED` are **HTTP 200 responses** — normal outcomes,
not transport errors. Only malformed requests (`400`/`422`), bad credentials
(`401`), insufficiently privileged identities (`403`), and server failures
(`5xx`) are HTTP errors. On `5xx`, **fail closed**: never fall back to direct
data access.

### 3.3 Errors

| Status | Meaning |
|---|---|
| 400 / 422 | Request shape rejected (unknown resource, empty fields, bad purpose shape) |
| 401 | Missing/invalid credential |
| 403 | Verified identity not permitted (incl. out-of-scope audit filters) |
| 404 | Missing or out-of-scope resource (existence is not disclosed) |
| 5xx | Gateway/backend failure — fail closed |

### 3.4 Audit & explainability

`GET /api/v1/audit/events` returns a paginated, filtered view
(`action`, `requester_id`, `resource`, `outcome`, `session_id`,
`start_date`, `end_date`, `limit` 1–100, `offset`) of the recorded trail.
`GET /api/v1/audit/events/{id}` returns full detail: per-field decisions with
reason codes and policy versions, transformation types, purpose/operation,
correlation ids, verified requester + agent snapshots, and model-stage
metadata (`model_invoked`, guard action).

Visibility is enforced server-side from the verified principal:

* `admin` (or a service account with `*` / `role:admin`) → full trail;
* `hr_manager` / `executive` → privacy-pipeline events, all actors;
* everyone else (including agents) → **own events only**.

Events are safe by construction: no passwords, API keys, JWTs, raw protected
values, purpose free text, prompts, or model outputs are ever stored.
Full contract: [`docs/api-design.md`](api-design.md) §4.8–4.9.

---

## 4. Python SDK

### 4.1 Install

```powershell
pip install -e sdk        # from the repository root (editable, development)
# or build/install a wheel from the same directory:
pip install sdk
```

Package: `contextshield` **version 0.1.0** (Alpha). The package is typed
(`py.typed`), depends only on `httpx`, requires Python ≥ 3.10, and ships no
credentials. It is prepared for a package registry but **not yet published**;
install from the repository. Verified in a clean virtual environment: install
exit 0, `pip check` clean, `contextshield.__version__ == "0.1.0"`, `py.typed`
present, and a live request against the running gateway returned a typed
`ALLOW` result with request/audit ids.

### 4.2 Configure

Credentials come from the environment — never hardcode them:

| Variable | Purpose |
|---|---|
| `CONTEXTSHIELD_BASE_URL` | Gateway URL (default `http://localhost:8000`) |
| `CONTEXTSHIELD_API_KEY` | Agent/service key (`X-API-Key`) |
| `CONTEXTSHIELD_TOKEN` | Pre-issued JWT |
| `CONTEXTSHIELD_USERNAME` + `CONTEXTSHIELD_PASSWORD` | Human login flow |

```python
from contextshield import ContextShieldClient

client = ContextShieldClient.from_env()

# Or configure explicitly (e.g. from a secret manager):
client = ContextShieldClient(
    base_url="https://shield.internal",
    api_key_provider=lambda: read_secret("contextshield/agent-key"),
    timeout=5.0,
    max_retries=1,
)
```

Exactly one credential form may be set; ambiguous configuration raises
`ConfigurationError`. An anonymous client can call `health()` only —
authenticated calls fail closed.

### 4.3 Submit a governed request

```python
result = client.secure_request(
    resource="customer_records",
    data_fields=["contact_email", "contact_phone"],
    purpose="customer_service",
    target_entity="CUS003",
    context={"session_id": "ticket-4521"},   # correlation only
    include_llm_response=False,
)
```

### 4.4 Handle the decision

```python
if result.blocked:          # .allowed / .blocked / .escalated
    reasons = sorted({d.reason_code for d in result.fields.values() if d.reason_code})
    reply = f"Not disclosed ({', '.join(reasons)})"
elif result.escalated:
    reply = "A review is required before this can be answered."
else:
    approved = result.granted_values()      # only granted, already-transformed values
    reply = f"Contact: {approved.get('contact_email')}"

    # Optionally, exception-style handling:
    # result.raise_if_blocked()  → RequestBlockedError / RequestEscalatedError
```

* `result.fields` — `dict[str, FieldDecision]` (`action`, `value`,
  `reason_code`, `policy_id`, `policy_version`).
* `result.records` — approved rows or `None`; `result.audit_id` — the trail
  reference; `result.llm` / `result.llm_response` — governed model stage when
  requested and permitted.
* `FieldDecision.granted` mirrors the backend semantics; `value` is the
  transformed value.

### 4.5 Errors

All SDK errors derive from `ContextShieldError`:

| Exception | Meaning |
|---|---|
| `ConfigurationError` | Missing/ambiguous client configuration |
| `AuthenticationError` | 401 |
| `PermissionDeniedError` | 403 |
| `ValidationError` | 400/422 (structured `.details`) |
| `NotFoundError` | 404 (missing **or** out of scope) |
| `GatewayError` | 5xx / unexpected status |
| `GatewayUnavailableError` | Connection/DNS/TLS failure |
| `RequestTimeoutError` | Timeout exceeded |
| `InvalidResponseError` | Off-contract or non-JSON response |

Treat every transport-level failure as **fail closed**: surface an error, do
not silently serve raw data instead.

### 4.6 Audit queries

```python
page = client.audit_events(action="data_denied", limit=20)
for event in page.items:
    print(event.actor.kind, event.action, event.overall_decision, event.reason_codes)

detail = client.audit_event(page.items[0].id)
print(detail.decisions, detail.llm)
```

### 4.7 Timeouts, retries, logging

* `timeout` — seconds or `httpx.Timeout` (default 10s).
* `max_retries` — transport errors only, default `0`. Retried requests can
  appear as duplicate attempts in the audit trail.
* Logging uses the `contextshield` logger: method, path, status, duration,
  `request_id` — **never** credentials, headers, or bodies.

---

## 5. Integration patterns

### 5.1 A simple existing Python agent

Keep the agent's structure; replace its one protected lookup method with a
secure request. The agent's only path to protected data becomes the gateway.

→ Full code: [`examples/simple_agent.py`](../examples/simple_agent.py)

### 5.2 An agent with a tool / data connector

Wrap the tool. Every tool call carries an explicit purpose and goes through
`secure_request`; the tool hands the host agent only the transformed values
released by the gateway (masking, generalization, aggregation apply
server-side). A tool call without a purpose is rejected locally, fail-closed.

→ Full code: [`examples/tool_connector_agent.py`](../examples/tool_connector_agent.py)

### 5.3 Gateway pre-flight before your own LLM

Run the secure request **first**, then build the model prompt **only** from
the approved values. If the decision is `BLOCK` — including prompt-injection
attempts smuggled through free-text fields — the model is never called. (If
you prefer the gateway to run the model stage itself, set
`include_llm_response=True`; the model sees only authorized,
post-transformation context, and its output is inspected before release.)

→ Full code: [`examples/llm_precheck_agent.py`](../examples/llm_precheck_agent.py)

### 5.4 Non-Python agents (generic HTTP)

Call the API directly with your platform's HTTP client — the contract in §3 is
everything you need. A minimal Node.js variant:

```javascript
const response = await fetch(`${BASE}/api/v1/privacy/secure-request`, {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-API-Key": process.env.CONTEXTSHIELD_API_KEY },
  body: JSON.stringify({
    resource: "order_records",
    data_fields: ["order_id", "status"],
    purpose: "order_status",
    target_entity: "ORD0001",
  }),
});
const result = await response.json();
if (result.overall_decision === "ALLOW") { /* use result.fields */ }
else { /* surface result.overall_decision — do not retry around it */ }
```

→ curl / JavaScript / PowerShell walkthroughs:
[`examples/http/README.md`](../examples/http/README.md)

### 5.5 End-to-end demos

[`examples/demo_end_to_end.py`](../examples/demo_end_to_end.py) runs the full
story on the seeded synthetic data: a customer's request for **another**
customer's data returns `BLOCK` (no data, no model call), the same customer's
request for their **own** order returns `ALLOW` (with a mock-LLM summary),
and the audit trail for the session is printed at the end.

[`examples/agent_full_flow.py`](../examples/agent_full_flow.py) walks the
complete governed sequence for one agent: intent → SDK → verified identity and
policy → authorized retrieval → transformations → approved model context →
mock LLM → output guard → approved answer, followed by a blocked request that
contains a prompt-injection string and a gateway-unreachable check that fails
closed (no direct-data fallback).

[`examples/devhost_demo.py`](../examples/devhost_demo.py) is the ten-scenario
DEVHOST demonstration against the real backend, printing expected vs actual for
each scenario. Runbook and recorded results:
[`docs/devhost-demo.md`](devhost-demo.md).

---

## 6. Verification

| Check | Command | Last result |
|---|---|---|
| Backend suite (incl. audit API, pipeline, auth, security properties, hardening) | `cd backend && python -m pytest tests -q` | 335 passed, 0 failed, 0 skipped |
| SDK suite (self-contained; simulated gateway) | `cd sdk && python -m pytest tests -q` | 32 passed, 2 skipped (live tests opt-in) |
| SDK install in a clean environment | `python -m venv <tmp> && <tmp>\Scripts\python -m pip install sdk` | install exit 0, `pip check` clean, live request verified |
| Live gateway check (opt-in) | set `CONTEXTSHIELD_LIVE_GATEWAY_URL` (+ credentials) and run `python -m pytest sdk/tests/test_live_gateway.py -v` | 2 passed (seeded customer account) |
| Runnable examples | `python examples/agent_full_flow.py`, `python examples/devhost_demo.py` (gateway + seeded DB) | all scenarios PASS |
| Frontend quality gates | `cd frontend && npm run lint && npm run type-check && npm run build` | exit 0, production build succeeds |
| Frontend E2E (real backend) | `cd frontend && npm run e2e` | 12 passed |
| Docker images + stack | `docker compose build` then `docker compose up -d db backend frontend` | build PASS; fresh-volume migrations + idempotent seed + health PASS |

CI (`.github/workflows/ci.yml`) runs the backend suite, SDK suite, frontend
lint/type-check/build, and a `frontend-e2e` job on GitHub infrastructure. The
frontend-e2e job has not yet executed on GitHub at the time of writing (no push
was made for Prompts 10–12); the same suite passed locally against the real
backend.

---

## 7. Honest security boundary

* **Installing the SDK protects nothing by itself.** The gateway enforces
  policy *for requests it receives*. Your agent must be changed so its
  protected retrieval and model-invocation paths actually call the gateway.
* **Remove or restrict the direct paths.** If the agent keeps a database
  credential or an unfiltered provider client, that path bypasses
  ContextShield entirely. In production, scope the agent's data credentials
  to the gateway (or remove them), and front the model provider with the
  gateway's adapter where possible.
* **Fail closed.** On gateway errors/timeouts/5xx, surface an error or a safe
  refusal. Never "fall back" to querying the source database or calling the
  model with raw data.
* **`BLOCK` is not an obstacle to engineer around.** It is the enforced
  decision; retrying with rephrased fields or different purposes to fish for
  data defeats the system (and is itself visible in the audit trail).
* **Purpose is context, not permission.** The gateway never accepts identity
  or purpose claims from the client as proof; it re-derives both
  server-side.
* **Audit is record, not surveillance.** Events store identifiers, reason
  codes, transformation *types*, and model metadata — never raw values,
  credentials, or complete prompts/outputs, and reads are visibility-scoped.

---

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `ConfigurationError: No credentials configured` | Set one of the `CONTEXTSHIELD_*` credential forms (§4.2) |
| `GatewayUnavailableError` | Gateway not running, or wrong `CONTEXTSHIELD_BASE_URL` |
| `401` on every call | Wrong password / expired token / disabled or expired API key |
| `403` from audit endpoints | Your identity is not scoped for that query (§3.4) |
| `INVALID_PURPOSE` reason code | The `purpose` value is not a recognized policy input — check spelled purposes in `docs/policy-engine.md` |
| `NO_MATCHING_NORM` / `INSUFFICIENT_ROLE` | Correct, enforced denial — adjust who asks, for what, not the request string |
| Empty `records` with `PARTIAL_ALLOW` | All requested fields were transformed into `fields`; use per-field values |
| Audit list is empty for an agent | Agents see only their own events — expected (§3.4) |

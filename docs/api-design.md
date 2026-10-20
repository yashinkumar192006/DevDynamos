# ContextShield — API Design & Contract

> **Version:** 1.0.0  
> **Status:** Implemented — reconciled with the running FastAPI application  
> **Last Updated:** 2026-10-20

---

## 1. API Overview

| Property          | Value                                       |
|-------------------|---------------------------------------------|
| **Base URL**      | `http://localhost:8000`                      |
| **API Prefix**    | `/api/v1`                                    |
| **Format**        | JSON (application/json)                      |
| **Auth**          | JWT Bearer token (HS256)                     |
| **Docs**          | Swagger UI at `/docs`, ReDoc at `/redoc`     |
| **OpenAPI**       | `/openapi.json`                              |
| **Versioning**    | URL path (`/api/v1/`)                        |

### Using Swagger UI

1. Start the backend and open `http://localhost:8000/docs`. The schema is served
   from `/openapi.json` (no authentication to read it).
2. Call `POST /api/v1/auth/login` with a seeded demo account, or create a
   service account with `python -m app.create_service_account` (API-key auth).
3. Click **Authorize**:
   * **BearerAuth** → paste the `access_token` returned by login (without the
     `Bearer ` prefix).
   * **ApiKeyAuth** → paste a service-account key for `X-API-Key`.
4. Use **Try it out** on `POST /api/v1/privacy/secure-request` to submit the
   core request body. `ALLOW`/`BLOCK`/`ESCALATION_NEEDED` are normal HTTP 200
   decisions; validation and authentication use the error envelope below.
5. `GET /api/v1/system/status` confirms database/provider/classifier health.
6. Generated OpenAPI JSON is the source of truth for paths; if this document
   and the running schema disagree, treat the schema as authoritative and fix
   the document.

Verified in this environment: `/docs` → HTTP 200 (Swagger UI), `/openapi.json`
→ HTTP 200, and the schema lists `/health`, `/api/v1/health`, auth
login/logout/me/whoami, secure-request, policies, audit list/detail,
dashboard, data assets, system status, and admin users.

---

## 2. Authentication

### 2.1 Obtaining a Token

All protected endpoints require a valid JWT in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

Tokens are obtained via `POST /api/v1/auth/login` and expire after 30 minutes (configurable).

### 2.2 Token Refresh

v1 does not implement refresh tokens. Users must re-authenticate when the token expires.

### 2.3 Required Permissions by Endpoint

| Endpoint                              | Auth Required | Minimum Role      |
|---------------------------------------|---------------|--------------------|
| `GET /health`                         | No            | —                  |
| `GET /api/v1/health`                  | No            | —                  |
| `GET /api/v1/system/status`           | Yes           | Any authenticated  |
| `POST /api/v1/auth/login`             | No            | —                  |
| `POST /api/v1/auth/logout`            | Yes           | Any authenticated  |
| `GET /api/v1/auth/me`                 | Yes           | Any authenticated  |
| `GET /api/v1/auth/whoami`             | Yes           | Any authenticated  |
| `GET /api/v1/admin/users`             | Yes           | Administrator      |
| `POST /api/v1/privacy/secure-request` | Yes           | Any authenticated  |
| `GET /api/v1/policies`                | Yes           | Any authenticated (inactive history: administrators only) |
| `GET /api/v1/audit/events`            | Yes           | Any authenticated (visibility-scoped — see §4.8) |
| `GET /api/v1/audit/events/{id}`       | Yes           | Any authenticated (visibility-scoped — see §4.9) |
| `GET /api/v1/dashboard/overview`      | Yes           | Any authenticated  |
| `GET /api/v1/data/assets`             | Yes           | Any authenticated  |

---

## 3. Common Models

### 3.1 Error Response

Application errors raised by the gateway follow this format:

```json
{
  "error": {
    "type": "AuthorizationError",
    "detail": "Not authorized"
  }
}
```

The correlation id is **not** in the body: every response carries a
server-generated `X-Request-ID` header (32 lowercase hex characters), and
that same id appears in server logs for the failing request. The id is
never accepted from the client.

Two framework-level shapes also occur (both still traceable via
`X-Request-ID`):

* request-validation failures (`422`) use FastAPI's standard
  `{"detail": [ { "loc": …, "msg": …, "type": … } ]}` shape;
* unknown routes return `{"detail": "Not Found"}`.

Internal errors (`500`) return a generic body — `{"error": {"type":
"InternalServerError", "detail": "Internal server error"}}` — and never
include exception messages, table names, or stack traces.

### 3.2 Standard Error Codes

| HTTP Status | `error.type` / shape        | Description                                 |
|-------------|---------------------------|---------------------------------------------|
| 401         | `AuthenticationError`     | Missing, invalid, or expired credentials (`WWW-Authenticate: Bearer`) |
| 403         | `AuthorizationError`      | Verified identity without the required role/permission |
| 404         | `{"detail": "Not Found"}` or `error.type` = `HTTPException` | Resource does not exist or is outside your visibility scope |
| 422         | FastAPI `detail` list     | Request body failed schema validation       |
| 429         | `RateLimitError`          | Too many failed sign-in attempts; `Retry-After` header (seconds) |
| 500         | `InternalServerError`     | Unhandled server-side error (generic body; details go to the server log only) |

Route-level 405s (method not allowed — e.g. writing to the audit trail)
use the framework's standard shape.

### 3.3 Pagination

Endpoints returning lists support cursor-based pagination:

```json
{
  "items": [...],
  "pagination": {
    "total": 142,
    "limit": 20,
    "offset": 0,
    "has_more": true
  }
}
```

Query parameters: `?limit=20&offset=0`

---

## 4. Endpoint Specifications

---

### 4.1 `GET /health`

**Purpose:** Root-level health check. No authentication required.

**Response (200):**
```json
{
  "status": "ok"
}
```

---

### 4.2 `GET /api/v1/health`

**Purpose:** API-level health check. No authentication required.

**Response (200):**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

---

### 4.3 `GET /api/v1/system/status`

**Purpose:** Detailed system status including database connectivity, service health, and configuration. Requires authentication.

**Headers:** `Authorization: Bearer <token>`

**Response (200):**
```json
{
  "status": "ok",
  "version": "0.1.0",
  "environment": "development",
  "services": {
    "database": { "status": "connected", "latency_ms": 2 },
    "classifier": { "status": "ready", "model": "en_core_web_sm" },
    "policy_engine": { "status": "ready", "active_policies": 8 }
  },
  "uptime_seconds": 3600,
  "timestamp": "2026-10-18T11:30:00Z"
}
```

---

### 4.4 `POST /api/v1/auth/login`

**Purpose:** Authenticate a user and receive a JWT access token.

**Request Body:**
```json
{
  "username": "sarah.chen",
  "password": "********"
}
```

**Schema:**
| Field      | Type   | Required | Validation                |
|------------|--------|----------|---------------------------|
| `username` | string | Yes      | 1–100 characters           |
| `password` | string | Yes      | 1–256 characters           |

Extra fields are ignored — a client cannot smuggle `role` / `is_admin`
into the login call (verified by `test_v06`).

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": {
    "id": "…",
    "username": "sarah.chen",
    "email": "sarah.chen@contextshield.dev",
    "full_name": "Sarah Chen",
    "department": "Human Resources",
    "employee_id": "EMP001",
    "is_active": true,
    "roles": [{"name": "hr_manager", "description": "…"}],
    "permissions": [{"resource": "employee_salary", "action": "read"}]
  }
}
```

**Error (401):**
```json
{
  "error": {
    "type": "AuthenticationError",
    "detail": "Invalid username or password"
  }
}
```

**Error (429 — repeated failures):** identical body shape with `type` =
`RateLimitError`, plus a `Retry-After` header. Throttling checks run
before credential verification and count failures only for the same
username + client address (with an address-level backstop).

**Security notes:**
- The error message is intentionally vague ("Invalid username or password")
  and identical for unknown users, wrong passwords, and inactive accounts —
  no account enumeration.
- Password comparison is timing-safe (bcrypt).
- Failed and successful attempts are written to the audit trail
  (usernames only, never passwords or tokens).

---

### 4.5 `GET /api/v1/auth/me`

**Purpose:** Return the authenticated user's profile. Role and permissions are read from the database, not from the token.

**Headers:** `Authorization: Bearer <token>`

**Response (200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "hr.manager@contextshield.demo",
  "full_name": "Alice Chen",
  "role": "hr_manager",
  "department": "Human Resources",
  "clearance_level": "restricted",
  "is_active": true,
  "created_at": "2026-01-15T09:00:00Z"
}
```

---

### 4.6 `POST /api/v1/privacy/secure-request` ⭐ Core Endpoint

**Purpose:** Submit a data request through the full ContextShield privacy pipeline. This is the primary integration point for AI agents.

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "data_fields": ["employee_name", "salary", "department", "email"],
  "purpose": "performance_review",
  "target_entity": "employee-456",
  "context": {
    "session_id": "sess-abc123",
    "additional_claims": {}
  },
  "include_llm_response": false
}
```

**Request Schema:**
| Field                 | Type     | Required | Description                                        |
|-----------------------|----------|----------|----------------------------------------------------|
| `data_fields`         | string[] | Yes      | Fields being requested (1–50 fields)               |
| `purpose`             | string   | Yes      | Claimed purpose (will be validated server-side)     |
| `target_entity`       | string   | Yes      | ID of the entity being queried                      |
| `context.session_id`  | string   | No       | Session ID for mosaic-effect tracking               |
| `context.additional_claims` | object | No  | Additional context (untrusted, server-validated)   |
| `include_llm_response`| boolean | No       | Whether to generate an LLM natural-language response |

**Response (200) — Authorized HR manager:**
```json
{
  "request_id": "req-550e8400-e29b-41d4-a716-446655440000",
  "overall_decision": "PARTIAL_ALLOW",
  "fields": {
    "employee_name": {
      "action": "ALLOW",
      "value": "Jane Smith",
      "reason_code": "NORM_MATCHED",
      "policy_id": "P-hr-salary-review",
      "policy_version": 2
    },
    "salary": {
      "action": "ALLOW",
      "value": 95000,
      "reason_code": "NORM_MATCHED",
      "policy_id": "P-hr-salary-review",
      "policy_version": 2
    },
    "department": {
      "action": "ALLOW",
      "value": "Engineering",
      "reason_code": "NORM_MATCHED",
      "policy_id": "P-hr-salary-review",
      "policy_version": 2
    },
    "email": {
      "action": "MASK",
      "value": "j***@company.com",
      "reason_code": "NORM_MATCHED",
      "policy_id": "P-hr-contact-masked",
      "policy_version": 1
    }
  },
  "llm_response": null,
  "guard_triggered": false,
  "audit_id": "aud-789e8400-e29b-41d4-a716-446655440000",
  "mosaic_warning": false,
  "timestamp": "2026-10-18T11:30:00.123Z"
}
```

**Response (200) — Unauthorized peer employee:**
```json
{
  "request_id": "req-660e8400-e29b-41d4-a716-446655440000",
  "overall_decision": "PARTIAL_ALLOW",
  "fields": {
    "employee_name": {
      "action": "ALLOW",
      "value": "Jane Smith",
      "reason_code": "NORM_MATCHED",
      "policy_id": "P-self-service",
      "policy_version": 1
    },
    "salary": {
      "action": "BLOCK",
      "value": null,
      "reason_code": "INSUFFICIENT_ROLE",
      "policy_id": null,
      "policy_version": null
    },
    "department": {
      "action": "ALLOW",
      "value": "Engineering",
      "reason_code": "NORM_MATCHED",
      "policy_id": "P-self-service",
      "policy_version": 1
    },
    "email": {
      "action": "BLOCK",
      "value": null,
      "reason_code": "INSUFFICIENT_ROLE",
      "policy_id": null,
      "policy_version": null
    }
  },
  "llm_response": null,
  "guard_triggered": false,
  "audit_id": "aud-890e8400-e29b-41d4-a716-446655440000",
  "mosaic_warning": false,
  "timestamp": "2026-10-18T11:30:01.456Z"
}
```

**Overall Decision Logic:**
| Condition                                   | overall_decision   |
|---------------------------------------------|--------------------|
| All fields ALLOW                            | `ALLOW`            |
| All fields BLOCK                            | `BLOCK`            |
| Mix of ALLOW and BLOCK/MASK/GENERALIZE      | `PARTIAL_ALLOW`    |
| Any field ESCALATE                          | `ESCALATION_NEEDED`|
| Evaluation error                            | `BLOCK`            |

**Implementation notes (v1):**

* `resource` is a **required** request field: the catalog resource being
  addressed (`employee_salary`, `order_records`, …). The example above is
  from the original design draft; the implemented contract addresses data by
  resource + field, not by implicit field lookup.
* `operation` is limited to `read` and `aggregate` — the two operations the
  minimum-disclosure pipeline implements.
* Destinations are **not client-settable**; `context` carries correlation
  metadata only (`session_id`, `conversation_id`, `task_id`, `turn_index`,
  `agent_name`, scalar `additional_claims`). Claims that look like identity
  or authorization (`role`, `permissions`, …) are dropped at the edge and
  never influence decisions.
* Responses add the structured fields the SDK consumes: top-level
  `reason_code`/`reason`, `retrieved`, and — when `include_llm_response` is
  set — an `llm` object (`requested`, `invoked`, `provider`, `model`,
  `error_code`, `error`, `guard`). Guard findings carry category/rule/span
  metadata only, never the matched text.
* Shape/validation problems return `422`; everything semantic (unknown
  resource, unauthorized target, invalid purpose, policy denial) is a
  fail-closed **200** with `BLOCK`/`ESCALATION_NEEDED` and per-field reason
  codes.
* When the output guard flags model output, `guard_triggered` is set and the
  response follows `LLM_OUTPUT_GUARD_MODE` (redact/reject/escalate). A guard
  failure withholds the output entirely (`GUARD_ERROR`). See
  [llm-integration.md](llm-integration.md) for provider configuration and
  guard semantics.

---

### 4.7 `GET /api/v1/policies` — implemented

**Purpose:** List privacy policies — the rules the policy engine enforces.
Active policies are readable by **any authenticated principal**; inactive /
superseded / archived versions are administrative history and require an
administrator identity (user role `admin`, or a service account with `*` /
`role:admin` / policy-admin scopes). Non-admins asking for
`include_inactive=true` receive `403`.

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
| Parameter | Type   | Default | Description                        |
|-----------|--------|---------|------------------------------------|
| `limit`   | int    | 20      | Items per page (1–100)             |
| `offset`  | int    | 0       | Pagination offset                  |
| `resource`| string | —       | Only policies whose `resource_pattern` matches this resource (exact, or trailing-`*` prefix — the same semantics the engine uses) |
| `role`    | string | —       | Filter by `required_role`          |
| `include_inactive` | bool | `false` | Include superseded/archived versions (administrators only) |

**Response (200):**
```json
{
  "items": [
    {
      "id": "pol-…",
      "name": "salary_access_policy",
      "version": 1,
      "description": "HR manager salary access for performance reviews.",
      "policy_text": "HR managers may read salary data for direct reports during reviews.",
      "resource_pattern": "employee_salary",
      "required_role": "hr_manager",
      "min_sensitivity": "restricted",
      "allowed_purposes": ["hr_review"],
      "allowed_actions": ["read"],
      "action": "ALLOW",
      "priority": 100,
      "status": "active",
      "is_active": true,
      "effective_from": "2026-01-01T00:00:00Z",
      "effective_until": null
    }
  ],
  "pagination": { "total": 12, "limit": 20, "offset": 0, "has_more": false }
}
```

* The projection is allowlisted — nothing outside this shape can leak even
  if the policy store grows.
* `policy_text` is the human-readable rule summary (the same text shipped
  in `docs/privacy-policies.md`); it contains no secrets or protected data.
* Ordering is `name` ascending, then version descending (newest first).

---

### 4.8 `GET /api/v1/audit/events` — implemented

**Purpose:** Query the audit trail. Visibility is derived server-side from the
**verified principal only** (never from query parameters):

| Principal | Visible slice of the trail |
|---|---|
| `admin` role, or a service account holding `*` / `role:admin` | Complete trail — all actors, all action classes |
| `hr_manager` / `executive`, or `role:hr_manager` / `role:executive` service scopes | Privacy-pipeline events for all actors: `data_access`, `data_denied`, `policy_evaluation`, `transformation`, `ai_query`, `output_inspection` |
| Every other authenticated principal (human or agent) | **Own** events only, all action classes |

Scope is enforced in SQL (`actor_id` / `action IN (…)` constraints), so
out-of-scope rows are never loaded. An explicit **out-of-scope filter** (e.g.
`requester_id=<someone else>` for an own-scope principal, or an authentication
action for a compliance-role principal) is rejected with **403**; a direct
fetch of an out-of-scope event returns **404** (§4.9) so event existence is
not disclosed.

**Headers:** `Authorization: Bearer <token>` or `X-API-Key: <service key>`

**Query Parameters:**
| Parameter       | Type     | Default  | Description |
|-----------------|----------|----------|-------------|
| `limit`         | int      | 20       | Items per page (1–100) |
| `offset`        | int      | 0        | Pagination offset |
| `requester_id`  | string   | —        | Filter by actor id (users *and* agents) |
| `action`        | string   | —        | `login`, `logout`, `data_access`, `data_denied`, `policy_evaluation`, `transformation`, `ai_query`, `output_inspection`, `admin_action`, `seed_data` |
| `resource`      | string   | —        | Filter by catalog resource (e.g. `employee_salary`) |
| `outcome`       | string   | —        | `success`, `denied`, `escalated`, `failed`, `passed`, `flagged` |
| `session_id`    | string   | —        | Correlation id supplied with the secure request |
| `start_date`    | datetime | —        | Events at/after this timestamp (ISO 8601) |
| `end_date`      | datetime | —        | Events at/before this timestamp (ISO 8601) |

Invalid shapes (unknown action, `limit > 100`, `start_date > end_date`) → 422.

**Response (200):**
```json
{
  "items": [
    {
      "id": "9a0d1f7c5e2b4a8d93c1f0e6b7a2d4c8",
      "timestamp": "2026-10-19T11:30:00.123456+00:00",
      "action": "data_denied",
      "outcome": "denied",
      "actor": {
        "id": "3b7c9d1e5f2a4b8c6d0e9f1a2b3c4d5e",
        "kind": "user",
        "name": "Mia Torres",
        "roles": ["marketing_intern"],
        "scopes": []
      },
      "request_id": "8f1e2d3c4b5a69788796a5b4c3d2e1f0",
      "session_id": "sess-abc123",
      "resource": "employee_salary",
      "resource_id": "EMP002",
      "overall_decision": "BLOCK",
      "reason_codes": ["INSUFFICIENT_ROLE"],
      "policy_versions": [4],
      "sensitivity_categories": ["financial"],
      "model_requested": false,
      "model_invoked": false,
      "guard_outcome": null,
      "mosaic_warning": false
    }
  ],
  "pagination": { "total": 142, "limit": 20, "offset": 0, "has_more": true }
}
```

**Recorded content is safe by construction.** Events never store raw protected
values, passwords, API keys, JWTs, purpose free text, prompts, or model
outputs. `actor` identity (name/roles/scopes) is re-resolved from the database
at read time; `requester` in the detail response (§4.9) is the snapshot
verified at request time.

**Implementation:** `app/api/v1/audit.py`, `app/services/audit_service.py`,
`app/schemas/audit.py`; events are written by
`app/services/data_connector.py` (`_persist`) for both human and agent
principals (`audit_events.actor_kind` = `"user"` | `"service"`).

---

### 4.9 `GET /api/v1/audit/events/{id}` — implemented

**Purpose:** Full explainability for one event: per-field decisions, reason
codes, policy versions, transformation types, and model-stage metadata.

**Headers:** `Authorization: Bearer <token>` or `X-API-Key: <service key>`

**Visibility:** the same scopes as §4.8: admins read any event; compliance
roles read privacy-pipeline events; every other principal reads only its own.
A missing **or out-of-scope** id returns **404** (existence is not revealed).

**Response (200):** the §4.8 list-item projection plus:

```json
{
  "id": "9a0d1f7c5e2b4a8d93c1f0e6b7a2d4c8",
  "timestamp": "2026-10-19T11:30:00.123456+00:00",
  "action": "data_access",
  "outcome": "success",
  "actor": {
    "id": "3b7c9d1e5f2a4b8c6d0e9f1a2b3c4d5e",
    "kind": "service",
    "name": "support-copilot",
    "roles": [],
    "scopes": ["privacy:request", "customer_records:read"]
  },
  "request_id": "8f1e2d3c4b5a69788796a5b4c3d2e1f0",
  "session_id": "sess-abc123",
  "resource": "customer_records",
  "resource_id": "CUS003",
  "overall_decision": "PARTIAL_ALLOW",
  "reason_codes": ["NORM_MATCHED"],
  "policy_versions": [2],
  "sensitivity_categories": ["contact"],
  "model_requested": true,
  "model_invoked": true,
  "guard_outcome": "none",
  "mosaic_warning": false,
  "purpose": "customer_service",
  "purpose_recognized": true,
  "operation": "read",
  "subject_scope": "record",
  "flags": [],
  "requested_fields": ["contact_email", "contact_phone"],
  "decisions": [
    {
      "field": "contact_email",
      "action": "MASK",
      "reason_code": "NORM_MATCHED",
      "policy_id": "P-support-contact",
      "policy_version": 2,
      "sensitivity": "high",
      "pii_category": "contact"
    }
  ],
  "transformations": [
    { "field": "contact_email", "transformation": "mask" }
  ],
  "llm": {
    "requested": true,
    "invoked": true,
    "provider": "mock",
    "model": "mock-deterministic",
    "guard_triggered": false,
    "guard_action": "none",
    "guard_reason_code": null,
    "error_code": null
  },
  "guard_triggered": false,
  "correlation": { "session_id": "sess-abc123", "agent_name": "support-copilot" },
  "ip_address": null,
  "requester": {
    "id": "3b7c9d1e5f2a4b8c6d0e9f1a2b3c4d5e",
    "kind": "service",
    "name": "support-copilot",
    "roles": [],
    "scopes": ["privacy:request", "customer_records:read"],
    "authentication": "api_key"
  },
  "agent": {
    "id": "3b7c9d1e5f2a4b8c6d0e9f1a2b3c4d5e",
    "kind": "service_account",
    "name": "support-copilot",
    "scopes": ["privacy:request", "customer_records:read"]
  }
}
```

`POST /api/v1/privacy/secure-request` returns the same event id as
`audit_id`, so a caller can always correlate the decision it received with
the recorded trail entry.

---

### 4.10 `GET /api/v1/dashboard/overview` — implemented

**Purpose:** Dashboard summary metrics for the authenticated caller's
visible audit trail. Counting follows the audit visibility model (§4.8):
administrators see the full trail (`scope: "full"`), compliance roles the
privacy pipeline (`"privacy_trail"`), everyone else only their own events
(`"own"`). All numbers are aggregated from **recorded audit events** and
live configuration — nothing is fabricated; an empty trail yields zeros.

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
| Parameter      | Type | Default | Description                     |
|----------------|------|---------|---------------------------------|
| `window_days`  | int  | 14      | Look-back window in days (1–90) |
| `recent_limit` | int  | 8       | Recent decisions to embed (1–50) |

**Response (200):**
```json
{
  "scope": "own",
  "window_days": 14,
  "summary": {
    "window_days": 14,
    "total_requests": 47,
    "decisions": { "ALLOW": 30, "PARTIAL_ALLOW": 5, "BLOCK": 10, "ESCALATION_NEEDED": 2 },
    "requests_with_transformations": 6,
    "model_invocations": 4,
    "guard_triggered": 1,
    "mosaic_warnings": 2
  },
  "daily": [
    { "date": "2026-10-05", "total": 5, "allow": 3, "partial_allow": 1, "block": 1, "escalation": 0 }
  ],
  "recent_decisions": [ { "id": "aud-…", "timestamp": "…", "action": "data_access",
                          "actor": { "id": "…", "kind": "user", "name": "…", "roles": [], "scopes": [] },
                          "overall_decision": "PARTIAL_ALLOW", "reason_codes": ["…"], "…": "…" } ],
  "policy_stats": { "active_policies": 12, "most_triggered_policy": "salary_access_policy" },
  "health": {
    "database": "healthy",
    "database_latency_ms": 1.24,
    "llm": { "provider": "mock", "model": "mock-deterministic", "configured": true },
    "classifier": { "status": "ready" }
  },
  "timestamp": "2026-10-18T11:30:00Z"
}
```

* `daily` is a continuous, zero-filled series for the window (one entry per
  day, UTC) — chart-ready.
* `recent_decisions` items use the same allowlisted projection as §4.8;
  the newest `recent_limit` decision events are embedded.
* `summary.total_requests` counts gateway decisions
  (`data_access`/`data_denied` events); `requests_with_transformations`
  counts decisions whose recorded detail includes applied transformations;
  `model_invocations` counts `ai_query` events; `guard_triggered` counts
  flipped output-inspection events; `mosaic_warnings` counts decision
  events flagged for re-identification risk.
* `health` mirrors the safe shapes of §4.3 (no keys or secrets ever).

---

### 4.11 `GET /api/v1/data/assets` — implemented

**Purpose:** List data assets and their classification metadata — the
catalog resources the gateway guards and the field classifications the
policy engine relies on. Readable by **any authenticated principal**.

**Classification metadata only.** The payload contains names, types,
sensitivity levels, PII categories, and record *counts*; it never contains
row data from the backing tables, so raw values cannot leak through this
endpoint by construction.

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
| Parameter     | Type   | Default | Description                     |
|---------------|--------|---------|---------------------------------|
| `limit`       | int    | 20      | Items per page (1–100)          |
| `offset`      | int    | 0       | Pagination offset               |
| `sensitivity` | string | —       | Only assets containing at least one field at this level (`low`/`medium`/`high`/`restricted`) |
| `asset_type`  | string | —       | Filter by asset type            |

**Response (200):**
```json
{
  "items": [
    {
      "id": "asset-…",
      "name": "employee_salary",
      "description": "Employee compensation and payroll data",
      "asset_type": "employee_records",
      "owner_department": "Human Resources",
      "table_name": "employees",
      "field_count": 4,
      "sensitivity_summary": { "low": 2, "medium": 0, "high": 1, "restricted": 1 },
      "record_count": 25,
      "fields": [
        {
          "name": "base_salary",
          "column_name": "base_salary",
          "field_type": "numeric",
          "sensitivity": "restricted",
          "pii_category": "salary",
          "description": "Annual base salary"
        }
      ]
    }
  ],
  "pagination": { "total": 5, "limit": 20, "offset": 0, "has_more": false }
}
```

* `record_count` is the live row count of the backing table (metadata), or
  `null` for assets without a known table.
* Assets are ordered by `name`; fields are ordered by `name`.

---

## 5. Request Validation Rules

| Rule                                        | Implementation                                    |
|---------------------------------------------|---------------------------------------------------|
| All string fields are trimmed               | Pydantic `validator`                              |
| `data_fields` must contain 1–50 items       | Pydantic `conlist(min_length=1, max_length=50)`   |
| `purpose` must be a known, valid purpose    | Validated against the policy database              |
| `target_entity` must be a non-empty string  | Pydantic `constr(min_length=1)`                   |
| `email` is validated as RFC-compliant       | Pydantic `EmailStr`                                |
| `password` is 8–128 characters              | Pydantic `constr(min_length=8, max_length=128)`   |
| Pagination `limit` capped at 100           | Pydantic `conint(ge=1, le=100)`                    |
| UUIDs are validated format                  | Pydantic `UUID4`                                   |
| All dates are ISO 8601                      | Pydantic `datetime`                                |

---

## 6. Rate Limiting

**Implemented (v1):** login throttling only — a failure-only sliding
window per username + client address (`AUTH_RATE_LIMIT_MAX_FAILURES`,
default 10/window) with a per-address backstop
(`AUTH_RATE_LIMIT_IP_MAX_FAILURES`, default 50/window) and a configurable
window (`AUTH_RATE_LIMIT_WINDOW_SECONDS`, default 60). Exceeding the
limit returns `429` + `Retry-After` before credential verification.
Successful sign-ins are never throttled and clear their own counter.
Per-process, in-memory — see the limitations in
`docs/verification-report.md`.

**Not yet implemented (v2 candidates):** global per-tier quotas below.
They remain design targets, not shipped behavior.

| Tier           | Limit (proposed)       | Window   |
|----------------|------------------------|----------|
| Unauthenticated| 10 requests            | 1 minute |
| Authenticated  | 100 requests           | 1 minute |
| Secure-request | 30 requests            | 1 minute |

---

## 7. OpenAPI Tags

| Tag          | Description                             | Endpoints                     |
|--------------|-----------------------------------------|-------------------------------|
| `system`     | Health checks and system status         | `/health`, `/system/status`   |
| `auth`       | Authentication and user profile         | `/auth/login`, `/auth/me`     |
| `privacy`    | Core privacy pipeline                   | `/privacy/secure-request`     |
| `policies`   | Policy management and listing           | `/policies`                   |
| `audit`      | Audit trail queries                     | `/audit/events`, `/audit/events/{id}` |
| `dashboard`  | Overview metrics and analytics          | `/dashboard/overview`         |
| `data`       | Data asset inventory                    | `/data/assets`                |

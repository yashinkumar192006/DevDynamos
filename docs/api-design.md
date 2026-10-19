# ContextShield — API Design & Contract

> **Version:** 1.0.0  
> **Status:** Draft — Pre-implementation  
> **Last Updated:** 2026-10-18

---

## 1. API Overview

| Property          | Value                                       |
|-------------------|---------------------------------------------|
| **Base URL**      | `http://localhost:8000`                      |
| **API Prefix**    | `/api/v1`                                    |
| **Format**        | JSON (application/json)                      |
| **Auth**          | JWT Bearer token (HS256)                     |
| **Docs**          | Swagger UI at `/docs`, ReDoc at `/redoc`     |
| **Versioning**    | URL path (`/api/v1/`)                        |

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
| `GET /api/v1/auth/me`                 | Yes           | Any authenticated  |
| `POST /api/v1/privacy/secure-request` | Yes           | Any authenticated  |
| `GET /api/v1/policies`                | Yes           | Any authenticated  |
| `GET /api/v1/audit/events`            | Yes           | Any authenticated (visibility-scoped — see §4.8) |
| `GET /api/v1/audit/events/{id}`       | Yes           | Any authenticated (visibility-scoped — see §4.9) |
| `GET /api/v1/dashboard/overview`      | Yes           | Any authenticated  |
| `GET /api/v1/data/assets`             | Yes           | Any authenticated  |

---

## 3. Common Models

### 3.1 Error Response

All error responses follow this format:

```json
{
  "error": {
    "code": "AUTHORIZATION_FAILED",
    "message": "You do not have permission to access this resource.",
    "request_id": "req-550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2026-10-18T11:30:00Z"
  }
}
```

### 3.2 Standard Error Codes

| HTTP Status | Error Code                | Description                                 |
|-------------|---------------------------|---------------------------------------------|
| 400         | `VALIDATION_ERROR`        | Request body failed Pydantic validation     |
| 401         | `AUTHENTICATION_REQUIRED` | Missing or invalid JWT token                |
| 401         | `TOKEN_EXPIRED`           | JWT token has expired                       |
| 403         | `AUTHORIZATION_FAILED`    | Valid token but insufficient permissions    |
| 404         | `NOT_FOUND`               | Requested resource does not exist           |
| 422         | `UNPROCESSABLE_ENTITY`    | Request is syntactically valid but semantically invalid |
| 429         | `RATE_LIMITED`             | Too many requests (v2)                      |
| 500         | `INTERNAL_ERROR`          | Server-side error with request ID for correlation |

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
  "email": "hr.manager@contextshield.demo",
  "password": "demo-password-123"
}
```

**Schema:**
| Field      | Type   | Required | Validation                |
|------------|--------|----------|---------------------------|
| `email`    | string | Yes      | Valid email format         |
| `password` | string | Yes      | 8–128 characters           |

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "hr.manager@contextshield.demo",
    "full_name": "Alice Chen",
    "role": "hr_manager",
    "department": "Human Resources"
  }
}
```

**Error (401):**
```json
{
  "error": {
    "code": "AUTHENTICATION_REQUIRED",
    "message": "Invalid email or password.",
    "request_id": "req-...",
    "timestamp": "2026-10-18T11:30:00Z"
  }
}
```

**Security notes:**
- The error message is intentionally vague ("Invalid email or password") to prevent user enumeration.
- Password comparison is timing-safe (bcrypt).
- Failed attempts are logged for audit.

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

### 4.7 `GET /api/v1/policies`

**Purpose:** List all active privacy policies. Useful for understanding what rules are in effect.

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
| Parameter | Type   | Default | Description                        |
|-----------|--------|---------|------------------------------------|
| `limit`   | int    | 20      | Items per page (1–100)             |
| `offset`  | int    | 0       | Pagination offset                  |
| `role`    | string | —       | Filter by applicable role          |
| `data_type` | string | —     | Filter by data type                |

**Response (200):**
```json
{
  "items": [
    {
      "id": "P-hr-salary-review",
      "version": 2,
      "name": "HR Salary Review",
      "description": "HR managers may access full salary data for performance reviews.",
      "allowed_roles": ["hr_manager"],
      "data_types": ["SALARY", "PERSON_NAME", "DEPARTMENT"],
      "allowed_purposes": ["performance_review", "compensation_planning"],
      "action": "ALLOW",
      "priority": 100,
      "is_active": true,
      "effective_from": "2026-01-01T00:00:00Z"
    }
  ],
  "pagination": {
    "total": 8,
    "limit": 20,
    "offset": 0,
    "has_more": false
  }
}
```

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

### 4.10 `GET /api/v1/dashboard/overview`

**Purpose:** Dashboard summary metrics for the authenticated user's view.

**Headers:** `Authorization: Bearer <token>`

**Response (200):**
```json
{
  "summary": {
    "total_requests_today": 47,
    "total_requests_week": 312,
    "decisions": {
      "ALLOW": 189,
      "PARTIAL_ALLOW": 85,
      "BLOCK": 28,
      "ESCALATION_NEEDED": 10
    },
    "guard_triggered_count": 3,
    "mosaic_warnings_count": 2
  },
  "recent_events": [
    {
      "id": "aud-...",
      "timestamp": "2026-10-18T11:30:00Z",
      "requester_role": "hr_manager",
      "overall_decision": "PARTIAL_ALLOW",
      "target_entity_id": "employee-456"
    }
  ],
  "policy_stats": {
    "active_policies": 8,
    "most_triggered_policy": "hr_salary_review",
    "most_blocked_data_type": "SSN"
  },
  "timestamp": "2026-10-18T11:30:00Z"
}
```

---

### 4.11 `GET /api/v1/data/assets`

**Purpose:** List data assets and their classification metadata. Shows what data sources are available and how they are classified.

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
| Parameter         | Type   | Default | Description                     |
|-------------------|--------|---------|---------------------------------|
| `limit`           | int    | 20      | Items per page (1–100)          |
| `offset`          | int    | 0       | Pagination offset               |
| `sensitivity`     | string | —       | Filter by sensitivity level     |

**Response (200):**
```json
{
  "items": [
    {
      "id": "da-employees",
      "name": "Employee Records",
      "description": "Core employee data including personal and compensation information.",
      "table_name": "employees",
      "fields": [
        {
          "name": "full_name",
          "entity_type": "PERSON_NAME",
          "sensitivity": "MEDIUM",
          "source": "schema_annotation"
        },
        {
          "name": "salary",
          "entity_type": "SALARY",
          "sensitivity": "RESTRICTED",
          "source": "schema_annotation"
        },
        {
          "name": "email",
          "entity_type": "EMAIL",
          "sensitivity": "MEDIUM",
          "source": "schema_annotation"
        },
        {
          "name": "ssn",
          "entity_type": "SSN",
          "sensitivity": "RESTRICTED",
          "source": "schema_annotation"
        },
        {
          "name": "department",
          "entity_type": null,
          "sensitivity": "LOW",
          "source": "schema_annotation"
        }
      ],
      "record_count": 25,
      "last_updated": "2026-10-18T00:00:00Z"
    }
  ],
  "pagination": {
    "total": 4,
    "limit": 20,
    "offset": 0,
    "has_more": false
  }
}
```

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

## 6. Rate Limiting (v2)

| Tier           | Limit                  | Window   |
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

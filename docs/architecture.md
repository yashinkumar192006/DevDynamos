# ContextShield — Architecture Document

> **Version:** 1.0.0  
> **Status:** Draft — Pre-implementation  
> **Last Updated:** 2026-10-18

---

## 1. System Overview

ContextShield is a **privacy enforcement middleware** that intercepts data requests from AI agents, applies contextual privacy policies, and returns only the information that the requester is authorized to receive in the given context. The product consists of three deliverables:

1. **Python SDK** — An importable library for direct integration with Python-based AI agents.
2. **FastAPI HTTP Gateway** — A REST API for language-agnostic integration.
3. **Demo Frontend** — A React dashboard that visualizes the privacy pipeline in action.

The frontend is a demonstration interface. **The security boundary is the backend.**

---

## 2. Complete Pipeline Architecture

```text
┌───────────────────────────────────────────────────────────────────────┐
│              Existing AI Agent / Demo Frontend                        │
│                    (untrusted client)                                  │
└──────────────────────────┬────────────────────────────────────────────┘
                           │  HTTP / SDK call
                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│                    Python SDK / HTTP API                               │
│             (request serialization & validation)                      │
└──────────────────────────┬────────────────────────────────────────────┘
                           │
                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│                      FastAPI Gateway                                  │
│              (routing, middleware, error handling)                     │
└──────────────────────────┬────────────────────────────────────────────┘
                           │
                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│              Authentication & Identity Layer                          │
│  • JWT validation (HS256, python-jose)                                │
│  • User lookup from PostgreSQL (role, department, clearance)          │
│  • Reject all client-supplied role claims                             │
└──────────────────────────┬────────────────────────────────────────────┘
                           │  Authenticated Identity
                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│                    Context Analyzer                                    │
│  • Resolve requester: server-side identity, role, department          │
│  • Validate purpose claim against allowed scenarios                   │
│  • Resolve target entity and data scope                               │
│  • Detect ambiguity → require clarification or escalation             │
│  • Output: AnalyzedContext (trusted context tuple)                    │
└──────────────────────────┬────────────────────────────────────────────┘
                           │  AnalyzedContext
                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│              Sensitive-Data Classification                             │
│  • Database schema annotations (authoritative, trusted)               │
│  • Microsoft Presidio + spaCy NLP (signal, not decision)              │
│  • Deterministic rules for domain-specific fields                     │
│  • Output: ClassifiedFields[] with entity type + sensitivity level    │
└──────────────────────────┬────────────────────────────────────────────┘
                           │  ClassifiedFields
                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│              Deterministic Policy Engine                               │
│  • Match (requester_role, data_type, purpose) against flow norms      │
│  • LLM NEVER decides permissions — backend code only                  │
│  • Output per-field decision: ALLOW|MASK|TOKENIZE|GENERALIZE|         │
│    AGGREGATE|BLOCK|ESCALATE                                           │
│  • Attach reason code and matched policy ID to each decision          │
│  • Fail-closed: no matching norm → BLOCK                              │
└──────────────────────────┬────────────────────────────────────────────┘
                           │  PolicyDecision[]
                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│              Authorized Data Connector                                 │
│  • Fetch ONLY the fields permitted by policy (pre-filter)             │
│  • Query PostgreSQL with scoped SELECT (no SELECT *)                  │
│  • Protected data is never retrieved before permission check          │
│  • Row-level filtering where applicable                               │
└──────────────────────────┬────────────────────────────────────────────┘
                           │  Raw authorized data
                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│              Minimum-Disclosure Transformer                            │
│  • Apply per-field transformations based on policy decisions           │
│  • MASK: partial reveal (e.g., ***-**-1234)                           │
│  • TOKENIZE: replace with reversible token                            │
│  • GENERALIZE: replace salary with range, age with bracket            │
│  • AGGREGATE: replace individual values with group stats              │
│  • BLOCK: omit field entirely                                         │
│  • ESCALATE: hold pending approval                                    │
│  • Track cumulative disclosures for mosaic-effect detection            │
└──────────────────────────┬────────────────────────────────────────────┘
                           │  Transformed data
                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│                    Safe AI Context                                     │
│  • Privacy-enforced data assembled into LLM prompt context            │
│  • Contains ONLY disclosed fields and their transformed values        │
│  • Includes system instructions constraining the LLM's behavior       │
└──────────────────────────┬────────────────────────────────────────────┘
                           │  Sanitized prompt
                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│              Backend LLM Adapter                                       │
│  • Provider-independent interface (strategy pattern)                  │
│  • Built-in MockLLMProvider for deterministic testing                 │
│  • Optional GeminiProvider behind feature flag                        │
│  • LLM receives ONLY privacy-enforced context                         │
│  • Timeout, retry, and error handling                                 │
└──────────────────────────┬────────────────────────────────────────────┘
                           │  Raw LLM response
                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│              Output Privacy Guard                                      │
│  • Scan LLM response for PII re-introduction                          │
│  • Presidio + deterministic checks on response text                   │
│  • Strip any sensitive values that were not in the ALLOW set          │
│  • Detect hallucinated PII (values LLM invented)                     │
│  • If guard fires → redact + add warning annotation                  │
└──────────────────────────┬────────────────────────────────────────────┘
                           │  Sanitized response
                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│                    Approved Response                                   │
│  • Final JSON response with per-field decisions                       │
│  • Includes policy_applied, reason_codes, and audit_id                │
│  • Returned to the calling AI agent or demo frontend                  │
└──────────────────────────┬────────────────────────────────────────────┘
                           │
                           ▼
┌───────────────────────────────────────────────────────────────────────┐
│              Audit & Explainability                                    │
│  • Immutable audit record per request (AuditEvent)                    │
│  • Fields: request_context, policy_id, decisions[], reason_codes,     │
│    timestamp, requester_id, target_entity, hashed_values              │
│  • NO raw PII in audit logs — only hashed representations             │
│  • Queryable via API for compliance review                            │
│  • Dashboard visualization of access patterns                         │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Responsibilities

### 3.1 FastAPI Gateway (`backend/app/main.py`)

| Responsibility               | Detail                                                |
|-------------------------------|-------------------------------------------------------|
| Application bootstrap         | Configure middleware, CORS, routes, error handlers    |
| Request ID tracking           | Assign UUID to every request for log correlation      |
| CORS enforcement              | Allow only configured origins                         |
| Global error handling         | Return structured JSON errors, never leak stack traces|
| OpenAPI documentation         | Auto-generated at `/docs` and `/redoc`                |

### 3.2 Authentication & Identity (`backend/app/core/security.py`)

| Responsibility               | Detail                                                |
|-------------------------------|-------------------------------------------------------|
| JWT creation & validation     | HS256, configurable expiry, python-jose                |
| Password verification         | bcrypt via passlib, timing-safe comparison             |
| User lookup                   | Database query by token subject (user ID)              |
| Role resolution               | Read roles from DB, never from token/client claims     |
| Auth dependency               | FastAPI `Depends()` for protecting routes              |

### 3.3 Context Analyzer (`backend/app/services/context_service.py`)

| Responsibility               | Detail                                                |
|-------------------------------|-------------------------------------------------------|
| Identity resolution           | Map authenticated user to role, department, clearance  |
| Purpose validation            | Check stated purpose against server-side allowed list  |
| Target resolution             | Identify target entity and validate existence          |
| Ambiguity detection           | Flag unclear requests for clarification                |
| Context assembly              | Produce `AnalyzedContext` Pydantic model               |

### 3.4 Sensitive-Data Classifier (`backend/app/services/classifier.py`)

| Responsibility               | Detail                                                |
|-------------------------------|-------------------------------------------------------|
| Schema-driven classification  | Read field metadata from DB; authoritative source      |
| NLP classification            | Presidio + spaCy for free-text PII detection           |
| Deterministic rules           | Domain-specific patterns (salary, SSN formats)         |
| Sensitivity assignment        | Map entity type → sensitivity level (LOW..RESTRICTED)  |
| Log safety                    | Hash all raw values before logging                     |

### 3.5 Deterministic Policy Engine (`backend/app/services/policy_engine.py`)

| Responsibility               | Detail                                                |
|-------------------------------|-------------------------------------------------------|
| Norm matching                 | Match (role, data_type, purpose) tuples against rules  |
| Decision generation           | Produce per-field ALLOW/MASK/TOKENIZE/GENERALIZE/AGGREGATE/BLOCK/ESCALATE |
| Fail-closed default           | No matching norm → BLOCK with reason code              |
| Reason codes                  | Attach human-readable reason to every decision         |
| Policy versioning             | Track policy version; decisions reference policy ID    |

### 3.6 Authorized Data Connector (`backend/app/services/data_connector.py`)

| Responsibility               | Detail                                                |
|-------------------------------|-------------------------------------------------------|
| Scoped queries                | SELECT only permitted columns, never SELECT *          |
| Pre-check enforcement         | Data is never fetched before policy evaluation         |
| Row-level filtering           | Apply row-level access rules (e.g., own department)    |
| Connection pooling            | Use SQLAlchemy async session pool                      |

### 3.7 Minimum-Disclosure Transformer (`backend/app/services/transformer.py`)

| Responsibility               | Detail                                                |
|-------------------------------|-------------------------------------------------------|
| Field-level transformation    | Apply MASK, TOKENIZE, GENERALIZE, AGGREGATE per field  |
| Masking                       | Partial reveal with configurable patterns              |
| Tokenization                  | Reversible token substitution (server-side map)        |
| Generalization                | Salary → range, DOB → age bracket, location → region   |
| Aggregation                   | Individual → group mean/median with k-anonymity check  |
| Mosaic tracking               | Record cumulative disclosures per session              |

### 3.8 Backend LLM Adapter (`backend/app/services/llm_adapter.py`)

| Responsibility               | Detail                                                |
|-------------------------------|-------------------------------------------------------|
| Provider abstraction          | `LLMProvider` protocol with `generate()` method        |
| Mock provider                 | Deterministic responses for testing                    |
| Gemini provider (optional)    | Google AI API integration behind feature flag           |
| Prompt assembly               | Inject privacy-safe context into system/user prompts   |
| Error handling                | Timeout, retry, and graceful degradation               |

### 3.9 Output Privacy Guard (`backend/app/services/output_guard.py`)

| Responsibility               | Detail                                                |
|-------------------------------|-------------------------------------------------------|
| Response scanning             | Presidio + deterministic checks on LLM output text    |
| PII stripping                 | Remove any PII not in the ALLOW set                    |
| Hallucination detection       | Flag values that appear in output but not in input     |
| Warning annotation            | Add metadata if guard intervened                       |

### 3.10 Audit Service (`backend/app/services/audit_service.py`)

| Responsibility               | Detail                                                |
|-------------------------------|-------------------------------------------------------|
| Event creation                | Immutable AuditEvent per request                       |
| Value hashing                 | SHA-256 hash of sensitive values, never raw PII        |
| Queryable log                 | Filter by user, time, decision, policy                 |
| Compliance support            | Full context preserved for regulatory review           |

---

## 4. Backend Layered Architecture

```text
┌─────────────────────────────────────────────────────┐
│                  API Layer (api/v1/)                  │
│  FastAPI route handlers, input validation, response  │
│  serialization. Thin layer — delegates to services.  │
├─────────────────────────────────────────────────────┤
│                 Schema Layer (schemas/)               │
│  Pydantic models for requests, responses, and        │
│  internal data transfer objects. Validation here.     │
├─────────────────────────────────────────────────────┤
│                Service Layer (services/)              │
│  Business logic, orchestration, privacy pipeline.     │
│  Never imports from API layer. Testable in isolation. │
├─────────────────────────────────────────────────────┤
│              Repository Layer (repositories/)         │
│  Database queries only. No business logic.            │
│  Returns domain models or DTOs.                       │
├─────────────────────────────────────────────────────┤
│                 Model Layer (models/)                 │
│  SQLAlchemy ORM table definitions and relationships.  │
├─────────────────────────────────────────────────────┤
│                  Core Layer (core/)                   │
│  Config, security, logging, middleware, database      │
│  session management.                                  │
└─────────────────────────────────────────────────────┘
```

### Dependency Rules

- **API → Services → Repositories → Models/Core** (one-way dependencies)
- Services never import from the API layer.
- Repositories never contain business logic.
- Models are pure data definitions.
- Core provides cross-cutting concerns (config, security, logging).

---

## 5. Directory Structure

```
contextshield/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                    # FastAPI app bootstrap
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   └── v1/
│   │   │       ├── __init__.py
│   │   │       ├── router.py          # Aggregates all v1 routers
│   │   │       ├── auth.py            # POST /login, GET /me
│   │   │       ├── privacy.py         # POST /secure-request
│   │   │       ├── policies.py        # GET /policies
│   │   │       ├── audit.py           # GET /audit/events
│   │   │       ├── dashboard.py       # GET /dashboard/overview
│   │   │       ├── data.py            # GET /data/assets
│   │   │       └── system.py          # GET /health, /system/status
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── config.py              # Pydantic Settings
│   │   │   ├── database.py            # Async engine, session factory
│   │   │   ├── security.py            # JWT, password hashing
│   │   │   ├── logging.py             # structlog configuration
│   │   │   ├── middleware.py          # Request ID, timing, error handler
│   │   │   └── dependencies.py        # Shared FastAPI dependencies
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── base.py                # DeclarativeBase, common mixins
│   │   │   ├── user.py                # User, Role tables
│   │   │   ├── employee.py            # Employee records
│   │   │   ├── customer.py            # Customer records
│   │   │   ├── order.py               # Order records
│   │   │   ├── policy.py              # AccessPolicy, PolicyVersion
│   │   │   ├── audit.py               # AuditEvent
│   │   │   └── data_asset.py          # DataAsset, FieldMetadata
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py                # LoginRequest, TokenResponse
│   │   │   ├── privacy.py             # SecureRequest, SecureResponse
│   │   │   ├── policy.py              # PolicyOut, PolicyDecision
│   │   │   ├── audit.py               # AuditEventOut, AuditFilter
│   │   │   ├── context.py             # AnalyzedContext, ContextField
│   │   │   ├── classifier.py          # ClassifiedField, SensitivityLevel
│   │   │   ├── dashboard.py           # DashboardOverview
│   │   │   └── common.py              # Pagination, ErrorResponse
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── context_service.py     # Context Analyzer
│   │   │   ├── classifier.py          # Sensitive-Data Classifier
│   │   │   ├── policy_engine.py       # Deterministic Policy Engine
│   │   │   ├── data_connector.py      # Authorized Data Connector
│   │   │   ├── transformer.py         # Minimum-Disclosure Transformer
│   │   │   ├── llm_adapter.py         # Backend LLM Adapter
│   │   │   ├── output_guard.py        # Output Privacy Guard
│   │   │   ├── audit_service.py       # Audit & Explainability
│   │   │   └── pipeline.py            # Privacy Pipeline Orchestrator
│   │   └── repositories/
│   │       ├── __init__.py
│   │       ├── user_repo.py           # User queries
│   │       ├── employee_repo.py       # Employee queries
│   │       ├── customer_repo.py       # Customer queries
│   │       ├── order_repo.py          # Order queries
│   │       ├── policy_repo.py         # Policy queries
│   │       ├── audit_repo.py          # Audit event queries
│   │       └── data_asset_repo.py     # Data asset queries
│   ├── alembic/                        # Database migrations
│   ├── tests/                          # Backend tests
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/                           # React + Vite + TypeScript
│   ├── src/
│   │   ├── components/                # Reusable UI components
│   │   ├── pages/                     # Route pages
│   │   ├── services/                  # API client (Axios)
│   │   ├── hooks/                     # Custom React hooks
│   │   ├── types/                     # TypeScript type definitions
│   │   └── utils/                     # Utility functions
│   ├── package.json
│   └── Dockerfile
├── sdk/                                # Python SDK package
│   ├── contextshield/
│   │   ├── __init__.py
│   │   ├── client.py                  # SDK client class
│   │   ├── models.py                  # SDK data models
│   │   └── exceptions.py             # SDK exceptions
│   └── setup.py
├── policies/                           # Policy definition files
│   └── default_policies.yaml
├── database/seed/                      # Seed data scripts
├── tests/                              # E2E / integration tests
├── docs/                               # Documentation
├── .github/workflows/ci.yml
├── docker-compose.yml
└── .env.example
```

---

## 6. Data Flow: Secure Request Lifecycle

```text
1. Client sends POST /api/v1/privacy/secure-request with JWT

2. Gateway: Extract JWT → validate → get user_id

3. Auth Layer: SELECT user WHERE id = user_id → role, dept, clearance

4. Context Analyzer:
   input:  { user, requested_fields, purpose_claim, target_entity }
   output: AnalyzedContext { trusted_identity, validated_purpose,
                             target_ref, required_clearance }

5. Classifier:
   input:  requested_fields
   output: ClassifiedField[] { field_name, entity_type, sensitivity }

6. Policy Engine:
   input:  AnalyzedContext + ClassifiedField[]
   output: PolicyDecision[] { field, action, reason_code, policy_id }

7. Data Connector (if any fields are ALLOW/MASK/GENERALIZE/TOKENIZE):
   input:  allowed fields + target entity
   output: raw field values (scoped SELECT)

8. Transformer:
   input:  raw values + PolicyDecision[]
   output: transformed values per field

9. (Optional) Safe AI Context → LLM Adapter → Output Guard

10. Assemble response → return to client

11. Audit Service: persist AuditEvent (hashed values only)
```

---

## 7. Deployment Architecture

### 7.1 Local Development (Docker Compose)

```text
┌──────────────────────────────────────────────┐
│               Docker Compose                  │
│                                               │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │ Frontend │  │ Backend  │  │ PostgreSQL │ │
│  │  :5173   │→ │  :8000   │→ │   :5432    │ │
│  │ Vite dev │  │ Uvicorn  │  │  pg:16     │ │
│  └──────────┘  └──────────┘  └────────────┘ │
└──────────────────────────────────────────────┘
```

### 7.2 CI/CD (GitHub Actions)

```text
push/PR → backend-tests (Python 3.12 + PostgreSQL service)
        → frontend-lint (Node 20, lint + type-check)
        → (future) e2e-tests (Playwright)
        → (future) docker-build
```

---

## 8. Technology Decision Records

### TDR-1: Deterministic Policy Engine (Not LLM-Based)

**Decision:** Policy decisions are made by deterministic backend code, not by an LLM.

**Rationale:** LLMs are non-deterministic, susceptible to prompt injection, and cannot be formally verified. Privacy enforcement requires reproducible, auditable decisions. The LLM is a *consumer* of privacy-enforced data, never a *decision-maker* about access.

### TDR-2: Schema Annotations Over NLP

**Decision:** Database field metadata is the authoritative source for data classification; NLP is a supplementary signal.

**Rationale:** NLP classifiers have non-zero false-negative rates. For structured business data (salary columns, SSN fields), the database schema annotation is guaranteed accurate. NLP handles free-text scenarios where schema annotations don't exist.

### TDR-3: Fail-Closed Default

**Decision:** If no policy norm matches a request, the default action is BLOCK.

**Rationale:** In privacy enforcement, failing open (allowing access) creates data breaches. Failing closed (denying access) may inconvenience a user but never leaks data.

### TDR-4: Provider-Independent LLM Adapter

**Decision:** The LLM integration uses a strategy pattern with swappable providers.

**Rationale:** Avoids vendor lock-in. The mock provider enables deterministic testing. Real providers (Gemini, OpenAI) can be added without changing the privacy pipeline.

### TDR-5: Hash-Only Audit Logs

**Decision:** Audit logs contain SHA-256 hashes of sensitive values, never raw PII.

**Rationale:** If audit logs are compromised, no PII is exposed. Hashes allow verifying that specific values were processed without storing them.

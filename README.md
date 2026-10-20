# 🛡️ ContextShield

> **Context-Aware Data Privacy Enforcement Engine for AI Agents**

[![CI](https://github.com/yashinkumar192006/DevDynamos/actions/workflows/ci.yml/badge.svg)](https://github.com/yashinkumar192006/DevDynamos/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19%2B-61DAFB.svg)](https://react.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 Table of Contents

- [Problem Statement](#-problem-statement)
- [Our Solution](#-our-solution--contextshield)
- [How It Works](#-how-it-works)
- [Architecture](#-architecture)
- [Key Features](#-key-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [API Endpoints](#-api-endpoints)
- [Use Cases & Examples](#-use-cases--examples)
- [Security Principles](#-security-principles)
- [Verification & Release](#-verification--release)
- [Team](#-team)
- [License](#-license)

---

> **Verified release status (2026-10-20):** backend 335 passed / 0 failed /
> 0 skipped · SDK 32 passed + 2 opt-in skips (clean-environment install
> verified) · frontend lint, type-check, and production build pass ·
> Playwright 12/12 against the real backend · Docker images build and a fresh
> compose stack applied migrations, seeded idempotently, and served both apps ·
> GitHub Actions CI passed all four jobs ([run `39384448875`](https://github.com/yashinkumar192006/DevDynamos/actions/runs/39384448875)).
> **Not deployed**: no remote application, database, or paid resource was
> created. Exact commands, evidence, and limitations:
> [`docs/release-report.md`](docs/release-report.md).

---

## 🎯 Problem Statement

As AI agents become integral to enterprise workflows — answering employee queries, generating reports, automating customer interactions — they inevitably access **sensitive data**: salaries, personal identifiable information (PII), medical records, financial details, and customer data.

**The core challenge:**

> How do you let an AI agent access the data it needs to be useful, while ensuring it **never discloses sensitive information** to unauthorized users or in inappropriate contexts?

Traditional approaches fail because they rely on **static, binary access control** (allow/deny). But privacy is **contextual** — the same data point may be appropriate to share in one context and a violation in another:

| Scenario | Data | Recipient | Context | Should Disclose? |
|----------|------|-----------|---------|------------------|
| HR manager reviewing team | Salary | HR Manager | Performance review | ✅ Yes |
| Colleague asking chatbot | Salary | Peer employee | Casual inquiry | ❌ No |
| Support agent helping customer | Phone number | Support agent | Active ticket | ✅ Yes |
| Marketing analyst | Phone number | Marketing team | Campaign targeting | ❌ No |

Static rules can't capture this nuance. **ContextShield can.**

---

## 💡 Our Solution — ContextShield

ContextShield is a **privacy enforcement middleware** that sits between AI agents and the data they access. It implements the **Contextual Integrity** framework (Nissenbaum, 2004) — a theory from information ethics that defines privacy not as secrecy, but as **appropriate information flow**.

### The Three Pillars

```
┌─────────────────────────────────────────────────────────────┐
│                      AI Agent Request                       │
│         "Show me John's salary for the Q3 review"           │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│  PILLAR 1: CLASSIFY                                         │
│  ─────────────────                                          │
│  • Detect sensitive entities (salary → FINANCIAL_PII)       │
│  • Assign sensitivity level (salary → RESTRICTED)           │
│  • Use NLP (Presidio + spaCy) + deterministic schema rules  │
│  • Trust database annotations over NLP guesses              │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│  PILLAR 2: CONTEXTUALIZE                                    │
│  ────────────────────────                                   │
│  • WHO is asking? (role, department, clearance)             │
│  • WHY are they asking? (purpose: review, curiosity, task)  │
│  • WHAT norm applies? (HR can see salary for reviews)       │
│  • Verify purpose claims server-side — never trust client   │
│  • Flag ambiguous requests for clarification                │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│  PILLAR 3: ENFORCE                                          │
│  ────────────────                                           │
│  • Apply minimum-disclosure: redact, mask, aggregate        │
│  • Return only what the context authorizes                  │
│  • Log every decision for audit (with hashed values only)   │
│  • Detect mosaic effects (combining safe data = unsafe)     │
│  • Never send raw PII to external LLMs or classifiers       │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    Safe AI Agent Response                    │
│      "John's compensation is in the $XX,XXX range.          │
│       Full details are available in the HR portal."         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔄 How It Works

### Step-by-Step Flow

1. **AI Agent Intercept** — When an AI agent (chatbot, copilot, automation) prepares to access or return data, it sends the request through ContextShield's API.

2. **Sensitive Data Classification** — ContextShield scans the data using a hybrid approach:
   - **Microsoft Presidio + spaCy** for NLP-based entity recognition (names, emails, phone numbers, SSNs)
   - **Deterministic rules** for domain-specific fields (salary, medical codes, financial accounts)
   - **Database schema annotations** as the trusted source of truth — if a column is marked `sensitivity: restricted`, that overrides any NLP result

3. **Context Analysis** — The system evaluates the full context:
   - **Requester identity** — verified server-side from JWT claims, never from user input
   - **Requester role & permissions** — looked up from the database (HR, manager, support, etc.)
   - **Stated purpose** — treated as an *untrusted claim* until validated against allowed scenarios
   - **Data sensitivity level** — matched against the requester's clearance

4. **Policy Evaluation** — Context is checked against information flow norms:
   - "HR managers MAY access salary data WHEN conducting performance reviews"
   - "Support agents MAY access customer phone numbers WHEN resolving active tickets"
   - "No one MAY access raw SSNs through the AI agent interface"

5. **Privacy Enforcement** — Based on the deterministic policy decision:
   - **ALLOW** — approved fields pass through (values already transformed where required)
   - **MASK** — value partially hidden (e.g. `****@example.com`)
   - **TOKENIZE** — value replaced with a stable opaque token
   - **GENERALIZE** — value coarsened (e.g. exact salary → range)
   - **AGGREGATE** — statistics only (`mean`, `median`, `count`, `range`); no rows
   - **BLOCK** — request denied before retrieval/model access, with safe reason codes
   - **ESCALATE** — human approval required (for example repeated aggregate disclosures)

   Overall decisions are `ALLOW`, `PARTIAL_ALLOW`, `BLOCK`, or
   `ESCALATION_NEEDED`. Policy conflict resolution is deterministic and
   deny-by-default.

6. **Audit Logging** — Every decision is logged with:
   - Request context (who, what, why, when)
   - Policy that was applied and its version
   - Decision, per-field actions, and reason codes
   - Transformation *types* only — **never raw values, credentials, tokens, or prompts**

7. **Mosaic Effect Detection** — ContextShield tracks what data has been disclosed across a session. Even if each individual disclosure is safe, the *combination* might not be:
   - Name + Department + Salary range → Could identify an individual
   - The system flags these compound risks and may require escalation

---

## 🏗️ Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────────────┐
│   Frontend   │────▶│   Backend    │────▶│     PostgreSQL       │
│  React/Vite  │◀────│   FastAPI    │◀────│  Users, Policies,    │
│  TypeScript  │     │   Python     │     │  Audit Logs, Data    │
└──────────────┘     └──────┬───────┘     └──────────────────────┘
                            │
                    ┌───────┴────────┐
                    │  ContextShield │
                    │    Engine      │
                    ├────────────────┤
                    │ ┌────────────┐ │
                    │ │ Classifier │ │  ← Presidio + spaCy + Rules
                    │ └─────┬──────┘ │
                    │ ┌─────▼──────┐ │
                    │ │  Context   │ │  ← Contextual Integrity
                    │ │  Analyzer  │ │
                    │ └─────┬──────┘ │
                    │ ┌─────▼──────┐ │
                    │ │ Privacy   │ │  ← Mask / Tokenize / Generalize
                    │ │   Guard    │ │     / Aggregate / Block / Escalate
                    │ └─────┬──────┘ │
                    │ ┌─────▼──────┐ │
                    │ │   Audit    │ │  ← Immutable decision log
                    │ │   Logger   │ │
                    │ └────────────┘ │
                    └────────────────┘
```

### Backend Architecture (Clean Layered Design)

| Layer | Responsibility | Example |
|-------|---------------|---------|
| **API Routes** (`api/v1/`) | HTTP request handling, input validation | `POST /api/v1/privacy/secure-request` |
| **Schemas** (`schemas/`) | Pydantic request/response models | `SecureRequestPayload`, `FieldDecision` |
| **Services** (`services/`) | Business logic, orchestration | `PolicyEngine`, `DataConnectorService`, `SafeLLMService` |
| **Repositories** (`repositories/`) | Database queries, data access | `UserRepository`, `PolicyRepository` |
| **Models** (`models/`) | SQLAlchemy ORM table definitions | `User`, `PrivacyPolicy`, `AuditEvent` |
| **Core** (`core/`) | Config, security, logging, middleware | JWT handling, structured logging |

---

## ✨ Key Features

### 🔍 Intelligent Data Classification
- **12 entity types** supported: names, emails, phone numbers, SSNs, addresses, dates of birth, salary, medical records, credit cards, bank accounts, passwords, API keys
- **4 sensitivity levels**: Low, Medium, High, Restricted
- **Hybrid detection**: NLP catches free-text PII; deterministic rules handle structured business data
- **Schema-first trust model**: Database annotations are authoritative — NLP is a signal, not a decision

### 🧠 Context-Aware Authorization
- Evaluates the full context tuple: *(sender, recipient, data type, purpose, transmission principle)*
- Supports predefined scenarios: HR salary review, department statistics, customer support, order status
- **Purpose verification**: User-claimed purposes are validated against server-side policy, never blindly trusted
- **Ambiguity handling**: Unclear requests trigger clarification prompts, not silent denials

### 🔒 Privacy Enforcement
- **Minimum disclosure principle**: Only the data necessary for the stated purpose is released
- **Deterministic enforcement actions**: Allow, Mask, Tokenize, Generalize, Aggregate, Block, Escalate — resolved with a deny-by-default conflict rule
- **Mosaic effect detection**: Tracks cumulative disclosures to prevent re-identification through data combination
- **No raw PII leaves the gateway**: external model providers (only when explicitly configured) receive approved, minimized context; blocked fields and raw records are never included. Classification and policy evaluation run locally.

> Decision semantics, mandatory protection floors, aggregate safeguards,
> tokenization, and policy administration:
> [`docs/policy-engine.md`](docs/policy-engine.md)

### 🤖 Safe AI Integration & Output Guard
- **Provider-independent LLM adapter**: deterministic mock provider by default; optional Gemini behind server-side configuration — the app runs fully offline without a paid API
- **Minimum-disclosure model context**: the model sees only authorized, post-transformation values — never raw PII, blocked fields, full tables, or unfiltered retrieval
- **Untrusted-data framing**: retrieved data and prompts can never override authorization, and injected instructions are detected before any model call
- **Second line of defense**: every model response is scanned for PII re-introduction and redacted, rejected, or escalated per policy — a guard failure never returns an unchecked response

> Provider configuration, guard modes, and fail-closed behaviour:
> [`docs/llm-integration.md`](docs/llm-integration.md)

### 📊 Audit & Explainability
- Every gateway decision — human or agent, granted or denied — is recorded immutably
- Queryable APIs: `GET /api/v1/audit/events` (+ `/{id}`) with filtering, pagination, and full explainability (reason codes, policy versions, transformation types, model-invocation and output-inspection outcome)
- Visibility-scoped server-side: admins see the full trail, compliance roles the privacy pipeline, everyone else only their own events
- Records are safe by construction — no raw PII, credentials, tokens, prompts, or model outputs

### 🖥️ React Demonstration Console
- Full frontend (`frontend/`) over the real API: login, dashboard (real aggregated metrics + charts), privacy request simulator, audit trail + explainability detail, policy viewer, data-asset catalogue, system status, and an SDK/integration page
- **No fake security UI**: the frontend never decides, redacts, or role-checks — every decision, mask, and audit entry is produced by the backend; blocked values never reach the browser
- Demo identity selector only prefills the login form with seeded accounts — authentication and role resolution stay server-side
- Authorization-aware rendering (scope banners, admin-only controls), loading/empty/error states everywhere, and fail-closed behaviour when the gateway is unreachable
- Playwright end-to-end journeys run against the real backend (login, simulate ALLOW/BLOCK, inspect the audit trail, session expiry, SDK page deep links, scope isolation)

> Console architecture, scripts, and E2E setup:
> [`frontend/README.md`](frontend/README.md)

### 🧩 Python SDK & Integration
- Typed, dependency-light Python SDK (`sdk/contextshield`, **v0.1.0**) over the same HTTP contract any language can call
- Credentials from environment variables or a credential provider — never hardcoded; configurable timeouts, typed errors, safe logging, mock-transport tests
- `BLOCK` / `ESCALATION_NEEDED` decisions arrive as first-class typed results with explicit handling (no exceptions required)
- Runnable integration examples: simple agent, tool/data connector, LLM pre-flight, full governed agent flow, ten-scenario DEVHOST demo, and generic non-Python HTTP
- Install in a clean environment: `pip install sdk` (from the repository); verified alongside the live gateway

> Integration contract, patterns, and the honest security boundary:
> [`docs/integration-guide.md`](docs/integration-guide.md) · runnable examples in
> [`examples/`](examples/)

### 🔐 Authentication & Authorization
- JWT-based authentication (HS256); tokens carry identity only — roles are re-resolved from the database on every request
- Server-side RBAC with reusable authorization services (resource, field, ownership, purpose checks)
- Service-account API keys for AI agents / backend services (`X-API-Key`) — client-supplied headers like `X-User-Id` are never trusted
- Secure password hashing with bcrypt; secrets only in environment variables
- Demo user seeding for development and testing
- Login throttling: failure-only sliding windows (per account+address and per address) with `429` + `Retry-After`

> Architecture, error semantics, service accounts, and React integration guidance:
> [`docs/authentication.md`](docs/authentication.md)

### 🛡️ Security Hardening & Verification
- Every response carries a server-generated `X-Request-ID` (correlation only — never accepted from the client)
- Structured-log sanitizer redacts sensitive keys (`password`, `token`, `api_key`, PII fields) before any log line is emitted
- All unhandled errors return a generic `500` body — exception messages (which can embed values) go only to the server-side log, as a class name + request id
- The mosaic brake is process-wide: repeated aggregate disclosures escalate across requests, not just within one
- Hostile input cannot break audit writes: identifiers are clamped to storage bounds at the repository boundary
- **Verification reports** — exact commands, pass/fail counts, scenario mapping, and remaining limitations:
  [`docs/verification-report.md`](docs/verification-report.md) ·
  [`docs/release-report.md`](docs/release-report.md)

---

## 🛠️ Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| **Backend API** | FastAPI (Python) | Async, auto-docs, Pydantic validation |
| **Database** | PostgreSQL 16 | ACID compliance, JSONB for flexible policies |
| **ORM** | SQLAlchemy 2.x (async) | Type-safe queries, Alembic migrations |
| **NLP / PII** | Microsoft Presidio + spaCy | Production-grade entity recognition |
| **Auth** | python-jose (JWT) + bcrypt | Industry-standard token auth |
| **Frontend** | React 19 + Vite + TypeScript + Tailwind CSS 4 | Fast dev experience, type safety |
| **Charts** | Recharts | Dashboard decision visualisation |
| **E2E tests** | Playwright | Critical journeys against the real backend |
| **Logging** | structlog | Structured, context-aware JSON logging |
| **Containers** | Docker + Docker Compose | Reproducible environments |
| **CI/CD** | GitHub Actions | Automated testing on every push |

---

## 📁 Project Structure

```
contextshield/
├── backend/
│   ├── app/
│   │   ├── api/v1/           # Versioned API route handlers
│   │   ├── core/             # Config, security, logging, middleware
│   │   ├── models/           # SQLAlchemy ORM models
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   ├── repositories/     # Database access layer (queries)
│   │   ├── services/         # Policy engine, classification, retrieval,
│   │   │                     #   transformations, LLM adapter, output guard, audit
│   │   ├── main.py           # FastAPI application entry point
│   │   ├── seed.py           # Idempotent synthetic demo seed
│   │   └── check_db.py       # Bounded database-readiness probe
│   ├── alembic/              # Database migration scripts
│   ├── tests/                # Backend unit & integration tests
│   ├── scripts/              # One-time database bootstrap SQL
│   ├── Dockerfile            # Non-root production image
│   ├── docker-entrypoint.sh  # Wait for DB → migrate → optional seed
│   └── requirements.txt
│
├── frontend/
│   ├── src/                  # React + TypeScript console (pages, components, API)
│   ├── e2e/                  # Playwright journeys against the real backend
│   ├── Dockerfile            # Vite dev-server image used by compose
│   ├── vercel.json           # SPA deep-link rewrite for static hosting
│   └── package.json
│
├── sdk/
│   ├── contextshield/        # Typed Python client (v0.1.0, py.typed)
│   └── tests/                # Mock-transport tests + opt-in live tests
│
├── examples/                 # Agent integrations + DEVHOST demonstration
├── docs/                     # Architecture, security, API, deployment, reports
├── database/                 # Reserved placeholder (seed lives in backend/app/seed.py)
├── policies/                 # Reserved placeholder (policies are seeded from code)
├── tests/                    # Reserved placeholder (suites live in backend/, sdk/, frontend/e2e)
│
├── .github/workflows/ci.yml  # GitHub Actions: backend, SDK, frontend, E2E
├── .env.example              # Safe environment template
├── docker-compose.yml        # PostgreSQL + backend + frontend
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

| Requirement | Minimum Version |
|-------------|----------------|
| Python | 3.12+ |
| Node.js | 20 LTS+ |
| PostgreSQL | 16+ |
| Docker Desktop | Latest (optional) |

### 1. Clone the Repository

```bash
git clone https://github.com/yashinkumar192006/DevDynamos.git
cd DevDynamos
```

### 2. Configure Environment

```powershell
Copy-Item .env.example .env
# Set DATABASE_URL and a long random JWT_SECRET in .env.
# Backend secrets stay in .env; frontend overrides go in frontend/.env.local.
```

`.env.example` contains placeholders only. Never commit `.env`, provider keys,
or real credentials.

### 3. Database Setup

ContextShield uses PostgreSQL with a **dedicated non-superuser account**
(`contextshield_app`). One-time bootstrap, as a PostgreSQL superuser:

```powershell
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -h localhost -d postgres `
    -f backend\scripts\create_database.sql
```

Then (from `backend/`):

```powershell
python -m alembic upgrade head     # create the schema
python -m app.check_db             # verify connectivity
python -m app.seed                 # insert synthetic demo data (idempotent)
```

> Full instructions, verification steps, and recovery procedures:
> [`docs/database-setup.md`](docs/database-setup.md)

### 4. Backend Setup

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_sm   # NLP model; optional (rules still work)

# Start the API server
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`.

Swagger UI: `http://localhost:8000/docs` · ReDoc: `/redoc` · schema:
`/openapi.json`. Use **Authorize** with a login token (Bearer) or a
service-account key (`X-API-Key`) to call protected endpoints.

### 5. Frontend Setup

```powershell
cd frontend
npm install
npm run dev
```

The UI will be available at `http://localhost:5173` and talks to the
backend at `http://localhost:8000` (override with `VITE_API_BASE_URL` —
**origin only**, no `/api/v1`; see `frontend/.env.example`; frontend
environment files must never contain secrets).

Sign in with any seeded demo account (the login page offers one-click
prefill — credentials still go through the real login endpoint). A good
demo order: **Dashboard → Privacy Simulator (try the blocked scenarios) →
Audit Events → Policies → Data Assets → System Status → SDK & Integration**.

End-to-end journeys (requires the backend running with the seeded DB):

```powershell
npx playwright install chromium   # one-time
npm run e2e
```

### 6. Docker (Alternative — All Services)

```powershell
Copy-Item .env.example .env   # only if .env does not exist yet
docker compose up --build -d
docker compose ps
docker compose logs -f backend
```

Compose starts PostgreSQL (health-checked), the backend (waits for the DB,
applies Alembic migrations, then seeds synthetic demo data idempotently), and
the frontend. Services: UI `http://localhost:5173`, API
`http://localhost:8000`; override `DATABASE_PORT`, `BACKEND_PORT`, or
`FRONTEND_PORT` if they conflict. The frontend container receives **only**
`VITE_API_BASE_URL` — backend secrets are never injected into it. Set
`SEED_ON_START=false` to skip demo seeding.

`docker compose down` preserves the `pgdata` volume; `down -v` deletes the
local database and must be used only intentionally on throwaway data.

> Startup behavior, Render/Vercel deployment, migrations, and troubleshooting:
> [`docs/deployment.md`](docs/deployment.md)

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/api/v1/health` | Versioned health check |
| `GET` | `/api/v1/system/status` | System / provider status |
| `POST` | `/api/v1/auth/login` | Authenticate and receive JWT |
| `GET` | `/api/v1/auth/me` | Current user profile (roles + permissions) |
| `GET` | `/api/v1/auth/whoami` | Verified identity (user JWT or service API key) |
| `POST` | `/api/v1/auth/logout` | Audit-logged logout (client discards token) |
| `GET` | `/api/v1/admin/users` | List users — requires `admin` role/scope |
| `POST` | `/api/v1/privacy/secure-request` | Governed data request: policy evaluation, minimum-disclosure transforms, optional inspected model stage |
| `GET` | `/api/v1/audit/events` | Query the audit trail (visibility-scoped, filterable, paginated) |
| `GET` | `/api/v1/audit/events/{id}` | Full explainability for one recorded decision |
| `GET` | `/api/v1/dashboard/overview` | Real dashboard metrics aggregated from the visible audit trail |
| `GET` | `/api/v1/policies` | List active privacy policies (inactive history: admins only) |
| `GET` | `/api/v1/data/assets` | Data-asset catalogue with field classifications (metadata only) |

Interactive contract: Swagger UI at `/docs`, ReDoc at `/redoc`, raw schema at
`/openapi.json`. Authorize with a Bearer token from `/api/v1/auth/login` or a
service-account `X-API-Key`; login tokens expire after 30 minutes by default.
The OpenAPI schema is the authoritative path list.

### Example: Login

```powershell
$response = Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/v1/auth/login `
    -ContentType "application/json" `
    -Body '{"username": "sarah.chen", "password": "SarahHR@2024!"}'
$response.user.roles        # → hr_manager (resolved server-side)
$response.access_token      # → Bearer token for protected endpoints
```

### Example: Governed Secure Request

```powershell
$token = (Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/v1/auth/login `
    -ContentType "application/json" `
    -Body '{"username": "natalie.brooks", "password": "<seeded demo password>"}').access_token

$result = Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/v1/privacy/secure-request `
    -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" `
    -Body '{
      "resource": "order_records",
      "data_fields": ["order_id", "status"],
      "purpose": "order_status",
      "target_entity": "ORD0001"
    }'

$result.overall_decision   # → ALLOW
$result.fields             # per-field action + already-transformed values
$result.audit_id           # recorded audit event for this decision
```

**Blocked request (marketing intern requesting an individual salary):**

```json
{
  "overall_decision": "BLOCK",
  "fields": { "base_salary": { "action": "BLOCK", "value": null, "reason_code": "INSUFFICIENT_ROLE" } },
  "records": null,
  "retrieved": false,
  "llm_response": null,
  "audit_id": "…"
}
```

A `BLOCK` is an HTTP 200 **decision** — normal, enforced, and audited; only
malformed requests or credential failures are HTTP errors. The Python SDK
returns decisions as typed results (`result.blocked`), never as exceptions —
see [`docs/integration-guide.md`](docs/integration-guide.md).

---

## 🔬 Use Cases & Examples

### Use Case 1: HR Salary Review
An HR manager asks the AI assistant: *"What is John's current salary? I'm preparing his annual review."*

- **Classifier** detects `salary` → `FINANCIAL_PII` → sensitivity: `RESTRICTED`
- **Context Analyzer** verifies: requester = HR manager, purpose = performance review ✅
- **Policy** matches: "HR MAY access salary FOR performance reviews"
- **Result**: Salary disclosed. Audit log created.

### Use Case 2: Curious Colleague
A software engineer asks: *"Hey, what does Sarah in marketing make?"*

- **Classifier** detects `salary` → `FINANCIAL_PII` → sensitivity: `RESTRICTED`
- **Context Analyzer** verifies: requester = engineer, purpose = unspecified ❌
- **Policy** matches: No norm authorizes salary disclosure to peers
- **Result**: Request denied with explanation. Audit log created.

### Use Case 3: Customer Support
A support agent asks: *"I need the customer's phone number to call them about ticket #4521."*

- **Classifier** detects `phone_number` → `CONTACT_PII` → sensitivity: `HIGH`
- **Context Analyzer** verifies: requester = support agent, purpose = active ticket resolution ✅
- **Policy** matches: "Support MAY access contact info FOR active ticket resolution"
- **Result**: Phone number disclosed. Audit log created.

### Use Case 4: Mosaic Effect Detection
Over multiple queries, a user obtains: department → role → salary range → name.

- **Aggregator** tracks session disclosures
- **Mosaic detector** flags: combination of department + salary range + name = potential re-identification risk
- **Result**: Warning issued, escalation required for further queries.

### Run the full demonstration

```powershell
# Backend + seeded DB running; from the repository root:
python examples/devhost_demo.py       # 10 scenarios, expected vs actual
python examples/agent_full_flow.py    # full governed agent sequence + fail-closed
```

The DEVHOST runbook, recorded results, and browser walkthrough:
[`docs/devhost-demo.md`](docs/devhost-demo.md). The automated frontend
equivalent is `npm run e2e` in `frontend/`.

---

## 🔐 Security Principles

1. **Never trust the client** — All authorization decisions are made server-side. User-supplied purpose claims are validated, never blindly accepted.

2. **Schema annotations are authoritative** — Database field metadata (sensitivity levels, classifications) override NLP detection. NLP is a signal, not a decision-maker.

3. **Minimum disclosure** — Only the data strictly necessary for the verified purpose is released. When in doubt, block.

4. **Raw PII stays local** — Raw sensitive data is never sent to external LLMs, third-party classifiers, or any external API. Classification happens locally; a live model provider (only when configured) receives approved, minimized context after authorization and transformation. The default provider is an offline deterministic mock.

5. **Audit everything** — Every access decision is logged immutably. Audit records contain identifiers, reason codes, policy versions, and transformation types — never raw values, credentials, tokens, or prompts.

6. **Defense in depth** — Multiple layers of protection: authentication → role check → context validation → policy evaluation → minimum-disclosure transformations → output guard.

7. **Fail closed** — If context is ambiguous or a policy can't be resolved, the default action is **BLOCK**, never ALLOW.

---

## ✅ Verification & Release

| Area | Last result |
|---|---|
| Backend suite | 335 passed, 0 failed, 0 skipped |
| SDK suite (offline) | 32 passed, 2 skipped (opt-in live tests) |
| Clean-environment SDK install | PASS (`pip install sdk`, `pip check`, live request) |
| Frontend lint / type-check / production build | PASS |
| Playwright E2E (real backend) | 12 passed |
| Docker images | PASS (non-root, migrations + idempotent seed verified) |
| GitHub Actions CI | PASS — all four jobs (backend, SDK, frontend lint, Playwright E2E) |
| Deployment | **NOT DEPLOYED** — manual steps in `docs/deployment.md` |

Full evidence, PASS/FAIL/BLOCKED items, and known limitations:
[`docs/release-report.md`](docs/release-report.md) ·
[`docs/verification-report.md`](docs/verification-report.md).

---

## 👥 Team

**DevDynamos** — DEVHOST Hackathon 2026

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

# ContextShield — Development Roadmap

> **Version:** 1.1.0  
> **Status:** Reflects implemented Prompts 1–9 (backend, pipeline, audit APIs, SDK, examples)  
> **Last Updated:** 2026-10-19

---

## 1. Current State Assessment

### What Exists (as of 2026-10-19)

| Component                     | Status           | Details                                    |
|-------------------------------|------------------|--------------------------------------------|
| **Repository structure**      | ✅ Complete       | All directories, `.gitignore`, `.env.example` |
| **Docker Compose**            | ✅ Complete       | PostgreSQL + backend + frontend services   |
| **Backend Dockerfile**        | ✅ Complete       | Python 3.12, spaCy model download          |
| **CI pipeline**               | ✅ Complete       | GitHub Actions: backend tests + SDK tests + frontend lint |
| **FastAPI app skeleton**      | ✅ Complete       | Full versioned API: auth, admin, privacy pipeline, audit, system status |
| **Backend dependencies**      | ✅ Complete       | `requirements.txt` with all core deps      |
| **Frontend scaffold**         | ✅ Scaffold       | Vite + React + TypeScript default app      |
| **Backend modules**           | ✅ Complete       | Layered API / schemas / services / repositories / models |
| **Database models**           | ✅ Complete       | ORM models + Alembic migrations (`docs/database-design.md`) |
| **Alembic migrations**        | ✅ Complete       | Schema + audit actor-kind migration; upgrade/downgrade verified |
| **Authentication**            | ✅ Complete       | JWT + service-account API keys, server-side RBAC |
| **Classifier service**        | ✅ Complete       | Hybrid classifier (deterministic rules + optional NLP) |
| **Context analyzer**          | ✅ Complete       | Verified requester, purpose validation, injection flags |
| **Policy engine**             | ✅ Complete       | Deterministic norm-matched decisions + reason codes |
| **Data connector**            | ✅ Complete       | 12-step secure-request pipeline, fail-closed |
| **Transformer**               | ✅ Complete       | Mask/tokenize/generalize/aggregate with audit hashes |
| **LLM adapter**               | ✅ Complete       | Mock default; optional Gemini (server-side env only) |
| **Output guard**              | ✅ Complete       | Redact/reject/escalate; never returns unchecked output |
| **Audit service**             | ✅ Complete       | Polymorphic actors (user/service), scoped query APIs, explainability |
| **Privacy pipeline**          | ✅ Complete       | Blocked requests: no retrieval, no model call — always audited |
| **SDK**                       | ✅ Complete       | Typed `contextshield` client, packaging, tests (see `sdk/`) |
| **Frontend UI**               | 🔲 Not started   | Default Vite scaffold only                 |
| **E2E tests**                 | 🔲 Not started   | Backend integration suites complete; root `tests/` still empty |
| **Documentation**             | ✅ Complete       | All 9 specification documents + integration guide & runnable examples |

---

## 2. Implementation Phases

### Phase 1: Backend Foundation 🏗️

**Goal:** Establish the core backend infrastructure — database, authentication, configuration, and middleware.

| Task                                         | Priority | Estimated Effort | Dependencies |
|----------------------------------------------|----------|------------------|--------------|
| 1.1 Core config (`core/config.py`)           | P0       | 1h               | —            |
| 1.2 Database setup (`core/database.py`)      | P0       | 1h               | 1.1          |
| 1.3 Structured logging (`core/logging.py`)   | P0       | 1h               | 1.1          |
| 1.4 Middleware (`core/middleware.py`)         | P1       | 1h               | 1.1, 1.3     |
| 1.5 SQLAlchemy models (all tables)           | P0       | 3h               | 1.2          |
| 1.6 Alembic initial migration                | P0       | 1h               | 1.5          |
| 1.7 Security module (`core/security.py`)     | P0       | 2h               | 1.1          |
| 1.8 Auth routes (`api/v1/auth.py`)           | P0       | 2h               | 1.5, 1.7     |
| 1.9 System routes (`api/v1/system.py`)       | P1       | 1h               | 1.2, 1.3     |
| 1.10 Seed data script                        | P0       | 2h               | 1.5, 1.6     |
| 1.11 Backend tests for Phase 1               | P0       | 3h               | 1.8, 1.9     |

**Deliverables:**
- User can login with demo credentials and receive a JWT
- `/health`, `/api/v1/health`, `/api/v1/system/status` work
- Database has all tables and seed data
- Tests pass in CI

---

### Phase 2: Classification & Context 🔍

**Goal:** Implement sensitive data classification and context analysis.

| Task                                              | Priority | Estimated Effort | Dependencies |
|---------------------------------------------------|----------|------------------|--------------|
| 2.1 Classifier service (`classifier.py`)          | P0       | 4h               | 1.5          |
| 2.2 Context analyzer (`context_service.py`)       | P0       | 3h               | 1.5, 1.7     |
| 2.3 Classification schemas                        | P0       | 1h               | —            |
| 2.4 Context schemas                               | P0       | 1h               | —            |
| 2.5 Data asset seeding (field metadata)            | P0       | 1h               | 1.10         |
| 2.6 Tests for classifier (entity types, levels)   | P0       | 3h               | 2.1          |
| 2.7 Tests for context analyzer                    | P0       | 2h               | 2.2          |

**Deliverables:**
- Classifier identifies all 12 entity types and 4 sensitivity levels
- Context analyzer validates identity, purpose, and target
- Schema annotations override NLP results
- Comprehensive test coverage

---

### Phase 3: Policy Engine & Data Layer 📋

**Goal:** Implement the deterministic policy engine, authorized data connector, and minimum-disclosure transformer.

| Task                                              | Priority | Estimated Effort | Dependencies |
|---------------------------------------------------|----------|------------------|--------------|
| 3.1 Policy engine (`policy_engine.py`)            | P0       | 4h               | 2.1, 2.2     |
| 3.2 Policy repository (`policy_repo.py`)          | P0       | 2h               | 1.5          |
| 3.3 Seed initial policy norms                     | P0       | 2h               | 1.10, 3.2    |
| 3.4 Data connector (`data_connector.py`)          | P0       | 3h               | 3.1          |
| 3.5 Employee repository (`employee_repo.py`)      | P0       | 2h               | 1.5          |
| 3.6 Customer repository (`customer_repo.py`)      | P0       | 1h               | 1.5          |
| 3.7 Order repository (`order_repo.py`)            | P0       | 1h               | 1.5          |
| 3.8 Transformer (`transformer.py`)                | P0       | 4h               | 3.1          |
| 3.9 All MASK/TOKENIZE/GENERALIZE/AGGREGATE impls  | P0       | 3h               | 3.8          |
| 3.10 k-anonymity threshold enforcement            | P0       | 1h               | 3.9          |
| 3.11 Mosaic effect detector                       | P1       | 3h               | 3.8          |
| 3.12 Tests for policy engine                      | P0       | 3h               | 3.1          |
| 3.13 Tests for transformer (all 7 actions)        | P0       | 3h               | 3.8          |
| 3.14 Tests for fail-closed behavior               | P0       | 1h               | 3.1          |

**Deliverables:**
- Policy engine evaluates norms with priority resolution
- Data connector fetches only permitted fields
- Transformer applies all 7 decision types
- Fail-closed default on all error paths
- k-anonymity threshold enforced for AGGREGATE

---

### Phase 4: Privacy Pipeline & Secure Request ⭐

**Goal:** Wire the full pipeline together and implement the core `POST /api/v1/privacy/secure-request` endpoint.

| Task                                              | Priority | Estimated Effort | Dependencies |
|---------------------------------------------------|----------|------------------|--------------|
| 4.1 Pipeline orchestrator (`pipeline.py`)         | P0       | 3h               | 3.1–3.8      |
| 4.2 Privacy route (`api/v1/privacy.py`)           | P0       | 2h               | 4.1          |
| 4.3 Request/response schemas                      | P0       | 1h               | —            |
| 4.4 Audit service (`audit_service.py`)            | P0       | 2h               | 1.5          |
| 4.5 Audit repository (`audit_repo.py`)            | P0       | 1h               | 1.5          |
| 4.6 Audit route (`api/v1/audit.py`)               | P1       | 2h               | 4.4          |
| 4.7 Policy listing route (`api/v1/policies.py`)   | P1       | 1h               | 3.2          |
| 4.8 Dashboard route (`api/v1/dashboard.py`)       | P2       | 2h               | 4.4          |
| 4.9 Data assets route (`api/v1/data.py`)          | P2       | 1h               | 2.5          |
| 4.10 Integration tests: all 14 demo scenarios     | P0       | 4h               | 4.1–4.7      |
| 4.11 Security tests (auth bypass, role escalation)| P0       | 2h               | 4.2          |

**Deliverables:**
- Full privacy pipeline working end-to-end
- All 11 API endpoints functional
- All 14 demo scenarios pass as integration tests
- Audit trail is complete and queryable

---

### Phase 5: LLM Integration 🤖

**Goal:** Implement the LLM adapter, safe context builder, and output privacy guard.

| Task                                              | Priority | Estimated Effort | Dependencies |
|---------------------------------------------------|----------|------------------|--------------|
| 5.1 LLM adapter interface (`llm_adapter.py`)     | P0       | 2h               | —            |
| 5.2 Mock LLM provider                            | P0       | 2h               | 5.1          |
| 5.3 Safe AI context builder                       | P0       | 2h               | 4.1          |
| 5.4 Output privacy guard (`output_guard.py`)      | P0       | 3h               | 2.1          |
| 5.5 Gemini API provider (optional)                | P2       | 3h               | 5.1          |
| 5.6 Update pipeline to include LLM path           | P0       | 2h               | 5.1–5.4      |
| 5.7 Tests for output guard (PII detection in LLM) | P0      | 3h               | 5.4          |
| 5.8 Test scenario S14 (guard trigger)             | P0       | 1h               | 5.6          |

**Deliverables:**
- Mock LLM produces deterministic, testable responses
- Output guard detects and redacts PII in LLM output
- Optional Gemini integration behind feature flag
- S14 (LLM output with leaked PII) passes

---

### Phase 6: Python SDK 📦

**Goal:** Create the reusable Python SDK that wraps the REST API.

| Task                                              | Priority | Estimated Effort | Dependencies |
|---------------------------------------------------|----------|------------------|--------------|
| 6.1 SDK client class (`sdk/contextshield/client.py`) | P0    | 3h               | 4.2          |
| 6.2 SDK data models (`sdk/contextshield/models.py`)  | P0    | 2h               | —            |
| 6.3 SDK exceptions (`sdk/contextshield/exceptions.py`)| P0   | 1h               | —            |
| 6.4 SDK packaging (`setup.py` / `pyproject.toml`)    | P1    | 1h               | 6.1–6.3     |
| 6.5 SDK tests                                    | P0       | 2h               | 6.1          |
| 6.6 SDK usage examples                           | P1       | 1h               | 6.5          |

**Deliverables:**
- Installable SDK package
- All SDK methods tested
- Usage examples in `examples/` directory

---

### Phase 7: Frontend Dashboard 🖥️

**Goal:** Build the React demonstration frontend.

| Task                                              | Priority | Estimated Effort | Dependencies |
|---------------------------------------------------|----------|------------------|--------------|
| 7.1 Install frontend dependencies (Tailwind, Axios, etc.) | P0 | 1h            | —            |
| 7.2 API client service (Axios wrapper)            | P0       | 2h               | —            |
| 7.3 Auth context & protected routes               | P0       | 2h               | 7.2          |
| 7.4 Login page                                    | P0       | 2h               | 7.3          |
| 7.5 Dashboard overview page (Recharts)            | P0       | 4h               | 7.2          |
| 7.6 Secure request test page                      | P0       | 4h               | 7.2          |
| 7.7 Policy explorer page                          | P1       | 3h               | 7.2          |
| 7.8 Audit log browser page                        | P1       | 3h               | 7.2          |
| 7.9 Audit event detail page                       | P1       | 2h               | 7.8          |
| 7.10 Data assets page                             | P2       | 2h               | 7.2          |
| 7.11 Responsive layout & polish                   | P1       | 3h               | 7.4–7.10    |
| 7.12 Frontend Dockerfile                          | P1       | 1h               | —            |

**Deliverables:**
- Login flow with demo user selection
- Dashboard with live metrics (Recharts)
- Interactive "Test Request" page showing per-field decisions
- Audit log browser with detail views
- Policy explorer
- Responsive, polished design

---

### Phase 8: Testing & CI/CD 🧪

**Goal:** Comprehensive test coverage and CI/CD pipeline.

| Task                                              | Priority | Estimated Effort | Dependencies |
|---------------------------------------------------|----------|------------------|--------------|
| 8.1 Backend unit test suite (≥80% coverage)       | P0       | 4h               | All backend  |
| 8.2 Backend integration test suite                | P0       | 3h               | All backend  |
| 8.3 Security test suite                           | P0       | 3h               | All backend  |
| 8.4 Playwright E2E tests (key flows)              | P1       | 4h               | Phase 7      |
| 8.5 CI pipeline: add coverage reporting           | P1       | 1h               | 8.1          |
| 8.6 CI pipeline: add E2E test job                 | P2       | 2h               | 8.4          |
| 8.7 CI pipeline: Docker build verification        | P2       | 1h               | —            |

**Deliverables:**
- ≥80% backend test coverage
- All 14 demo scenarios as integration tests
- Security tests for all threats in the security model
- Playwright tests for login, request, and audit flows

---

### Phase 9: Documentation & Polish 📝

**Goal:** Finalize documentation, examples, and deployment readiness.

| Task                                              | Priority | Estimated Effort | Dependencies |
|---------------------------------------------------|----------|------------------|--------------|
| 9.1 Update README with current screenshots        | P1       | 1h               | Phase 7      |
| 9.2 API documentation review                      | P1       | 1h               | Phase 4      |
| 9.3 SDK documentation & examples                  | P1       | 1h               | Phase 6      |
| 9.4 Deployment guide                              | P2       | 1h               | Phase 8      |
| 9.5 Architecture diagram images                   | P2       | 1h               | —            |
| 9.6 Demo video recording                          | P2       | 2h               | Phase 7      |
| 9.7 Final security review                         | P0       | 2h               | All phases   |

---

## 3. Phase Dependencies

```text
Phase 1 (Foundation)
  ├── Phase 2 (Classification & Context)
  │     └── Phase 3 (Policy Engine & Data)
  │           └── Phase 4 (Pipeline & API) ⭐ Core milestone
  │                 ├── Phase 5 (LLM Integration)
  │                 ├── Phase 6 (SDK)
  │                 └── Phase 7 (Frontend)
  │                       └── Phase 8 (Testing & CI)
  └─────────────────────────────── Phase 9 (Docs & Polish)
```

---

## 4. Milestone Targets

| Milestone                          | Target   | Definition of Done                                    |
|------------------------------------|----------|-------------------------------------------------------|
| **M1: Backend boots & auth works** | Phase 1  | Login → JWT → protected endpoint → 200                |
| **M2: Classification pipeline**    | Phase 2  | 12 entity types classified correctly in tests         |
| **M3: Policy engine works**        | Phase 3  | Norms match, actions applied, fail-closed verified    |
| **M4: Core API complete**  ⭐     | Phase 4  | All 14 demo scenarios pass as integration tests       |
| **M5: LLM integration**           | Phase 5  | Mock LLM + output guard functional                    |
| **M6: SDK published**             | Phase 6  | `pip install -e ./sdk` works + tests pass             |
| **M7: Frontend demo**             | Phase 7  | Login → dashboard → test request → audit log          |
| **M8: Test coverage**             | Phase 8  | ≥80% coverage, E2E tests pass                         |
| **M9: Release-ready**             | Phase 9  | Docs complete, Docker works, demo video recorded      |

---

## 5. Risk Register

| Risk                                           | Impact | Likelihood | Mitigation                                          |
|------------------------------------------------|--------|------------|-----------------------------------------------------|
| Presidio/spaCy model download slows CI         | Medium | High       | Cache models in CI; pre-download in Dockerfile      |
| Policy engine edge cases cause false positives  | High   | Medium     | Exhaustive test scenarios; fail-closed is safe       |
| PostgreSQL connection issues in tests           | Medium | Medium     | Use SQLite for unit tests; PG for integration       |
| Frontend scope creep                           | Medium | High       | Frontend is demo only — minimal viable UI           |
| LLM hallucination volume overwhelms guard       | Low    | Low        | Mock LLM for demos; guard is best-effort v1         |
| Token expiry disrupts demo                     | Low    | Medium     | 30-min tokens; demo scripts handle re-auth          |

---

## 6. Technical Debt Tracking

| Item                                    | Phase | Notes                                    |
|-----------------------------------------|-------|------------------------------------------|
| SQLite fallback for tests               | 1     | Consider async SQLite driver or separate config |
| Refresh tokens                          | 1     | v1 uses re-login; add refresh in v2       |
| Rate limiting middleware                | 4     | Deferred to v2; document as known gap     |
| Differential privacy noise             | 3     | Deferred to v2; k-anonymity is v1 baseline |
| Policy authoring UI                     | 7     | Policies managed via seed scripts in v1    |
| Multi-tenant isolation                  | —     | Out of scope for v1                        |
| Streaming LLM responses                | 5     | Out of scope for v1                        |

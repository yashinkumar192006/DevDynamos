# ContextShield — Final Release Report

> **Prompt:** 12 of 12 — repository integrity, SDK, integration example, API/frontend completion, database/config/deployment readiness, DEVHOST demonstration, documentation, verification, release.
> **Date:** 2026-10-20
> **Revision:** `09e479d` (release commit pushed to `origin/main`; GitHub Actions run `39384448875` passed). This document was corrected in a docs-only follow-up to record the hosted CI result.
> **Release position:** **Release-ready for a local/DEVHOST demonstration. Not deployed. Not production-certified.**
> Verification proves the properties below on the tested revision and environment; it does not prove the absence of vulnerabilities.

---

## 0. Verdict at a glance

| Question | Answer |
|---|---|
| Is the repository complete and internally consistent? | **Yes** — see §1. Actual test, seed, and E2E locations are documented; empty root placeholders are labelled as such. |
| Does the Python SDK exist, install, and work? | **Yes** — `contextshield` 0.1.0, typed, clean-environment install verified, live gateway request PASS. See §2. |
| Is there a complete agent integration example? | **Yes** — `examples/agent_full_flow.py` (authorized, blocked, injection, gateway-outage fail-closed). See §3. |
| Is the API/Swagger complete and verified? | **Yes** — `/docs` and `/openapi.json` return HTTP 200 with the real route list. See §4. |
| Does the frontend show the real decisions? | **Yes** — 12 Playwright journeys against the real backend; blocked values never rendered. See §5. |
| Is the database initialization/recovery documented? | **Yes** — bootstrap, migrations, idempotent seed, backup, safe migration, and explicit destructive-reset warnings. See §6. |
| Are configuration and LLM providers handled safely? | **Yes** — mock default, server-side Gemini only, output guard, fail-closed. See §7. |
| Are Docker/CI/deployment paths present? | **Yes** — images and compose stack verified; GitHub Actions CI passed all four jobs; Render/Vercel runbook written. Hosted deployment did **not** run. See §8. |
| Is the ten-scenario DEVHOST demo demonstrated? | **Yes** — 9 automated scenarios PASS, browser step covered manually + by Playwright. See §9. |
| Is the documentation complete? | **Yes** — 23 Markdown files, all relative links resolve. See §10. |
| Were tests weakened or results invented? | **No.** No test was deleted or relaxed; all failures found were fixed and re-run. See §1.3 and §11. |
| Was anything committed, pushed, or deployed? | **Yes for commit/push, no for deployment.** Release commit `09e479d` was pushed to `origin/main`; GitHub Actions passed. No remote application, database, or paid resource was created. |

---

## 1. A — Repository integrity

### 1.1 What is actually here

```
backend/        FastAPI app, Alembic migrations, 335-test suite, non-root Docker image
frontend/       React 19 console, Playwright E2E (12), Vite dev image, Vercel rewrite
sdk/            typed Python client 0.1.0 + offline/live tests
examples/       4 integration examples + full-flow + DEVHOST runner + HTTP guide
docs/           18 documents (architecture, security, API, DB, deployment, reports)
database/       reserved placeholder only (`.gitkeep`)
policies/       reserved placeholder only (`.gitkeep`)
tests/          reserved placeholder only (`.gitkeep`)
```

The real locations — which the README and all docs now use — are:

| Concern | Real location |
|---|---|
| Backend tests | `backend/tests/` |
| Browser E2E | `frontend/e2e/` |
| Demo seed | `backend/app/seed.py` (`python -m app.seed`) |
| Policy definitions | seeded by `backend/app/seed.py`; evaluated by `backend/app/services/policy_engine.py` |
| Database bootstrap | `backend/scripts/create_database.sql` + Alembic |
| SDK | `sdk/contextshield/` |

The three empty root directories are documented as reserved placeholders rather
than presented as working components.

### 1.2 No rebuild; working code preserved

The project was extended in place. No existing test was deleted or skipped to
obtain a pass. The only test-infrastructure modification is the autouse state
reset in `backend/tests/conftest.py` (required because the mosaic guard and
login throttles are deliberately process-wide). Frontend assets removed during
the Prompt 10 console redesign are unrelated to tests or security controls.

The repository working tree contains the Prompt 10–12 additions (frontend
console, audit/policy/dashboard APIs, verification suites, Docker/CI hardening,
SDK page, examples, docs). **They were committed as `09e479d` and pushed to
`origin/main`; nothing was deployed.**

### 1.3 Document ↔ implementation reconciliation

Documents were corrected to match behavior, not the other way round:

| Claim found in docs | Reality, now documented |
|---|---|
| `POST /api/v1/analyze` example | Actual core route: `POST /api/v1/privacy/secure-request` |
| `REDACT` / `DENY` enforcement actions | Actual: `ALLOW`, `MASK`, `TOKENIZE`, `GENERALIZE`, `AGGREGATE`, `BLOCK`, `ESCALATE`; overall decisions `ALLOW`/`PARTIAL_ALLOW`/`BLOCK`/`ESCALATION_NEEDED` |
| Error body `{"detail": …}` | `{"error": {"type", "detail"}}` |
| JWT claim `role` | Identity-only claims; roles re-resolved per request; `typ` claim enforced |
| Passlib / argon2 | bcrypt via the `bcrypt` package |
| SSE decision stream | Not implemented and no longer claimed |
| `VITE_API_BASE_URL=http://localhost:8000/api/v1` | Origin only; the client appends `/api/v1/...` |
| "Zero external data transfer" | Raw PII never leaves the gateway; approved, minimized context may reach an explicitly configured provider |
| Seed/tests in empty root folders | Actual paths listed above |
| API design "Draft — pre-implementation" | Marked implemented and reconciled with `/openapi.json` |

---

## 2. B — Python SDK

Package: **`contextshield` 0.1.0 (Alpha)**, typed (`py.typed`), Python ≥ 3.10,
single runtime dependency `httpx>=0.24`, prepared for a registry but **not
published**. Source: `sdk/`.

### 2.1 The ten verified properties

| # | Property | Evidence | Status |
|---|---|---|---|
| 1 | Installable, versioned distribution with correct metadata | `pip install sdk` in a fresh venv; `importlib.metadata.version` → `0.1.0`; `py.typed` present | PASS |
| 2 | Explicit configuration (`base_url`, timeouts, retries) and `from_env()` | Live/offline tests; no hardcoded credentials | PASS |
| 3 | Three authentication modes | API key (`X-API-Key`), bearer token, username/password lazy login with token cache and one re-login on expiry | PASS |
| 4 | Typed secure-request API | `SecureRequestResult`, `FieldDecision`, `LLMInfo`, guard models; session/context convenience kwargs | PASS |
| 5 | Normal decision handling | `BLOCK`/`ESCALATION_NEEDED` returned as typed results, not raised; opt-in `raise_if_blocked()` / `raise_for_escalation()` | PASS |
| 6 | Minimum-disclosure access | `granted_values()` contains only approved/transformed values; blocked fields carry no value | PASS |
| 7 | Audit access | Typed event list/detail/pagination models, visibility-scoped server-side | PASS |
| 8 | Typed failure model | Validation/auth/permission/not-found/gateway/timeout/invalid-response errors; raw `httpx` exceptions never escape (including password login) | PASS |
| 9 | Safe logging and controlled retries | Method/path/status/duration/request id only — no headers/bodies/credentials; retries limited to transport errors | PASS |
| 10 | Tested independently of a live gateway | 32 offline tests via `httpx.MockTransport` + 2 opt-in live tests, both live tests executed and passed | PASS |

### 2.2 Clean-environment verification (real commands)

```powershell
python -m venv $env:TEMP\opencode\cs-sdk-clean
& "$env:TEMP\opencode\cs-sdk-clean\Scripts\python.exe" -m pip install C:\CONTEXTSHIELD\sdk
& "$env:TEMP\opencode\cs-sdk-clean\Scripts\python.exe" -m pip check
& "$env:TEMP\opencode\cs-sdk-clean\Scripts\python.exe" <smoke-script>
```

Observed:

```
distribution: 0.1.0
module:       0.1.0  (...\site-packages\contextshield\__init__.py)
py.typed:     True
gateway health: ok
decision:     ALLOW
request_id:   True
audit_id:     True
granted_fields: ['order_id', 'status']
pip check:    No broken requirements found.
```

### 2.3 SDK suite

```
cd sdk
..\backend\.venv\Scripts\python.exe -m pytest tests -q
→ 32 passed, 2 skipped in 0.53s   (skips = opt-in live tests)

live gateway:
→ 2 passed
```

The two login transport-error regression tests added in Prompt 12 prove that a
down or slow gateway during password authentication raises
`GatewayUnavailableError` / `RequestTimeoutError`, not a raw `httpx` exception.

---

## 3. C — Agent integration examples

| File | What it demonstrates | Last run |
|---|---|---|
| `examples/agent_full_flow.py` | Intent → SDK → verified identity/policy → retrieval → transformations → approved context → mock LLM → output guard → answer; a blocked request containing a prompt-injection string; an unreachable-gateway check that fails closed | **PASS**, exit 0 |
| `examples/devhost_demo.py` | Ten-scenario DEVHOST demonstration with expected vs actual output | **PASS**, 9 automated + 1 manual browser step |
| `examples/demo_end_to_end.py` | Blocked and allowed customer flows + audit trail | **PASS** |
| `examples/simple_agent.py` | One protected lookup wrapped by the gateway | **PASS** |
| `examples/tool_connector_agent.py` | Agent tool/connector wrapped by the gateway | **PASS** |
| `examples/llm_precheck_agent.py` | Gateway pre-flight before the agent's own LLM | **PASS** |
| `examples/http/README.md` | curl / JavaScript / PowerShell for non-Python agents | Documentation verified |

`agent_full_flow.py` deliberately distinguishes:

* **Authorized** — fields released with policy provenance, model invoked, guard
  outcome recorded, audit id returned.
* **Blocked** — `retrieved=False`, no records, `llm=None`,
  `llm_response=None`, no granted values; the agent refuses.
* **Provider failure / guard withholding** — the helper uses the guarded
  `llm_response` when present; otherwise it degrades to **approved field values
  only**. It never falls back to direct database/vendor access.
* **Gateway unavailable** — typed exception; the agent states it cannot answer
  and does not bypass the gateway.

The honest boundary is documented in `docs/integration-guide.md` §7 and in the
example itself: a data source that can be reached without the gateway is
outside ContextShield's enforcement. The gateway is not a substitute for
database permissions or network isolation.

---

## 4. D — API and Swagger verification

| Check | Result |
|---|---|
| `GET /docs` | **HTTP 200** (Swagger UI) |
| `GET /redoc` | **HTTP 200** (ReDoc) |
| `GET /openapi.json` | **HTTP 200**, parses |
| `/api/v1/health`, `/health` | **200** `{"status":"ok"}` |
| Login → protected request | **PASS** (Bearer), service-account `X-API-Key` covered by tests |
| Error envelope | `{"error":{"type","detail"}}` verified by tests |
| Decision semantics over HTTP | ALLOW/PARTIAL_ALLOW/BLOCK/ESCALATION_NEEDED all covered by the backend suite |

Actual OpenAPI paths:

```
/health
/api/v1/health
/api/v1/system/status
/api/v1/auth/login
/api/v1/auth/logout
/api/v1/auth/me
/api/v1/auth/whoami
/api/v1/admin/users
/api/v1/privacy/secure-request
/api/v1/audit/events
/api/v1/audit/events/{event_id}
/api/v1/dashboard/overview
/api/v1/policies
/api/v1/data/assets
```

Usage (Authorize, login, Try it out) is documented in
`docs/api-design.md` §1 and the README. There is no SSE/streaming endpoint and
none is claimed.

---

## 5. E — Frontend completion

| Route | Purpose | Backed by |
|---|---|---|
| `/login` | Authentication + demo identity prefill | `POST /api/v1/auth/login` |
| `/dashboard` | Metrics/charts/recent decisions/provider health | `GET /api/v1/dashboard/overview` |
| `/simulator` | Request builder + scenarios + full decision result | `POST /api/v1/privacy/secure-request` |
| `/audit`, `/audit/:id` | Scope-aware trail + explainability detail | audit endpoints |
| `/policies` | Active policy viewer (admin may include history) | `GET /api/v1/policies` |
| `/assets` | Data assets and field classifications | `GET /api/v1/data/assets` |
| `/system` | Provider/database/classifier status | system status + health |
| `/sdk` | SDK installation, auth, examples, decision semantics, integration boundary | static; displays public `VITE_API_BASE_URL` |
| `/unauthorized`, `*` | 403 / 404 | — |

* **All decision types** are rendered by real backend data: `ALLOW`,
  `PARTIAL_ALLOW`, `BLOCK`, `ESCALATION_NEEDED` (badges, dashboard summary,
  simulator result, audit detail, SDK documentation).
* The browser never authorizes, redacts, or role-checks. Blocked values do not
  reach it; the BLOCK response contains `value: null`, no records, and no model
  output.
* The demo identity selector only prefills the login form. Roles are always
  resolved server-side.
* Only `VITE_API_BASE_URL` is read from the environment (origin, no `/api/v1`);
  the production bundle was scanned for backend secrets — none found.
* The white-page report was reproduced as a **serving-configuration** issue,
  not an application defect; supported modes are documented in
  `frontend/README.md` and `docs/deployment.md`.

Quality gates (final):

```
npm run lint        → 0 errors (pre-existing warnings only)
npm run type-check  → clean
npm run build       → success (683 modules)
npm run e2e         → 12 passed in 46.4s (real backend, Chromium)
```

The 12 journeys cover login/session, HR ALLOW, intern BLOCK, customer
own-order vs cross-customer, audit trail/detail, policy/assets, dashboard
visibility, blocked-value absence, audit scope isolation, admin-only controls,
and the SDK page (deep link, refresh, no backend secrets in the DOM).

---

## 6. F — Database initialization and recovery

Verified against local PostgreSQL and a fresh Docker volume:

| Check | Result |
|---|---|
| Dedicated non-superuser role `contextshield_app` | PASS (`create_database.sql`) for local/managed PostgreSQL; the compose dev container bootstraps its own role (see note below) |
| Migrations from empty schema | PASS (Alembic reaches head on a fresh volume) |
| Idempotent seed | PASS — 11 users before and after two extra seed runs; no duplicates/deletions |
| Seed contents (synthetic) | 12 roles · 11 users · 5 assets / 35 fields · 12 policy rows (incl. history) · 28 employees · 10 customers · 20 orders · 8 documents |
| Readiness probe | `python -m app.check_db` exits non-zero on failure; prints host/db only |
| Backup/recovery | Documented (provider snapshot / `pg_dump`; downgrades are not backups) |
| Destructive resets | Explicitly marked local-only with warnings; nothing automatic deletes data |
| Volume safety | `docker compose down` preserves `pgdata`; `down -v` is flagged destructive |

Document: [`database-setup.md`](database-setup.md). The compose development
container bootstraps its role from `DATABASE_USER`/`DATABASE_PASSWORD`; that
role is the container's superuser and is not the production least-privilege
setup.

---

## 7. G — Configuration and LLM providers

* **Fail-closed defaults**: missing/invalid required settings stop startup;
  policy ambiguity returns BLOCK/ESCALATION, never ALLOW.
* **Provider model**: `LLM_PROVIDER=mock` by default (deterministic, offline,
  no key). `gemini` is optional and configured **only** server-side
  (`GEMINI_API_KEY`, `LLM_MODEL`). The browser never sees provider keys.
* **Ordering**: authorization and approved-context construction happen before
  any provider call; blocked requests make no model call (proved with an
  invocation-counting provider and audit `model_invoked=False`).
* **Output guard**: enabled by default (`redact`; `reject`/`escalate` modes
  available). Guard output is inspected before release; a guard failure never
  returns unchecked text.
* **Provider errors** return the authorized decision without model output
  (`llm_response=None`, error code in `llm`); they do not bypass privacy
  controls.
* **Secrets**: only `VITE_API_BASE_URL` is exposed to the frontend. `.env` is
  git-ignored; `.env.example` contains placeholders only. Docker compose injects
  backend secrets only into the backend service.
* **Live Gemini was not exercised** (no key provided; no external call was
  made). The mock/provider-failure paths are covered.

Documents: [`llm-integration.md`](llm-integration.md),
[`security-model.md`](security-model.md), [`.env.example`](../.env.example).

---

## 8. H — Docker, CI, and deployment

### Docker (verified locally)

* `backend/Dockerfile`: Python 3.12-slim, non-root uid 1000, health check,
  entrypoint waits for PostgreSQL → migrations → optional idempotent seed.
* `frontend/Dockerfile`: Vite dev server for compose; production uses the static
  build.
* `docker-compose.yml`: PostgreSQL 16 health-checked; backend depends on DB
  health; only public `VITE_API_BASE_URL` passed to the frontend; ports
  parameterized.
* `.dockerignore` files prevent `.env`, caches, `node_modules`, and secrets from
  entering images.
* Verification: both images build; on a fresh volume the backend applied
  migrations, seeded idempotently, and served `/health`; frontend returned
  HTTP 200; containers run as uid 1000; no `.env` copied.

### CI (hosted run PASS)

`.github/workflows/ci.yml` defines:

1. `backend-tests` — PostgreSQL service, migrations, seed, full pytest suite.
2. `sdk-tests` — editable SDK install + offline suite.
3. `frontend-lint` — `npm ci`, lint, type-check.
4. `frontend-e2e` — PostgreSQL + seeded backend + Playwright Chromium, with
   report upload on failure.

The same jobs were run locally. Release commit `09e479d` was pushed to
`origin/main`, and **GitHub Actions run
[`39384448875`](https://github.com/yashinkumar192006/DevDynamos/actions/runs/39384448875)
completed successfully**: `backend-tests`, `sdk-tests`, `frontend-lint`, and
`frontend-e2e` all passed.

### Deployment

Runbook: [`deployment.md`](deployment.md) (Render backend + managed PostgreSQL,
Vercel static frontend, SPA rewrites, CORS, migrations, troubleshooting, and a
security checklist).

**Status: NOT DEPLOYED.** No Render/Vercel resource, managed database, domain,
or paid service was created. Deployment requires the owner's authorization and
credentials.

---

## 9. I — DEVHOST demonstration

Command:

```powershell
cd backend
.\.venv\Scripts\python.exe ..\examples\devhost_demo.py
```

Recorded run (2026-10-20, session `devhost-3e6a1ea466`):

| # | Scenario | Expected | Actual | Status |
|---|---|---|---|---|
| 1 | Intern requests an individual salary | BLOCK / INSUFFICIENT_ROLE | BLOCK / INSUFFICIENT_ROLE | PASS |
| 2 | Blocked before retrieval/model | no retrieval, no records, no model | `retrieved=False`, `records=None`, `llm=None`, `llm_response=None` | PASS |
| 3 | HR manager requests the same salary | ALLOW through all gates | ALLOW; fields released; mock model invoked; guard `none`; audit id | PASS |
| 4 | Analyst aggregate statistics | ALLOW stats only; out-of-scope BLOCK | Engineering ALLOW/AGGREGATE (mean 94125.0, median 91500.0, count 8, range [42000.0, 138000.0]); Finance BLOCK/TRANSMISSION_VIOLATED | PASS |
| 5 | Customer reads another customer | BLOCK, no values | BLOCK/INSUFFICIENT_ROLE | PASS |
| 6 | Customer reads own order | ALLOW, approved fields only | ALLOW; order id/status/total only | PASS |
| 7 | Prompt injection in purpose detail | BLOCK/INJECTION_SUSPECTED, no model | BLOCK/INJECTION_SUSPECTED; `llm=None` | PASS |
| 8 | Audit trail | decisions/reason codes visible; blocked model_invoked False | 9 session events; blocked event `model_invoked=False`; detail opens | PASS |
| 9 | Python SDK against real backend | health ok; typed result | `health=ok`; ALLOW; request id | PASS |
| 10 | Frontend displays real decision | browser shows same decision | frontend served; browser walkthrough + Playwright 12/12 | MANUAL / Playwright PASS |

Evidence details, the browser walkthrough, and the reasons the “no model call”
claim is backed by a recording provider (not inferred) are in
[`devhost-demo.md`](devhost-demo.md).

---

## 10. J — Documentation

| Document | Contents |
|---|---|
| `README.md` | Overview, architecture, actual structure, setup, API, Docker, verification status, links |
| `docs/api-design.md` | Contract, error semantics, Swagger usage, actual endpoint list |
| `docs/architecture.md`, `database-design.md`, `classification.md` | System design |
| `docs/security-model.md`, `authentication.md`, `policy-engine.md`, `privacy-policies.md` | Trust boundaries, auth, deterministic policy, data classes |
| `docs/llm-integration.md` | Providers, approved context, output guard, failure behavior |
| `docs/integration-guide.md` | SDK, patterns, boundary, verification |
| `docs/database-setup.md` | Bootstrap, migrations, idempotent seed, backup, recovery, destructive-reset warnings |
| `docs/deployment.md` | Render/Vercel/compose, env vars, migrations, troubleshooting, checklist |
| `docs/devhost-demo.md` | Ten scenarios, recorded results, browser steps, evidence |
| `docs/verification-report.md` | Property-level verification, defects fixed, limitations |
| `docs/release-report.md` | This report |
| `frontend/README.md`, `sdk/README.md`, `examples/README.md` | Component-specific usage |
| `docs/demo-scenarios.md`, `development-roadmap.md`, `project-specification.md` | Demo catalogue and project context |

Link verification: **64 relative links across 23 Markdown files, 0 missing**
(script checked existence; external URLs were not fetched).

---

## 11. K — Verification matrix

Status vocabulary: **PASS**, **FAIL**, **NOT RUN**, **BLOCKED**. “Skipped by
design” is noted separately, not counted as a failure.

| Item | Command / evidence | Status |
|---|---|---|
| Backend full suite | `cd backend && python -m pytest tests -q` | **PASS** — 335 passed, 0 failed, 0 skipped |
| Security/hardening subset | `pytest tests/test_security_verification.py tests/test_hardening.py -q` | **PASS** — 29 passed |
| SDK offline suite | `cd sdk && pytest tests -q` | **PASS** — 32 passed, 2 skipped by design |
| SDK live gateway | `pytest tests/test_live_gateway.py -v` | **PASS** — 2 passed |
| SDK clean-env install | fresh venv + `pip install sdk` + live smoke | **PASS** |
| Python examples | `agent_full_flow.py`, `devhost_demo.py`, `demo_end_to_end.py`, `simple_agent.py`, `tool_connector_agent.py`, `llm_precheck_agent.py` | **PASS** |
| DEVHOST 10 scenarios | `devhost_demo.py` | **PASS** — 9 automated; step 10 manual (UI served) |
| Frontend lint/type/build | `npm run lint && npm run type-check && npm run build` | **PASS** (lint warnings only, pre-existing) |
| Frontend E2E | `npm run e2e` | **PASS** — 12 passed in 46.4s |
| Dependency audit | `npm audit` | **PASS** — 0 vulnerabilities |
| Swagger/OpenAPI | `/docs`, `/openapi.json` | **PASS** — HTTP 200; real paths confirmed |
| Docker image builds | `docker compose build backend frontend` | **PASS** |
| Compose stack, fresh volume | migrations, seed ×2, health, frontend HTTP, non-root | **PASS** |
| Seed idempotency | user count 11 before/after reruns | **PASS** |
| Secret scans | git grep for key/private-key patterns; frontend `dist` scan; env tracking check | **PASS** — only documented fake examples; `.env` ignored; no backend secrets in bundle |
| Documentation links | 64 relative links across 23 files | **PASS** |
| Hosted deployment (Render/Vercel/DB) | — | **NOT RUN** (not authorized; no resources created) |
| Live Gemini provider | — | **NOT RUN** (no key; no external call) |
| GitHub-hosted CI (commit `09e479d`) | [run `39384448875`](https://github.com/yashinkumar192006/DevDynamos/actions/runs/39384448875) | **PASS** — backend-tests, sdk-tests, frontend-lint, frontend-e2e |
| Docker on non-Windows runtimes | — | **NOT RUN** |
| Load/performance testing | — | **NOT RUN** |
| Coverage percentage (`--cov`) | — | **NOT RUN** |
| Production security certification / pen test | — | **NOT RUN** |
| **FAIL items** | — | **None** |
| **BLOCKED items** | — | **None** |

Skipped-by-design: the two SDK live tests skip unless
`CONTEXTSHIELD_LIVE_GATEWAY_URL` is set; they were executed separately and
passed. No other skips.

---

## 12. L — Final release position

### What can be claimed

* A working, locally verified privacy gateway with deterministic server-side
  authorization, minimum-disclosure transformations, audit explainability,
  agent SDK, integration examples, and a console that renders real decisions.
* Blocked requests do not retrieve protected rows and do not invoke a model
  (proved by invocation-counting provider tests and audit flags).
* Provider/guard failures never bypass privacy controls; gateway unavailability
  fails closed in the example agent.
* Repeatable initialization: migrations, idempotent synthetic seed, health
  checks, non-root Docker images, and a documented deployment path.
* The ten DEVHOST scenarios, with recorded expected/actual evidence.

### What cannot be claimed

* That the system is production-certified, penetration-tested, or free of
  vulnerabilities.
* That it has been deployed, or that Render/Vercel/managed PostgreSQL behavior,
  TLS, or production load has been verified.
* That a live external LLM (Gemini) was exercised.
* That coverage targets were measured.
* That the SDK is published to a package registry.
* That root `tests/`, `policies/`, or `database/seed/` contain working code;
  they are placeholders.

### Manual actions before a real deployment

1. Authorize deployment and provide Render/Vercel/managed-PostgreSQL access.
2. Set backend secrets (`DATABASE_URL`, `JWT_SECRET`, `CORS_ORIGINS`,
   optionally `GEMINI_API_KEY`) and frontend `VITE_API_BASE_URL` (origin only).
3. Run the pre-deploy migration; seed only a demo database.
4. Remove/disable the demo identity selector and demo accounts for real use.
5. Verify TLS, CORS, health, login, a real ALLOW, a real BLOCK, audit
   visibility, and provider failure behavior in the deployed environment.
6. Define audit retention/access review and a shared rate-limit store for
   multi-instance deployments.

### Working tree / release mechanics

Release commit `09e479d` is pushed to `origin/main`; GitHub Actions run
`39384448875` passed. A docs-only follow-up records that hosted result. No tag,
release, or deployment was performed.

---

## Appendix — exact final commands

```powershell
# Backend
cd backend
$env:DATABASE_URL='postgresql+asyncpg://contextshield_app:contextshield_pass@localhost:5432/contextshield'
$env:JWT_SECRET='dev-secret-key-change-me'
.venv\Scripts\python.exe -m pytest tests -q

# SDK offline + live
cd ..\sdk
..\backend\.venv\Scripts\python.exe -m pytest tests -q
$env:CONTEXTSHIELD_LIVE_GATEWAY_URL='http://localhost:8000'
$env:CONTEXTSHIELD_LIVE_USERNAME='natalie.brooks'
$env:CONTEXTSHIELD_LIVE_PASSWORD='NatalieCust@2024!'
..\backend\.venv\Scripts\python.exe -m pytest tests/test_live_gateway.py -v

# Examples (backend running, seeded DB)
cd ..\backend
.\.venv\Scripts\python.exe ..\examples\agent_full_flow.py
.\.venv\Scripts\python.exe ..\examples\devhost_demo.py

# Frontend
cd ..\frontend
npm run lint
npm run type-check
npm run build
npm run e2e

# Docker
cd ..
docker compose build backend frontend
docker compose up -d db backend frontend
docker compose down          # preserves volumes
```

# ContextShield — DEVHOST Demonstration

A repeatable, synthetic-data walkthrough of the complete privacy flow. Every
decision shown here is produced by the real FastAPI backend; the frontend only
renders what the backend returns. No decision is hardcoded in the browser.

> Run this against the local seeded demo database. Do not point it at a
> production database or real employee/customer data.

---

## 1. What the demonstration proves

```
Existing AI agent / browser
  → ContextShield SDK (or HTTP gateway)
  → verified identity + server-side RBAC
  → context analysis + deterministic policy evaluation
  → authorized data retrieval (or denial before retrieval)
  → minimum-disclosure transformations (mask/tokenize/generalize/aggregate)
  → approved model context
  → configured LLM (mock by default)
  → output privacy guard
  → approved decision / response
  → audit event
```

The agent in the demo never contacts the database or a model provider
directly. A client that bypasses the gateway gains nothing from
ContextShield — the protected data source must independently enforce access
controls (see the boundary in `docs/integration-guide.md` §7).

---

## 2. Prerequisites

| Component | Requirement |
|---|---|
| Backend | Running on `http://localhost:8000` with the migrated + seeded demo DB. |
| Frontend | Running on `http://localhost:5173` for the browser step. |
| Python | Backend virtualenv (has `httpx`) or an environment where `sdk` is installed. |
| Data | Synthetic seed only (`backend/app/seed.py`). |

Start the stack (two terminals):

```powershell
# Terminal 1 — backend
cd backend
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m app.seed
.\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000

# Terminal 2 — frontend
cd frontend
npm run dev -- --host
```

Optional full stack via Docker (migrations + seed automatic):

```powershell
docker compose up --build -d
```

---

## 3. Run the automated demonstration

From the repository root, using the backend environment (or any environment
with the SDK installed and the backend running):

```powershell
cd backend
.\.venv\Scripts\python.exe ..\examples\devhost_demo.py
```

The script uses the Python SDK for every secure request and prints expected vs
actual for each scenario. It exits non-zero if an automated check fails. The
seeded demo passwords are read from `examples/devhost_demo.py` (they are the
synthetic credentials from `backend/app/seed.py`, public by design).

### Results of the verification run (2026-10-20, local synthetic DB)

Session: `devhost-3e6a1ea466`

| # | Scenario | Expected | Actual | Status |
|---|---|---|---|---|
| 1 | Marketing intern requests an individual salary (`mia.torres`) | `BLOCK / INSUFFICIENT_ROLE` | `BLOCK / INSUFFICIENT_ROLE` | **PASS** |
| 2 | Blocked before retrieval and before model invocation | `retrieved=False`, `records=None`, `llm=None`, `llm_response=None` | identical; audit event `model_invoked=False` | **PASS** |
| 3 | HR manager requests the same salary (`sarah.chen`) | `ALLOW`, transformed fields, model call, guard, audit id | `ALLOW`; `employee_id=ALLOW`, `base_salary=ALLOW`; mock model invoked; guard `none`; audit id returned | **PASS** |
| 4 | Analyst aggregate salary statistics (`alex.kumar`) | Engineering: `ALLOW/AGGREGATE`, statistics only; Finance: `BLOCK` (department scope) | Engineering `ALLOW/AGGREGATE`: `mean=94125.0`, `median=91500.0`, `count=8`, `range=[42000.0,138000.0]`, `records=None`; Finance `BLOCK/TRANSMISSION_VIOLATED` | **PASS** |
| 5 | Customer requests another customer's contact data (`natalie.brooks`) | `BLOCK / INSUFFICIENT_ROLE`, no values | `BLOCK`; `contact_email=BLOCK/INSUFFICIENT_ROLE` | **PASS** |
| 6 | Customer requests their own order status | `ALLOW`, only approved order fields | `ALLOW`; `order_id=ORD0001`, `status=delivered`, `total_amount=15400.0` | **PASS** |
| 7 | Prompt injection in `purpose_detail` (`eve.johnson`) | `BLOCK / INJECTION_SUSPECTED`, no values, no model | `BLOCK/INJECTION_SUSPECTED`; `llm=None` | **PASS** |
| 8 | Audit trail records decisions and safe reason codes | session events visible; blocked event `model_invoked=False` | 9 events; blocked event found with `model_invoked=False`; detail opens | **PASS** |
| 9 | Python SDK submits to the actual backend | health ok; typed result with request id | `health=ok`; `ALLOW`; `request_id` returned | **PASS** |
| 10 | Frontend simulator displays the real backend decision | browser shows the same decision/audit reference | frontend served; browser step below; Playwright suite 12/12 passed | **MANUAL / Playwright PASS** |

The k-anonymity (`GROUP_TOO_SMALL`) and repeated-aggregate (`MOSAIC_RISK`)
controls are exercised by automated backend tests (V04); the seeded analyst
path above shows the department-scope disclosure control because the Finance
group is out of the analyst's scope.

### Evidence behind “no model call”

The live response cannot by itself prove a provider was never called (a
provider could have been called and its output discarded). The backend suite
proves it with a recording provider:

* `backend/tests/test_security_verification.py::test_v01_intern_cannot_retrieve_individual_salary`
  installs a provider that records every call and asserts `provider.calls == []`
  after a blocked request.
* The same assertion is made for the injection path (V07) and guard/pipeline
  tests.
* The audit event for the blocked demo request independently records
  `model_invoked=False`.

---

## 4. Browser walkthrough (scenario 10)

1. Open `http://localhost:5173`.
2. Sign in as `natalie.brooks` / `NatalieCust@2024!` (the demo selector only
   prefills the form; authentication happens against the backend).
3. Go to **Privacy Simulator**.
4. Choose **“Customer checks own order (allowed)”** → **Send secure request**.
   * Expected: result banner **ALLOW** with an audit reference; field decisions
     show the order fields returned by the backend.
5. Choose **“Customer probes another account (blocked)”** → **Send secure
   request**.
   * Expected: **BLOCK** with `INSUFFICIENT_ROLE`; no values and no records
     section are rendered.
6. Open **Audit Events** → select the newest event → verify the decision,
   reason codes, policy versions, and transformation types; no raw values.
7. Sign in as an **admin** to see the full trail (scope-aware views).
   Regular users see only their own events.
8. The **SDK & Integration** page documents installation and the integration
   boundary; it never displays backend secrets.

Automated equivalents (real API, no mocked frontend):

```powershell
cd frontend
npm run e2e
```

Covering tests in `frontend/e2e/journeys.spec.ts` and `security.spec.ts`:

* HR salary `ALLOW` and intern salary `BLOCK`.
* Customer own order `ALLOW` and cross-customer lookup `BLOCK`.
* Audit trail event + full detail.
* Policy and asset pages render backend data.
* Blocked decisions store no values in the browser.
* Audit isolation (own events vs admin full trail).
* Admin-only policy controls absent for regular users.
* SDK documentation page renders with no backend secrets.
* Deep-link navigation and refresh.

Last run: **12 passed in 51.1s**.

---

## 5. Reading the results safely

* The demo prints decisions, field actions, reason codes, and (synthetic)
  approved values. It does not print passwords, tokens, raw blocked values, or
  complete model prompts.
* Audit records contain identifiers, reason codes, policy versions, and
  transformation *types* — never raw values.
* Denials are normal outcomes (`HTTP 200` decision), not errors to retry
  around. Retrying with rephrased fields or a different purpose is visible in
  the audit trail and still evaluated by policy.
* The mock provider is deterministic and requires no API key. A configured
  live provider is used only for requests that already passed authorization and
  approved-context construction; its output is inspected before release.

---

## 6. Reset / repeat

* Re-running `python -m app.seed` is idempotent: no duplicates, no deletions.
* Re-running `examples/devhost_demo.py` creates new audit events under a new
  session; nothing is overwritten.
* Do not drop the database or delete volumes for a demo rerun. If you
  intentionally reset a **local** database, follow
  `docs/database-setup.md` §“Recovery & troubleshooting” and never do it against
  a deployment or production database.

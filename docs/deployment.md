# ContextShield — Deployment Guide

> **Status: NOT DEPLOYED.** This document contains the verified build/start
> procedure and the manual steps for Render (backend + managed PostgreSQL) and
> Vercel (frontend). No remote application, database, or paid resource was
> created, modified, or published during this project. Deployment requires your
> explicit authorization and your account credentials.

The project has been verified locally: backend suite, SDK suite, Playwright
journeys, production frontend build, Docker image builds, and a full
`docker compose` stack with a fresh PostgreSQL volume (migrations + seed +
health checks). Deployment-specific behavior (TLS, managed-DB latency, Render
or Vercel build minutes) is **not** verified until you run it.

---

## 1. Deployment shape

```
Browser ──HTTPS──▶ Vercel (static React build)
                        │  VITE_API_BASE_URL (public origin only)
                        ▼
                 Render Web Service (FastAPI + Uvicorn)
                        │  DATABASE_URL, JWT_SECRET, provider keys (server-side)
                        ▼
                 Render Managed PostgreSQL
```

* The frontend is a static SPA. It stores only a JWT returned by the real login
  endpoint; it never holds provider keys or database credentials.
* The backend is the only component that talks to PostgreSQL or an LLM
  provider. It enforces every decision server-side.
* Managed PostgreSQL must be reachable only by the backend (private/internal
  connection string where available).

---

## 2. Environment variables actually used

Backend (from `backend/app/core/config.py`; template in `.env.example`):

| Variable | Required | Notes |
|---|---|---|
| `ENVIRONMENT` | recommended | `production` for deployments (`development` default). |
| `DEBUG` | no | Keep `false` in production. |
| `DATABASE_URL` | **yes** | `postgresql+asyncpg://user:pass@host:5432/db`. `postgresql://` is accepted and upgraded to asyncpg. Use the provider's **internal** URL for the web service. |
| `JWT_SECRET` | **yes** | Long random value (32+ bytes). Rotating it invalidates all existing tokens. Never commit it. |
| `JWT_ALGORITHM` | no | `HS256` default. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | no | `30` default. |
| `AUTH_RATE_LIMIT_ENABLED` | no | `true` default. Failure-only login throttling, **per process** (see limitations). |
| `AUTH_RATE_LIMIT_MAX_FAILURES` | no | `10` default (per username + client address). |
| `AUTH_RATE_LIMIT_IP_MAX_FAILURES` | no | `50` default (per client address). |
| `AUTH_RATE_LIMIT_WINDOW_SECONDS` | no | `60` default. |
| `CORS_ORIGINS` | **yes** | Comma-separated allowed browser origins, e.g. `https://your-app.vercel.app`. Wildcards are not appropriate for credentialed APIs. |
| `LLM_PROVIDER` | no | `mock` (default, offline) or `gemini`. |
| `GEMINI_API_KEY` | only for live Gemini | Server-side only. Never put it in Vercel or any `VITE_*` variable. |
| `LLM_MODEL` | no | Optional model override, e.g. `gemini-2.5-flash`. |
| `LLM_TIMEOUT_SECONDS`, `LLM_MAX_RETRIES` | no | Provider timeout/retry controls. |
| `LLM_OUTPUT_GUARD_ENABLED`, `LLM_OUTPUT_GUARD_MODE` | recommended | Guard is enabled by default; `redact`, `reject`, or `escalate`. |
| `POLICY_*` | no | Deterministic policy floors (k-anonymity, mosaic window, mandatory categories). Defaults are safe; see `docs/policy-engine.md`. |
| `CLASSIFIER_*` | no | NLP settings. If spaCy/Presidio are unavailable, classification falls back to deterministic rules (never fails open). |

Frontend (Vercel or `frontend/.env.local`):

| Variable | Required | Notes |
|---|---|---|
| `VITE_API_BASE_URL` | **yes** | Backend **origin only**, e.g. `https://contextshield-api.onrender.com`. Do **not** append `/api/v1` — the client adds it. Public information by design. |

No other frontend variables are used. Never add `GEMINI_API_KEY`, `JWT_SECRET`,
database URLs, or any credential to a `VITE_*` variable: Vite inlines them into
the public bundle.

---

## 3. Backend on Render (manual steps)

1. **Create the database.** In Render, create a PostgreSQL instance (same
   region as the web service). Copy its **internal** connection string. Convert
   the scheme to `postgresql+asyncpg://` if Render shows `postgresql://`. Keep
   SSL parameters if provided.
2. **Create a Web Service** from this repository.
   * Runtime: **Python 3.12** (or deploy the Docker image).
   * Root directory: `backend`.
   * Build command:
     ```bash
     pip install -r requirements.txt && python -m spacy download en_core_web_sm
     ```
     (The spaCy model enables NLP classification. Omitting it degrades to
     deterministic rules by design, but shipping it matches local behavior.)
   * Pre-deploy command (runs once before the new instance receives traffic):
     ```bash
     python -m alembic upgrade head
     ```
   * Start command:
     ```bash
     uvicorn app.main:app --host 0.0.0.0 --port $PORT
     ```
     Render provides `$PORT`; do not hardcode `8000` for the native runtime.
   * Health-check path: `/health` (no authentication).
3. **Set environment variables** from §2. Minimum: `DATABASE_URL`,
   `JWT_SECRET`, `CORS_ORIGINS`, `ENVIRONMENT=production`. Keep
   `LLM_PROVIDER=mock` unless you have a valid Gemini key and want live calls.
4. **Migrations.** The pre-deploy command above is the normal path. If your
   plan does not support pre-deploy commands, run once from the Render shell:
   ```bash
   cd backend && python -m alembic upgrade head
   ```
   Do not run migrations concurrently from multiple replicas without a
   database-level migration lock; scale to one instance for the deploy, then
   scale out.
5. **Demo seed only (never for real data).** The synthetic seed is idempotent
   and intended for demos. From the Render shell:
   ```bash
   cd backend && python -m app.seed
   ```
   Do not run `app.seed` against a production database containing real records.
6. **Verify.**
   ```bash
   curl https://<service>.onrender.com/health
   curl https://<service>.onrender.com/api/v1/health
   ```
   Then sign in at `https://<service>.onrender.com/docs` (Authorize → login
   token) and call `GET /api/v1/system/status` to confirm database, classifier,
   and LLM provider health.
7. **Logs.** Use the Render log stream. Startup lines from
   `backend/docker-entrypoint.sh` (Docker path) show database wait, migration,
   and optional seed steps. Application logs are JSON-structured and redacted;
   raw exception text is not returned to clients.

### Docker on Render (optional)

The repository includes a production backend image (`backend/Dockerfile`) that:

* runs as a non-root user (uid 1000);
* waits for the database (`WAIT_FOR_DB=true`, bounded retries);
* applies migrations (`RUN_MIGRATIONS_ON_START=true`);
* optionally seeds (`SEED_ON_START=false` by default);
* exposes `/health` through a container health check.

Set Render's Docker command to respect its assigned port:

```bash
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

Do **not** enable `SEED_ON_START` for a production database.

---

## 4. Frontend on Vercel (manual steps)

1. Import the repository into Vercel.
2. Root directory: `frontend`.
3. Build command: `npm ci && npm run build`.
4. Output directory: `dist`.
5. Environment variable (Production and Preview): `VITE_API_BASE_URL` =
   backend **origin** (no trailing `/api/v1`).
6. SPA routing: deep links such as `/audit/aud-123` and `/sdk` must return
   `index.html`. The repository includes `frontend/vercel.json` with a rewrite
   to `/index.html`; static assets are still served from `/assets/*` first.
7. Set the backend's `CORS_ORIGINS` to the Vercel production URL (and preview
   URL if you need previews), for example:
   ```
   CORS_ORIGINS=https://contextshield.vercel.app
   ```
8. Redeploy after changing environment variables — Vite inlines
   `VITE_API_BASE_URL` at build time.
9. Verify login, dashboard metrics, simulator ALLOW/BLOCK, audit, and
   `/system` from the deployed URL.

The frontend production build was verified locally (`npm run build`, 683
modules, `dist/` generated). Vercel's build/runtime has not been exercised.

---

## 5. Local Docker Compose (verified)

Prerequisites: Docker Desktop running, `.env` created from `.env.example`.

```powershell
Copy-Item .env.example .env
# Edit .env: set a long random JWT_SECRET (and optionally CORS_ORIGINS)

docker compose up --build -d
docker compose ps
docker compose logs -f backend
```

What happens:

* PostgreSQL starts with a health check; the backend waits for it.
* The backend entrypoint applies `alembic upgrade head`.
* `SEED_ON_START` defaults to **true** in compose, so the synthetic demo data
  loads idempotently. Set `SEED_ON_START=false` to skip seeding.
* Compose overrides `DATABASE_URL` so the backend uses the `db` service
  (`postgresql+asyncpg://…@db:5432/contextshield`); the host value in `.env` is
  not used inside the compose network.
* The frontend receives **only** `VITE_API_BASE_URL`; backend secrets are not
  injected into that service.
* Ports default to `5432` (DB), `8000` (API), `5173` (UI). Override with
  `DATABASE_PORT`, `BACKEND_PORT`, `FRONTEND_PORT` when they conflict.
* `docker compose down` stops the stack and **preserves the `pgdata` volume**.
  `docker compose down -v` permanently deletes the database volume — use it
  only on a throwaway local environment.

> **Development-only database role:** the compose PostgreSQL container
> bootstraps one role from `DATABASE_USER`/`DATABASE_PASSWORD` (falling back to
> `postgres`), and that bootstrap role is the container's superuser. This is a
> local convenience. The dedicated least-privilege `contextshield_app` setup in
> `docs/database-setup.md` and the production checklist below apply to an
> installed or managed PostgreSQL instance; do not treat compose defaults as
> production hardening.

Images were built successfully in this environment:

| Image | Verified |
|---|---|
| `contextshield-backend:latest` | Build PASS; non-root uid 1000; migrations + idempotent seed on a fresh volume PASS. |
| `contextshield-frontend:latest` | Build PASS; Vite dev server returned HTTP 200. |

---

## 6. Applying migrations to an existing deployment database

1. **Back up first** (provider snapshot or `pg_dump`). Never rely on a
   downgrade as a backup.
2. Review the migration in `backend/alembic/versions/`; check for destructive
   operations (`DROP`, type narrowing, backfills).
3. Scale the API to one instance or stop writes.
4. Run:
   ```bash
   cd backend && python -m alembic upgrade head
   ```
5. Verify `python -m alembic current` shows `(head)` and `/api/v1/system/status`
   reports `database: healthy`.
6. Scale back out and watch logs/error rates.

Never run `alembic downgrade` against production data without a tested,
data-preserving plan. Never run the seed against production records.

---

## 7. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Backend exits at startup: validation error for `DATABASE_URL`/`JWT_SECRET` | Required env var missing. Set both in the hosting dashboard. |
| `password authentication failed` | URL/user/password mismatch or special characters not URL-encoded. |
| Database unreachable from the web service | Use the provider's internal URL and same region; check SSL parameters. |
| Login works but API calls fail with CORS | `CORS_ORIGINS` must exactly match the browser origin (scheme + host, no trailing slash). Redeploy/restart after changing it. |
| Deep links 404 on refresh | SPA rewrite missing; ensure `frontend/vercel.json` (or the host's rewrite) sends unknown paths to `index.html`. |
| API calls hit `/api/v1/api/v1/...` | `VITE_API_BASE_URL` includes `/api/v1`; use the origin only. |
| `/docs` loads but "Authorize" does not work | Log in via `POST /api/v1/auth/login`, then paste the `access_token` as a Bearer token in Swagger. Service accounts use `X-API-Key`. |
| Live Gemini requests fail but mock mode works | Check `GEMINI_API_KEY`, `LLM_PROVIDER=gemini`, provider egress, and `/api/v1/system/status`. Provider failure never bypasses privacy checks; the authorized decision returns without model output. |
| Login returns 429 | Failure-only throttling triggered; wait for `Retry-After`. Counters are per process. |
| 500 with a request id | Look up the `X-Request-ID` in server logs; responses never include stack traces or values. |

---

## 8. Security checklist before exposing the service

- [ ] `JWT_SECRET` is long, random, and stored only in the backend's secret store.
- [ ] `DEBUG=false`, `ENVIRONMENT=production`.
- [ ] `CORS_ORIGINS` is an explicit allowlist (no `*`).
- [ ] Database is not publicly reachable; the app uses a least-privilege role.
- [ ] `GEMINI_API_KEY` exists only in backend configuration; `VITE_*` variables contain no secrets.
- [ ] TLS terminates at the host; Uvicorn is not exposed directly.
- [ ] Migrations ran and `/api/v1/system/status` shows healthy components.
- [ ] Login throttling enabled (and understood to be per-process — use a shared store for multi-instance hardening).
- [ ] No production/employee data was seeded; the seed is synthetic only.
- [ ] Audit retention and access review are defined for your organization.
- [ ] Deployment authorization has been given by the project owner.

---

## 9. Manual actions still required

1. Provide deployment authorization and access to your Render/Vercel accounts.
2. Create the managed PostgreSQL instance and copy the internal URL.
3. Set backend/frontend environment variables and CORS origins.
4. Run the migration (pre-deploy or shell) and, only for a demo, the synthetic seed.
5. Verify the deployment with `/health`, `/docs`, and a sign-in.
6. Optionally configure a live Gemini key; otherwise keep `LLM_PROVIDER=mock`.

There is no deployed URL to report.

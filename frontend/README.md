# ContextShield Console (Frontend)

A React + Vite + TypeScript demonstration console for the ContextShield
privacy gateway. Every decision, transformation, and audit entry shown in
the UI is produced by the **real backend** — the browser never decides,
redacts, or role-checks anything, and blocked values never reach it.

## Pages

| Route            | Page                   | Backing API                            |
|------------------|------------------------|----------------------------------------|
| `/login`         | Login (+ demo identity prefill) | `POST /api/v1/auth/login`     |
| `/dashboard`     | Decision metrics + charts + recent decisions + provider health | `GET /api/v1/dashboard/overview` |
| `/simulator`     | Privacy request simulator (scenarios + request builder + full result) | `POST /api/v1/privacy/secure-request` |
| `/audit`         | Audit trail (filters, pagination, scope-aware) | `GET /api/v1/audit/events` |
| `/audit/:id`     | Full explainability for one event | `GET /api/v1/audit/events/{id}` |
| `/policies`      | Policy viewer (active; admin can include inactive) | `GET /api/v1/policies` |
| `/assets`        | Data assets & field classifications | `GET /api/v1/data/assets` |
| `/system`        | Provider/database/classifier status | `GET /api/v1/system/status` + `/api/v1/health` |
| `/sdk`           | SDK & integration documentation (static; public config only) | — (displays `VITE_API_BASE_URL`) |
| `/unauthorized`, `*` | 403 / 404 pages    | —                                      |

## Security model (what this app deliberately does *not* do)

- **No client-side authorization.** The demo identity selector only
  prefills the login form with seeded accounts; credentials go through the
  real login endpoint and roles come from the server. Nothing in the UI can
  grant a role or bypass the policy engine.
- **No fake data.** Empty states are explicit; statistics are aggregated by
  the backend from recorded audit events only.
- **No secrets in the bundle.** The only environment variable is
  `VITE_API_BASE_URL` (a public URL). Never put API keys, tokens, or
  database credentials in frontend environment files.
- **Fail closed.** If the gateway is unreachable, pages show errors — no
  cached or substituted data is displayed.
- **Scope-aware rendering.** Audit and dashboard views surface the
  caller's visibility scope; the server enforces it regardless (out-of-scope
  filters return 403, out-of-scope events 404).

## Prerequisites

1. PostgreSQL running with the migrated + seeded demo database
   (see [`docs/database-setup.md`](../docs/database-setup.md)).
2. The backend running on `http://localhost:8000`:

   ```powershell
   cd backend
   .\.venv\Scripts\uvicorn.exe app.main:app --port 8000
   ```

## Configuration

```powershell
Copy-Item .env.example .env.local   # optional override
```

| Variable | Default | Purpose |
|----------|---------|---------|
| `VITE_API_BASE_URL` | `http://localhost:8000` | Backend base URL |

## Running

```powershell
npm install
npm run dev        # http://localhost:5173
```

## Scripts

| Script | Purpose |
|--------|---------|
| `npm run dev` | Vite dev server (HMR) |
| `npm run build` | Type check + production build to `dist/` |
| `npm run preview` | Serve the production build locally |
| `npm run lint` | oxlint |
| `npm run type-check` | `tsc -b` (no emit) |
| `npm run e2e` | Playwright journeys (requires backend + seeded DB) |

## End-to-end tests

The Playwright suite runs against the real backend and is split in two
spec files (12 journeys total, last run 12 passed in 51.1s):

- `e2e/journeys.spec.ts` — login (valid/invalid/session-expiry), simulated
  ALLOW and BLOCK decisions, the audit trail + detail view, the policy/asset
  pages, the SDK documentation page (including deep-link refresh and a
  no-secrets assertion), and the identity-scoped dashboard label.
- `e2e/security.spec.ts` — authorization/visibility enforcement as seen
  in the UI: blocked decisions render no stored values and no records
  section, the audit trail is scope-isolated (own events vs. full trail
  for administrators), and admin-only controls are absent for regular
  users.

```powershell
npx playwright install chromium   # one-time browser download
npm run e2e                       # starts the Vite dev server automatically
```

Make sure the backend is running first. Tests run sequentially (the demo
database is shared state).

## Production notes

- `npm run build` emits a static SPA to `dist/`. Serve it with any web
  server and add an **SPA fallback** (rewrite unknown paths to
  `index.html`) so deep links like `/audit/aud-123` work on reload.
- The backend CORS allow-list (`CORS_ORIGINS`) must include the console's
  origin when it is served from a different host/port.

## Stack

React 19 · TypeScript · Vite · Tailwind CSS 4 · React Router · Axios ·
Recharts · Playwright

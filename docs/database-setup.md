# ContextShield — Database Setup & Operations

> **Status:** Implemented — SQLAlchemy models, Alembic migrations, and synthetic demo seed data are in place.
> **Last Updated:** 2026-10-20

This document covers the exact local PostgreSQL setup for ContextShield, plus
recovery procedures. The application **never** connects as the PostgreSQL
superuser; it uses a dedicated `contextshield_app` account with no
`SUPERUSER` / `CREATEDB` / `CREATEROLE` privileges.

> The Docker backend entrypoint (compose or a container deployment) waits for
> PostgreSQL, runs `alembic upgrade head`, and optionally runs the idempotent
> seed (`SEED_ON_START`). Nothing in the setup or startup path deletes
> databases, records, or volumes.

| Item | Value (local development) |
|------|---------------------------|
| Database | `contextshield` |
| Application role | `contextshield_app` |
| Role password | `contextshield_pass` *(change for anything beyond local dev)* |
| App connection URL | `postgresql+asyncpg://contextshield_app:contextshield_pass@localhost:5432/contextshield` |
| Migration tool | Alembic (`backend/alembic/`) |

---

## 1. Confirm PostgreSQL is installed and running

**Windows (PowerShell):**

```powershell
# Is the service running?
Get-Service *postgres*

# Is the port reachable?
Test-NetConnection localhost -Port 5432

# Is the CLI available? (typical path shown; adjust for your version)
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" --version
```

**Linux/macOS:**

```bash
systemctl status postgresql        # or: brew services list
pg_isready -h localhost -p 5432
psql --version
```

If the service is not running: start it via **Services** on Windows
(`postgresql-x64-<version>`), `sudo systemctl start postgresql` on Linux, or
`brew services start postgresql@16` on macOS.

---

## 2. Create the database and the dedicated application user

Run the bootstrap script **once** as a PostgreSQL superuser (for example the
`postgres` account created during installation):

```powershell
# From the repository root — will prompt for the superuser password
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -h localhost -d postgres `
    -f backend\scripts\create_database.sql
```

**pgAdmin alternative:** connect as the superuser → right-click **Databases** →
*Query Tool* → paste the contents of `backend/scripts/create_database.sql` and
execute. (The `\gexec` line is psql-only; in pgAdmin just run
`CREATE DATABASE contextshield OWNER contextshield_app;` and ignore the
"already exists" error if it comes up.)

Or do it manually:

```sql
CREATE ROLE contextshield_app LOGIN PASSWORD 'contextshield_pass'
    NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE contextshield OWNER contextshield_app;
```

Verify:

```powershell
$env:PGPASSWORD = "contextshield_pass"
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U contextshield_app -h localhost -d contextshield -c "SELECT current_user;"
```

> **Do not** put the superuser in `.env`. The only superuser use is this
> one-time bootstrap step.

---

## 3. Configure the local database URL

```powershell
Copy-Item .env.example .env    # from the repository root, if .env does not exist yet
```

Ensure `.env` contains:

```ini
DATABASE_URL=postgresql+asyncpg://contextshield_app:contextshield_pass@localhost:5432/contextshield
JWT_SECRET=<long random string>
```

`.env` is git-ignored — never commit it. Both `postgresql://` and
`postgresql+asyncpg://` URLs are accepted; the application upgrades the driver
automatically.

---

## 4. Install backend dependencies

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 5. Run Alembic migrations

All commands run **from `backend/`**:

```powershell
# Apply the schema (creates all 20 tables)
python -m alembic upgrade head

# Useful companions
python -m alembic current          # which revision is applied
python -m alembic history          # migration history
python -m alembic downgrade -1     # roll back one revision (local dev only)
```

The Docker entrypoint runs `alembic upgrade head` automatically when
`RUN_MIGRATIONS_ON_START=true` (the default). Do not run a manual migration at
the same time as a starting container unless you have coordinated it; Alembic
takes a database lock, but concurrent deploy steps add avoidable risk.

Creating a *new* migration after changing models (only when needed — never
regenerate existing history):

```powershell
python -m alembic revision --autogenerate -m "describe the change"
python -m alembic upgrade head
```

> All checked-in migrations are part of the history. Do **not** delete them, and
> do not re-autogenerate the baseline.

## 6. Check database connectivity

```powershell
python -m app.check_db
```

Expected output: a green light, the table list, and row counts. If it reports
"No tables found", run the migration step above.

## 7. Seed synthetic demo data

```powershell
python -m app.seed
```

The seed is **idempotent** — re-running it creates no duplicates and never
truncates or deletes existing records. It inserts:

| Category | Count | Examples |
|----------|-------|----------|
| Roles / permissions | 12 roles | `hr_manager`, `sales_staff`, `analyst`, … |
| Users (bcrypt-hashed passwords) | 11 | `admin`, `sarah.chen`, `james.wilson`, … |
| Data assets / classified fields | 5 assets / 35 fields | `employee_salary`, `customer_records`, … |
| Versioned privacy policies | 12 rows (including version history) | `salary_access_policy` |
| Employees | 28 | `EMP001` … `EMP027` (SSNs stored as SHA-256 hashes only) |
| Customers | 10 | `CUS001` … `CUS010` |
| Orders | 20 | `ORD0001` … `ORD0020` |
| Business documents | 8 | `DOC001` … `DOC008` (internal/financial) |

All records are fictional. No real employee or customer data is imported.

Verify idempotency without deleting anything:

```powershell
# From backend/ — run it twice; the second run reports no new records.
python -m app.seed
python -m app.seed

# Optional independent check (app role):
$env:PGPASSWORD = "contextshield_pass"
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U contextshield_app -h localhost `
    -d contextshield -tAc "select count(*) from users;"   # → 11 both times
```

The seed is for **synthetic demos and development only**. Never point it at a
production database that contains real records.

## 8. Run the database tests

```powershell
cd backend
python -m pytest tests/test_database.py -v
```

The suite verifies connectivity, all expected tables, foreign-key integrity,
seed idempotency, model constraints, and repository queries (including
field-level permission projection).

---

## Docker alternative

The compose stack runs PostgreSQL 16 with a health check. The backend waits for
it, applies migrations, and (by default) loads the idempotent synthetic seed:

```powershell
# From the repository root; requires .env (Copy-Item .env.example .env)
docker compose up --build -d
docker compose ps
docker compose logs -f backend
```

* Ports: `DATABASE_PORT` (5432), `BACKEND_PORT` (8000), `FRONTEND_PORT` (5173).
  Use overrides to avoid conflicts, e.g.
  `$env:DATABASE_PORT='55432'; docker compose up -d db backend`.
* Inside compose the backend connects to host `db`; the host-oriented
  `DATABASE_URL` in `.env` is intentionally overridden for that container.
* `SEED_ON_START=false` disables seeding. Migrations always run unless
  `RUN_MIGRATIONS_ON_START=false`.
* `docker compose down` **keeps** the `pgdata` volume. Only
  `docker compose down -v` deletes it — never use that flag on data you need.
* Compose bootstraps its PostgreSQL container role from `DATABASE_USER` /
  `DATABASE_PASSWORD` (default `postgres`). That role is the container's
  superuser; it is a local-development convenience, not the least-privilege
  production setup described above.

Ad hoc container (different port so it cannot clash with a local server):

```powershell
docker run -d --name contextshield-pg `
  -e POSTGRES_USER=contextshield_app -e POSTGRES_PASSWORD=contextshield_pass `
  -e POSTGRES_DB=contextshield -p 5433:5432 postgres:16-alpine
# then point DATABASE_URL at localhost:5433 and run the migration + seed
```

---

## Preserving data during ordinary restarts

* `docker compose stop` / `start` / `restart` and `docker compose down`
  preserve the `pgdata` volume and all rows.
* Restarting the backend or running `alembic upgrade head` again is a no-op when
  the database is already at head.
* Re-running `python -m app.seed` adds nothing and deletes nothing.
* Application restarts never run destructive SQL. There is no automatic
  database reset anywhere in the project.

---

## Applying migrations to a deployment database safely

1. Back up the database first (provider snapshot or `pg_dump`). A downgrade is
   not a backup.
2. Review the new migration under `backend/alembic/versions/` for destructive
   operations and long table rewrites.
3. Pause writes (or scale the API to one instance) during the migration.
4. Run `python -m alembic upgrade head` from `backend/` using the deployment
   `DATABASE_URL`.
5. Confirm `python -m alembic current` reports `(head)` and the API's
   `/api/v1/system/status` reports `database: healthy`.
6. Resume traffic and watch error rates and logs.

If a migration must be reversed, restore from the backup or write a tested
forward fix; do not run `alembic downgrade` against production data without a
data-preserving plan. Never run `python -m app.seed` against real records.

---

## Recovery & troubleshooting

### Lost the superuser password (Windows, requires admin rights)

1. Open `C:\Program Files\PostgreSQL\<version>\data\pg_hba.conf` **as
   Administrator**.
2. Temporarily change the `scram-sha-256` method to `trust` for
   `host all all 127.0.0.1/32`.
3. Restart the service: `Restart-Service postgresql-x64-<version>`.
4. Connect passwordless and reset:
   `psql -U postgres -h localhost -c "ALTER USER postgres PASSWORD 'new-password';"`
5. **Revert `pg_hba.conf` immediately** and restart the service again.

### Recreate a *local development* database from scratch

> **Destructive — local development only.** This deletes every row in the
> local `contextshield` database. Never run it against a deployment, and never
> as part of automated setup, tests, or startup. There is no confirmation
> prompt in the commands below; run them only when you intend the loss.

```powershell
# 1. Stop the backend first so it cannot reconnect mid-drop.
# 2. As superuser (will drop all local demo rows):
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -h localhost -d postgres `
    -c "DROP DATABASE IF EXISTS contextshield;"
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -h localhost -d postgres `
    -f backend\scripts\create_database.sql
# 3. As the app user, from backend/:
python -m alembic upgrade head
python -m app.seed
```

For Docker, deleting the local demo data requires explicitly removing the
volume:

```powershell
docker compose down          # keeps data (normal)
# docker compose down -v     # DESTRUCTIVE: removes the pgdata volume — local demo only
```

### Reset just the local schema (keep the database)

> **Destructive — local development only.** `downgrade base` drops the schema
> and all local rows.

```powershell
cd backend
python -m alembic current          # confirm you are on the local demo DB
python -m alembic downgrade base
python -m alembic upgrade head
python -m app.seed
```

### Common errors

| Symptom | Cause / fix |
|---------|-------------|
| `password authentication failed for user "contextshield_app"` | Password in `.env` differs from the role's; `ALTER ROLE contextshield_app PASSWORD '...';` as superuser. |
| `database "contextshield" does not exist` | Run the bootstrap script (§2). |
| `role "contextshield_app" does not exist` | Same as above. |
| `No module named 'asyncpg'` | `pip install -r requirements.txt` (async driver required). |
| `alembic.util.exc.CommandError: Can't locate revision` | You are not in `backend/`, or `alembic.ini` is missing; re-run from `backend/`. |
| `Target database is not up to date` | `python -m alembic upgrade head` before creating a new revision. |
| Seed prints nothing new on second run | Expected — the seed is idempotent. |
| `UnicodeEncodeError` in console output | Set `$env:PYTHONIOENCODING="utf-8"` (the scripts also try to self-configure). |
| Port 5432 already in use | Another PostgreSQL instance is running; stop it or use Docker on 5433. |

# ContextShield — Database Setup & Operations

> **Status:** Implemented — SQLAlchemy models, Alembic migration `initial schema`, and synthetic demo seed data are in place.
> **Last Updated:** 2026-10-18

This document covers the exact local PostgreSQL setup for ContextShield, plus
recovery procedures. The application **never** connects as the PostgreSQL
superuser; it uses a dedicated `contextshield_app` account with no
`SUPERUSER` / `CREATEDB` / `CREATEROLE` privileges.

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
python -m alembic downgrade -1     # roll back one revision
```

Creating a *new* migration after changing models (only when needed — never
regenerate existing history):

```powershell
python -m alembic revision --autogenerate -m "describe the change"
python -m alembic upgrade head
```

> The initial-schema migration is checked in
> (`backend/alembic/versions/*_initial_schema.py`). Do **not** delete it, and
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

The seed is **idempotent** — re-running it creates no duplicates. It inserts:

| Category | Count | Examples |
|----------|-------|----------|
| Roles / permissions | 8 roles | `hr_manager`, `sales_staff`, `analyst`, … |
| Users (bcrypt-hashed passwords) | 8 | `admin`, `sarah.chen`, `james.wilson`, … |
| Data assets / classified fields | 5 assets / 35 fields | `employee_salary`, `customer_records`, … |
| Versioned privacy policies | 7 (incl. v1→v2 history) | `salary_access_policy` |
| Employees | 28 | `EMP001` … `EMP027` (SSNs stored as SHA-256 hashes only) |
| Customers | 10 | `CUS001` … `CUS010` |
| Orders | 20 | `ORD0001` … `ORD0020` |
| Business documents | 8 | `DOC001` … `DOC008` (internal/financial) |

All records are fictional. No real employee or customer data is imported.

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

If you prefer not to use a local PostgreSQL install:

```bash
docker compose up db        # postgres:16-alpine from docker-compose.yml
```

or ad hoc (note the different port so it cannot clash with a local server):

```powershell
docker run -d --name contextshield-pg `
  -e POSTGRES_USER=contextshield_app -e POSTGRES_PASSWORD=contextshield_pass `
  -e POSTGRES_DB=contextshield -p 5433:5432 postgres:16-alpine
# then point DATABASE_URL at localhost:5433
```

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

### Recreate the database from scratch

```powershell
# as superuser
psql -U postgres -h localhost -d postgres -c "DROP DATABASE IF EXISTS contextshield;"
psql -U postgres -h localhost -d postgres -f backend\scripts\create_database.sql
# as the app user (from backend/)
python -m alembic upgrade head
python -m app.seed
```

### Reset just the schema (keep the database)

```powershell
cd backend
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

-- ============================================================================
-- ContextShield — one-time database bootstrap
--
-- Creates the dedicated (non-superuser) application role and the
-- ``contextshield`` database.  Run ONCE as a PostgreSQL superuser, e.g.:
--
--   psql -U postgres -h localhost -d postgres -f backend/scripts/create_database.sql
--
-- In pgAdmin: connect as the superuser, open the Query Tool, paste this
-- file's contents and execute.
--
-- The application must NOT run as the superuser.  Change the password below
-- (and in .env) for anything beyond local development.
-- ============================================================================

-- 1. Application role (no superuser / createdb / createrole privileges)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'contextshield_app') THEN
        CREATE ROLE contextshield_app
            LOGIN
            PASSWORD 'contextshield_pass'
            NOSUPERUSER NOCREATEDB NOCREATEROLE;
        RAISE NOTICE 'Role contextshield_app created.';
    ELSE
        RAISE NOTICE 'Role contextshield_app already exists — keeping it.';
    END IF;
END
$$;

-- 2. Database owned by the application role.  CREATE DATABASE cannot run
--    inside a transaction block, so it is issued separately.  psql users can
--    rely on \gexec to make this idempotent; pgAdmin users can simply run the
--    CREATE DATABASE statement and ignore the "already exists" error.
SELECT 'CREATE DATABASE contextshield OWNER contextshield_app'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'contextshield')\gexec

-- 3. Make sure the app role can fully use its database.
GRANT ALL PRIVILEGES ON DATABASE contextshield TO contextshield_app;

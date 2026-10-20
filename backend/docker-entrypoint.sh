#!/bin/sh
# Container startup helper.
#
# Responsibilities (each step is optional via environment variables):
#   1. wait until PostgreSQL is reachable (avoids crash-loops on slow DBs);
#   2. apply Alembic migrations (idempotent: "upgrade head");
#   3. optionally load the synthetic demo seed (idempotent by design);
#   4. exec the server command as PID 1.
#
# Nothing here ever drops a database, removes volumes, or deletes records.
set -e

if [ "${WAIT_FOR_DB:-true}" = "true" ] && [ -n "${DATABASE_URL:-}" ]; then
    echo "[entrypoint] waiting for the database to become reachable..."
    attempt=1
    max_attempts="${DB_WAIT_ATTEMPTS:-30}"
    while ! python -m app.check_db >/dev/null 2>&1; do
        if [ "$attempt" -ge "$max_attempts" ]; then
            echo "[entrypoint] database not reachable after ${max_attempts} attempts" >&2
            echo "[entrypoint] check DATABASE_URL and that the database is running" >&2
            exit 1
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    echo "[entrypoint] database is reachable"
fi

if [ "${RUN_MIGRATIONS_ON_START:-true}" = "true" ]; then
    echo "[entrypoint] applying database migrations (alembic upgrade head)..."
    python -m alembic upgrade head
fi

if [ "${SEED_ON_START:-false}" = "true" ]; then
    echo "[entrypoint] loading synthetic demo seed (idempotent, safe to re-run)..."
    python -m app.seed
fi

exec "$@"

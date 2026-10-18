"""Quick database connectivity check.

Usage::

    python -m app.check_db
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Force UTF-8 console output on Windows (legacy code pages cannot render ✔/emoji).
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import settings


async def check():
    db_url = str(settings.DATABASE_URL)
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

    print(f"Connecting to: {db_url.split('@')[-1]} …")
    engine = create_async_engine(db_url, echo=False)

    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            value = result.scalar_one()
            assert value == 1
            print("✅ Database connection successful.")

            # Check tables
            result = await conn.execute(text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' ORDER BY table_name"
            ))
            tables = [row[0] for row in result.fetchall()]
            if tables:
                print(f"📋 Tables ({len(tables)}): {', '.join(tables)}")
            else:
                print("⚠️  No tables found. Run migrations first:")
                print("   python -m alembic upgrade head")

            # Check row counts for key tables
            for tbl in ["users", "roles", "data_assets", "data_fields", "privacy_policies",
                        "employees", "customers", "orders", "business_documents", "audit_events"]:
                if tbl in tables:
                    r = await conn.execute(text(f"SELECT COUNT(*) FROM {tbl}"))
                    cnt = r.scalar_one()
                    print(f"   {tbl}: {cnt} rows")

    except Exception as exc:
        print(f"❌ Connection failed: {exc}")
        sys.exit(1)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(check())

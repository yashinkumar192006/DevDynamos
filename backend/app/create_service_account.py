"""Create a service account for an AI agent or backend service.

Usage (from ``backend/``)::

    python -m app.create_service_account --name demo-ai-agent \
        --scopes privacy:request,customer_records:read

The plaintext API key is printed **once** and never stored; only its
SHA-256 hash is persisted. Present it to the gateway as the
``X-API-Key`` header. Creating a second account with the same name fails.
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure the backend package is importable when run from any directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Windows consoles default to a legacy code page; force UTF-8 output.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.security import generate_api_key
from app.models import ServiceAccount, User


def _dsn() -> str:
    url = str(settings.DATABASE_URL)
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


async def create_service_account(
    name: str,
    scopes: list[str],
    description: str | None,
    expires_days: int | None,
) -> int:
    engine = create_async_engine(_dsn(), echo=False)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as session:
            async with session.begin():
                existing = await session.execute(
                    select(ServiceAccount).where(ServiceAccount.name == name)
                )
                if existing.scalar_one_or_none() is not None:
                    print(
                        f"[ERROR] A service account named '{name}' already exists. "
                        "Choose another name."
                    )
                    return 1

                admin = (
                    await session.execute(select(User).where(User.username == "admin"))
                ).scalar_one_or_none()

                plaintext, hashed, prefix = generate_api_key()
                expires_at = (
                    datetime.now(timezone.utc) + timedelta(days=expires_days)
                    if expires_days
                    else None
                )
                session.add(
                    ServiceAccount(
                        name=name,
                        description=description,
                        key_prefix=prefix,
                        hashed_key=hashed,
                        scopes=json.dumps(scopes),
                        is_active=True,
                        expires_at=expires_at,
                        created_by=admin.id if admin else None,
                    )
                )
    finally:
        await engine.dispose()

    print("\n+--------------------------------------------------+")
    print("|  Service account created                         |")
    print("+--------------------------------------------------+")
    print(f"  name:    {name}")
    print(f"  key:     {plaintext}")
    print(f"  prefix:  {prefix}")
    print(f"  scopes:  {', '.join(scopes) if scopes else '(none)'}")
    if expires_days:
        print(f"  expires: in {expires_days} day(s)")
    print("\n  Store the key now — it is shown only once.")
    print("  Send it as the X-API-Key header on gateway requests.\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a ContextShield service account (AI agent / service identity)."
    )
    parser.add_argument("--name", required=True, help="Unique account name, e.g. demo-ai-agent")
    parser.add_argument(
        "--scopes",
        default="privacy:request",
        help="Comma-separated scopes like 'privacy:request,customer_records:read' "
        "(use '*' for all). Default: privacy:request",
    )
    parser.add_argument("--description", default=None, help="Optional description")
    parser.add_argument(
        "--expires-days",
        type=int,
        default=None,
        help="Optional expiry in days (default: no expiry)",
    )
    args = parser.parse_args(argv)
    scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
    return asyncio.run(
        create_service_account(args.name, scopes, args.description, args.expires_days)
    )


if __name__ == "__main__":
    raise SystemExit(main())

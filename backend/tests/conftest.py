"""Shared pytest configuration.

The application engine is module-level and pools connections. Under
pytest-asyncio every test runs in a fresh event loop, so pooled asyncpg
connections from a previous loop would be dead on arrival. Replacing the
app engine's pool with ``NullPool`` (one connection per checkout, closed
when the request's session ends) keeps each test self-contained.
"""

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.core import database

_test_engine = create_async_engine(
    str(database.DATABASE_URL),
    echo=False,
    poolclass=NullPool,
)
database.engine = _test_engine
database.AsyncSessionLocal.configure(bind=_test_engine)

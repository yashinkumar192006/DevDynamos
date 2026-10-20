"""Shared pytest configuration.

The application engine is module-level and pools connections. Under
pytest-asyncio every test runs in a fresh event loop, so pooled asyncpg
connections from a previous loop would be dead on arrival. Replacing the
app engine's pool with ``NullPool`` (one connection per checkout, closed
when the request's session ends) keeps each test self-contained.

Process-wide sliding-window state (login throttling, repeated-aggregate
guard) is reset before each test so results are order-independent.
"""

import pytest
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


@pytest.fixture(autouse=True)
def _reset_process_shared_state():
    """Reset in-memory throttling/guard state between tests."""
    from app.core.rate_limit import login_ip_rate_limiter, login_rate_limiter
    from app.services import data_connector

    def _reset():
        guard = data_connector._shared_aggregate_guard
        if guard is not None:
            guard.reset()
        login_rate_limiter.reset()
        login_ip_rate_limiter.reset()

    _reset()
    yield
    _reset()

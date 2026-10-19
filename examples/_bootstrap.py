"""Shared helpers for the runnable ContextShield integration examples.

Run the examples from the repository root, e.g.::

    python examples/demo_end_to_end.py

Credentials are read from ``CONTEXTSHIELD_*`` environment variables — no
example hardcodes a credential (see ``examples/README.md``).
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]

# Windows consoles default to a legacy code page; force UTF-8 output so the
# examples print consistently everywhere.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # pragma: no cover — exotic stream types
            pass

# Make the SDK importable straight from a source checkout. If the package is
# installed (``pip install -e sdk``), the installed copy is used instead.
try:  # pragma: no cover — environment-dependent
    import contextshield  # noqa: F401
except ImportError:  # pragma: no cover
    _sdk_path = str(_ROOT / "sdk")
    if _sdk_path not in sys.path:
        sys.path.insert(0, _sdk_path)

from contextshield import (  # noqa: E402
    ContextShieldClient,
    ContextShieldError,
    GatewayUnavailableError,
)

DEFAULT_BASE_URL = "http://localhost:8000"

_CREDENTIAL_ENV_VARS = (
    "CONTEXTSHIELD_API_KEY",
    "CONTEXTSHIELD_TOKEN",
    "CONTEXTSHIELD_USERNAME",
)


def build_client(*, verbose: bool = False) -> ContextShieldClient:
    """Build an authenticated client from environment configuration.

    Credentials come from ``CONTEXTSHIELD_API_KEY`` / ``CONTEXTSHIELD_TOKEN``
    or ``CONTEXTSHIELD_USERNAME`` + ``CONTEXTSHIELD_PASSWORD``. The gateway
    URL defaults to ``http://localhost:8000`` (override with
    ``CONTEXTSHIELD_BASE_URL``).
    """
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s"
        )
        logging.getLogger("httpx").setLevel(logging.WARNING)

    if not any(os.environ.get(name) for name in _CREDENTIAL_ENV_VARS):
        print("No CONTEXTSHIELD_* credentials found in the environment.\n")
        print("Set them for a seeded demo identity first, e.g. (PowerShell):")
        print('  $env:CONTEXTSHIELD_USERNAME = "natalie.brooks"')
        print('  $env:CONTEXTSHIELD_PASSWORD = "<seeded demo password>"')
        print("  # demo passwords: see backend/app/seed.py (USERS list)")
        print("\nOr use an agent credential created with:")
        print("  python -m app.create_service_account --name demo-agent "
              "--scopes privacy:request")
        print('  $env:CONTEXTSHIELD_API_KEY = "<the key shown once>"')
        raise SystemExit(2)

    base_url = os.environ.get("CONTEXTSHIELD_BASE_URL", DEFAULT_BASE_URL)
    return ContextShieldClient.from_env(base_url=base_url)


def print_result(result: Any, *, heading: str | None = None) -> None:
    """Print a compact, safe view of a secure-request result."""
    if heading:
        print(f"\n{heading}")

    print(f"  decision:  {result.overall_decision}")
    print(f"  request:   {result.request_id}")
    if result.audit_id:
        print(f"  audit:     {result.audit_id}")

    for name, decision in result.fields.items():
        if decision.granted:
            print(f"  field {name!r}: {decision.action} -> {decision.value!r}")
        else:
            print(
                f"  field {name!r}: {decision.action} "
                f"({decision.reason_code})"
            )

    if result.llm is not None:
        guard = result.llm.guard
        print(
            "  model:     "
            f"invoked={result.llm.invoked} provider={result.llm.provider} "
            f"guard={(guard.action if guard is not None else 'n/a')}"
        )


def run_safely(main) -> int:
    """Run an example's ``main()`` with friendly failure messages."""
    try:
        main()
    except GatewayUnavailableError:
        print(
            "\nCould not reach the ContextShield gateway. Is it running?\n"
            "  cd backend && uvicorn app.main:app --reload --port 8000"
        )
        return 1
    except ContextShieldError as exc:
        print(f"\nContextShield error ({type(exc).__name__}): {exc}")
        return 1
    return 0

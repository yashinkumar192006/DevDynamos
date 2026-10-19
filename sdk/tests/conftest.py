"""SDK test configuration.

The SDK tests are fully self-contained: they use ``httpx.MockTransport`` to
simulate the gateway, so no server, database, or network access is needed.

``CONTEXTSHIELD_*`` environment variables are cleared for every test so a
developer's local gateway configuration cannot influence results; tests that
exercise environment-based configuration set them explicitly.
"""

import sys
from pathlib import Path

import pytest

SDK_ROOT = Path(__file__).resolve().parents[1]
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

_ENV_VARS = (
    "CONTEXTSHIELD_BASE_URL",
    "CONTEXTSHIELD_API_KEY",
    "CONTEXTSHIELD_TOKEN",
    "CONTEXTSHIELD_USERNAME",
    "CONTEXTSHIELD_PASSWORD",
)


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch):
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)

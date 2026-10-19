import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


def _client() -> AsyncClient:
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_root_health():
    async with _client() as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_api_v1_health():
    async with _client() as client:
        response = await client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_system_status():
    async with _client() as client:
        response = await client.get("/api/v1/system/status")
    assert response.status_code == 200
    json_data = response.json()
    assert "providers" in json_data
    assert "database" in json_data["providers"]
    assert "llm" in json_data["providers"]
    classifier = json_data["providers"]["classifier"]
    assert classifier["status"] in {"ready", "deterministic_only"}
    assert classifier["unknown_field_sensitivity"] == "high"
    assert classifier["uncertain_handling"] == "escalate"

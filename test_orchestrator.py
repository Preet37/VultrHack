import asyncio

import httpx
import pytest

from connectivity import check_connectivity, load_keys
from main import app


def test_health():
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            return await client.get("/health")

    response = asyncio.run(request())
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_catalog_requests_use_separate_keys():
    requests = []

    def respond(request):
        requests.append(request)
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "example-model"}]})
        if request.url.path == "/v2/regions":
            return httpx.Response(200, json={"regions": [{"id": "ewr"}]})
        return httpx.Response(404)

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await check_connectivity(client, "account-token", "inference-token")

    assert asyncio.run(request()) == (["example-model"], 1)
    assert [str(request.url) for request in requests] == [
        "https://api.vultrinference.com/v1/models",
        "https://api.vultr.com/v2/regions",
    ]
    assert [request.headers["authorization"] for request in requests] == [
        "Bearer inference-token",
        "Bearer account-token",
    ]


def test_catalog_failure_does_not_print_keys(capsys):
    def respond(request):
        return httpx.Response(401, json={"error": "unauthorized"})

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await check_connectivity(client, "account-token", "inference-token")

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(request())
    assert "token" not in capsys.readouterr().out


def test_load_keys_supports_documented_and_existing_env_names(monkeypatch):
    monkeypatch.setattr("connectivity.load_dotenv", lambda _: None)
    monkeypatch.setenv("VULTR_API_KEY", "account")
    monkeypatch.setenv("VULTR_INFERENCE_KEY", "inference")
    assert load_keys() == ("account", "inference")

    monkeypatch.delenv("VULTR_API_KEY")
    monkeypatch.delenv("VULTR_INFERENCE_KEY")
    monkeypatch.setenv("vultr_api_key", "legacy-account")
    monkeypatch.setenv("vultr_inference_api_key", "legacy-inference")
    assert load_keys() == ("legacy-account", "legacy-inference")

import asyncio
from pathlib import Path

import httpx
import pytest

from connectivity import check_connectivity, load_keys
from main import app


def test_health():
    assert app.title == "Cerberus"

    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            return await client.get("/health")

    response = asyncio.run(request())
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_home_displays_logo():
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            return await client.get("/"), await client.get("/logo.jpg")

    home, logo = asyncio.run(request())
    assert home.status_code == 200
    assert '<img src="/logo.jpg" alt="Cerberus logo"' in home.text
    assert logo.status_code == 200
    assert logo.headers["content-type"] == "image/jpeg"
    assert logo.content == Path(__file__).with_name("cerberus-logo.jpg").read_bytes()


def test_catalog_requests_use_separate_keys():
    requests = []

    def respond(request):
        requests.append(request)
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "example-model"}]})
        if request.url.path == "/v2/account":
            return httpx.Response(200, json={"account": {}})
        if request.url.path == "/v2/regions":
            return httpx.Response(200, json={"regions": [{"id": "ewr"}]})
        return httpx.Response(404)

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await check_connectivity(client, "account-token", "inference-token")

    assert asyncio.run(request()) == (["example-model"], 1)
    assert [str(request.url) for request in requests] == [
        "https://api.vultrinference.com/v1/models",
        "https://api.vultr.com/v2/account",
        "https://api.vultr.com/v2/regions",
    ]
    assert [request.headers["authorization"] for request in requests] == [
        "Bearer inference-token",
        "Bearer account-token",
        "Bearer account-token",
    ]


def test_public_regions_cannot_mask_invalid_account_auth():
    seen = []

    def respond(request):
        seen.append(request.url.path)
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "example-model"}]})
        if request.url.path == "/v2/regions":
            return httpx.Response(200, json={"regions": [{"id": "ewr"}]})
        return httpx.Response(401, json={"error": "Unauthorized IP address"})

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await check_connectivity(client, "account-token", "inference-token")

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(request())
    assert "/v2/account" in seen


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
    monkeypatch.setenv("VULTR_INFERENCE_KEY", "legacy-inference")
    monkeypatch.setenv("VULTR_INFERENCE_API_KEY", "inference")
    assert load_keys() == ("account", "inference")

    monkeypatch.delenv("VULTR_INFERENCE_API_KEY")
    assert load_keys() == ("account", "legacy-inference")

    monkeypatch.delenv("VULTR_API_KEY")
    monkeypatch.delenv("VULTR_INFERENCE_KEY")
    monkeypatch.setenv("vultr_api_key", "legacy-account")
    monkeypatch.setenv("vultr_inference_api_key", "legacy-inference")
    assert load_keys() == ("legacy-account", "legacy-inference")

    monkeypatch.delenv("vultr_inference_api_key")
    monkeypatch.setenv("OPENAI_API_KEY", "external-key")
    with pytest.raises(RuntimeError):
        load_keys()

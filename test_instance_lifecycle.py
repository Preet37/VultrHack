import asyncio
import base64
import json

import httpx
import pytest

from instance_lifecycle import ReadySignals, VultrInstances, temporary_instance
from main import app, ready_signals


def test_create_uses_cloud_init_without_vultr_keys():
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(202, json={"instance": {"id": "instance-123"}})

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await VultrInstances(client, "account-key").create(
                "ewr", "vc2-1c-1gb", 2284, "https://cerberus.example/internal/ready", "ready-token"
            )

    assert asyncio.run(request()) == "instance-123"
    sent = requests[0]
    assert sent.method == "POST"
    assert str(sent.url) == "https://api.vultr.com/v2/instances"
    assert sent.headers["authorization"] == "Bearer account-key"
    payload = json.loads(sent.content)
    assert (payload["region"], payload["plan"], payload["os_id"]) == ("ewr", "vc2-1c-1gb", 2284)
    assert payload["tags"] == ["cerberus"]
    script = base64.b64decode(payload["user_data"]).decode()
    assert "docker.io" in script
    assert "https://cerberus.example/internal/ready" in script
    assert "ready-token" in script
    assert "account-key" not in script


def test_invalid_callback_is_rejected_before_provisioning():
    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: pytest.fail("Network call"))) as client:
            await VultrInstances(client, "account-key").create("ewr", "vc2-1c-1gb", 2284, "http://localhost/ready", "token")

    with pytest.raises(ValueError):
        asyncio.run(request())


def test_poll_active_and_always_destroy_on_failure():
    methods = []
    statuses = iter([("pending", "stopped"), ("active", "running")])
    destroyed = False

    def respond(request):
        nonlocal destroyed
        methods.append(request.method)
        if request.method == "POST":
            return httpx.Response(202, json={"instance": {"id": "instance-123"}})
        if request.method == "DELETE":
            destroyed = True
            return httpx.Response(204)
        if destroyed:
            return httpx.Response(404)
        status, power_status = next(statuses)
        return httpx.Response(200, json={"instance": {"status": status, "power_status": power_status}})

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            api = VultrInstances(client, "account-key")
            async with temporary_instance(api, "ewr", "vc2-1c-1gb", 2284, "https://cerberus.example/internal/ready", "token") as instance_id:
                assert instance_id == "instance-123"
                await api.wait_active(instance_id, interval=0)
                raise RuntimeError("readiness failed")

    with pytest.raises(RuntimeError, match="readiness failed"):
        asyncio.run(request())
    assert methods == ["POST", "GET", "GET", "DELETE", "GET"]


def test_destroy_waits_until_instance_is_gone():
    methods = []

    def respond(request):
        methods.append(request.method)
        if request.method == "DELETE":
            return httpx.Response(204)
        if methods.count("GET") == 1:
            return httpx.Response(200, json={"instance": {"status": "active"}})
        return httpx.Response(404)

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await VultrInstances(client, "account-key").destroy("instance-123", interval=0)

    asyncio.run(request())
    assert methods == ["DELETE", "GET", "GET"]


def test_ready_callback_requires_registered_token():
    async def request():
        token = ready_signals.register()
        try:
            waiter = asyncio.create_task(ready_signals.wait(token, timeout=0.1))
            await asyncio.sleep(0)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                assert (await client.post("/internal/ready", headers={"Authorization": "Bearer wrong"})).status_code == 404
                assert (await client.post("/internal/ready", headers={"Authorization": f"Bearer {token}"})).status_code == 204
            await waiter
        finally:
            ready_signals.unregister(token)

    asyncio.run(request())


def test_ready_timeout():
    async def request():
        signals = ReadySignals()
        token = signals.register()
        try:
            with pytest.raises(TimeoutError):
                await signals.wait(token, timeout=0.01)
        finally:
            signals.unregister(token)

    asyncio.run(request())

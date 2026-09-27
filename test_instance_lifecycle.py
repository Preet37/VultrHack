import ast
import asyncio
import base64
import json
import subprocess

import httpx
import pytest

from instance_lifecycle import ReadySignals, VultrInstances, docker_user_data, temporary_instance, verify_instance
from main import app, callback_app, ready_signals


def test_create_uses_cloud_init_without_vultr_keys():
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(202, json={"instance": {"id": "instance-123"}})

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await VultrInstances(client, "account-key").create(
                "ewr", "vx1-g-2c-8g-120s", 2284, "https://cerberus.example/internal/ready", "ready-token"
            )

    assert asyncio.run(request()) == "instance-123"
    sent = requests[0]
    assert sent.method == "POST"
    assert str(sent.url) == "https://api.vultr.com/v2/instances"
    assert sent.headers["authorization"] == "Bearer account-key"
    payload = json.loads(sent.content)
    assert (payload["region"], payload["plan"], payload["os_id"]) == ("ewr", "vx1-g-2c-8g-120s", 2284)
    assert payload["block_devices"] == [{"block_id": "local", "bootable": True}]
    assert payload["tags"] == ["cerberus"]
    script = base64.b64decode(payload["user_data"]).decode()
    assert "systemctl stop ssh.socket ssh.service" in script
    assert script.index("systemctl stop ssh.socket ssh.service") < script.index("apt-get update")
    assert "OpenSSH port 22 remains listening" in script
    assert "test -c /dev/kvm" in script
    assert "test -r /dev/kvm" in script
    assert "test -w /dev/kvm" in script
    assert "docker.io" in script
    assert "runsc install" in script
    assert 'config["default-runtime"]="runsc"' in script
    assert "--runtime=runsc" in script
    assert "sh -c 'hostname; uname -a'" in script
    assert "docker info --format" in script
    assert "proof=$(python3 -c" in script
    assert '--data-binary "$proof"' in script
    assert script.index("--runtime=runsc") < script.index("https://cerberus.example/internal/ready")
    assert "ready-token" in script
    assert "account-key" not in script


def test_cloud_init_shell_and_host_proof_syntax():
    script = docker_user_data("https://cerberus.example/internal/ready", "ready-token")
    assert subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True).returncode == 0
    ast.parse(script.split("proof=$(python3 -c '", 1)[1].split("')\n", 1)[0])


def test_netbird_key_is_not_replaced_by_vultr_credentials_in_user_data():
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(202, json={"instance": {"id": "instance-123"}})

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await VultrInstances(client, "account-key").create(
                "ord", "vx1-g-2c-8g-120s", 2284, "https://cerberus.example/internal/ready", "ready-token", True, "A" * 36
            )

    asyncio.run(request())
    script = base64.b64decode(json.loads(requests[0].content)["user_data"]).decode()
    assert script.count("A" * 36) == 1
    assert "account-key" not in script
    assert "netbird up --setup-key-file" in script


def test_create_validation_error_redacts_credentials():
    def respond(request):
        return httpx.Response(400, json={"error": "Invalid os_id with account-key and ready-token"})

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await VultrInstances(client, "account-key").create(
                "ewr", "vx1-g-2c-8g-120s", 2284, "https://cerberus.example/internal/ready", "ready-token"
            )

    with pytest.raises(ValueError, match="Invalid os_id") as error:
        asyncio.run(request())
    assert "account-key" not in str(error.value)
    assert "ready-token" not in str(error.value)


def test_netbird_setup_key_is_redacted_from_vultr_validation_errors():
    def respond(request):
        return httpx.Response(400, json={"error": "Invalid setup key " + "A" * 36})

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await VultrInstances(client, "account-key").create(
                "ord", "vx1-g-2c-8g-120s", 2284, "https://cerberus.example/internal/ready", "ready-token", True, "A" * 36
            )

    with pytest.raises(ValueError) as error:
        asyncio.run(request())
    assert "A" * 36 not in str(error.value)


def test_non_vx1_or_diskless_plan_is_rejected_before_provisioning():
    async def request(plan):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: pytest.fail("Network call"))) as client:
            await VultrInstances(client, "account-key").create(
                "ewr", plan, 2284, "https://cerberus.example/internal/ready", "token"
            )

    for plan in ("vc2-1c-1gb", "vx1-g-2c-8g", "vx1-g-2c-8g-no-local-disks"):
        with pytest.raises(ValueError, match="VX1.*local"):
            asyncio.run(request(plan))


def test_netbird_test_requires_local_setup_key_before_provisioning(monkeypatch):
    monkeypatch.setattr("connectivity.load_keys", lambda: ("account-key", "inference-key"))
    monkeypatch.delenv("NETBIRD_SANDBOX_SETUP_KEY", raising=False)
    with pytest.raises(RuntimeError, match="NETBIRD_SANDBOX_SETUP_KEY"):
        asyncio.run(verify_instance("https://cerberus.example/internal/ready", "127.0.0.1", 8000, "ord", "vx1-g-2c-8g-120s", 2284, True, True))


def test_netbird_test_rejects_open_env_permissions(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("placeholder")
    env_file.chmod(0o644)
    monkeypatch.setattr("instance_lifecycle.Path", lambda _: env_file)
    monkeypatch.setattr("connectivity.load_keys", lambda: ("account-key", "inference-key"))
    monkeypatch.setenv("NETBIRD_SANDBOX_SETUP_KEY", "A" * 36)
    with pytest.raises(RuntimeError, match="chmod 600"):
        asyncio.run(verify_instance("https://cerberus.example/internal/ready", "127.0.0.1", 8000, "ord", "vx1-g-2c-8g-120s", 2284, True, True))


def test_private_ready_callback_requires_netbird_smoke_and_no_public_http():
    url = "http://100.124.55.15:8000/internal/ready"
    script = docker_user_data(url, "ready-token", True, "A" * 36, private_callback=True)
    assert url in script
    assert "http://100.124.55.15:8000/internal/failed" in script
    assert "trap cerberus_report_failure EXIT" in script
    assert script.count("A" * 36) == 1
    assert subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True).returncode == 0
    with pytest.raises(ValueError):
        docker_user_data(url, "ready-token", True, "A" * 36)
    with pytest.raises(ValueError):
        docker_user_data(url, "ready-token", netbird_setup_key="A" * 36, private_callback=True)


@pytest.mark.parametrize("url", [
    "http://192.0.2.10:8000/internal/ready",
    "http://127.0.0.1:8000/internal/ready",
    "http://100.124.55.15:8080/internal/ready",
    "http://100.124.55.15:8000/internal/other",
    "http://100.124.55.15:8000/internal/ready?key=abc",
    "http://user@100.124.55.15:8000/internal/ready",
])
def test_private_ready_callback_rejects_other_targets(url):
    with pytest.raises(ValueError, match="NetBird|callback"):
        docker_user_data(url, "ready-token", True, "A" * 36, private_callback=True)


def test_invalid_callback_is_rejected_before_provisioning():
    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: pytest.fail("Network call"))) as client:
            await VultrInstances(client, "account-key").create("ewr", "vx1-g-2c-8g-120s", 2284, "http://localhost/ready", "token")

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
            async with temporary_instance(api, "ewr", "vx1-g-2c-8g-120s", 2284, "https://cerberus.example/internal/ready", "token") as instance_id:
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


def test_destroy_retries_conflict_during_installation():
    methods = []

    def respond(request):
        methods.append(request.method)
        if request.method == "DELETE" and methods.count("DELETE") == 1:
            return httpx.Response(409, json={"error": "Instance installing"})
        return httpx.Response(204 if request.method == "DELETE" else 404)

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await VultrInstances(client, "account-key").destroy("instance-123", interval=0)

    asyncio.run(request())
    assert methods == ["DELETE", "DELETE", "GET"]


def test_destroy_reports_persistent_conflict_with_instance_id():
    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(409))) as client:
            await VultrInstances(client, "account-key").destroy("instance-123", timeout=0)

    with pytest.raises(TimeoutError, match="instance-123"):
        asyncio.run(request())


def test_ready_callback_requires_registered_token_and_host_proof():
    proof = {
        "hostname": "vx1-test",
        "uname": "Linux vx1-test x86_64",
        "cpu_virt": "vmx",
        "kvm_device": True,
        "kvm_access": True,
        "runtime": "runsc",
        "sandbox_hostname": "sandbox-test",
        "sandbox_uname": "Linux sandbox-test x86_64",
        "exit_code": 0,
    }

    async def request():
        token = ready_signals.register()
        try:
            waiter = asyncio.create_task(ready_signals.wait(token, timeout=0.1))
            await asyncio.sleep(0)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                assert (await client.post("/internal/ready", headers={"Authorization": "Bearer wrong"})).status_code == 404
                assert (await client.post("/internal/ready", headers={"Authorization": f"Bearer {token}"}, json={})).status_code == 400
                assert (await client.post("/internal/ready", headers={"Authorization": f"Bearer {token}"}, json={**proof, "kvm_access": False})).status_code == 400
                assert not waiter.done()
                assert (await client.post("/internal/ready", headers={"Authorization": f"Bearer {token}"}, json=proof)).status_code == 204
            assert await waiter == proof
        finally:
            ready_signals.unregister(token)

    asyncio.run(request())


def test_ready_callback_rejects_invalid_opensandbox_result():
    proof = {
        "hostname": "vx1-test", "uname": "Linux vx1-test x86_64", "cpu_virt": "vmx",
        "kvm_device": True, "kvm_access": True, "runtime": "runsc",
        "sandbox_hostname": "sandbox-test", "sandbox_uname": "Linux sandbox-test x86_64", "exit_code": 0,
    }

    async def request():
        token = ready_signals.register()
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=callback_app), base_url="http://test") as client:
                headers = {"Authorization": f"Bearer {token}"}
                invalid = await client.post("/internal/ready", headers=headers, json={**proof, "opensandbox": {"hostname": "sandbox", "uname": "Linux", "exit_code": 1}})
                public_ip = await client.post("/internal/ready", headers=headers, json={**proof, "netbird_ip": "192.0.2.1"})
                valid = await client.post("/internal/ready", headers=headers, json={**proof, "opensandbox": {"hostname": "sandbox", "uname": "Linux", "exit_code": 0}, "netbird_ip": "100.124.192.2"})
            assert invalid.status_code == 400
            assert public_ip.status_code == 400
            assert valid.status_code == 204
            assert (await ready_signals.wait(token, timeout=0.1))["netbird_ip"] == "100.124.192.2"
        finally:
            ready_signals.unregister(token)

    asyncio.run(request())


def test_private_failure_callback_rejects_untrusted_details_and_signals_safe_stage():
    async def request():
        token = ready_signals.register()
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                path = "/internal/failed"
                headers = {"Authorization": f"Bearer {token}"}
                assert (await client.post(path, json={"stage": "isolation_probe", "exit_code": 1})).status_code == 404
                assert (await client.post(path, headers=headers, json={"stage": "arbitrary", "exit_code": 1})).status_code == 400
                assert (await client.post(path, headers=headers, json={"stage": "isolation_probe", "exit_code": 0})).status_code == 400
                assert (await client.post(path, headers=headers, json={"stage": "isolation_probe", "exit_code": 1, "secret": "should-not-arrive"})).status_code == 400
                assert (await client.post(path, headers=headers, json={"stage": "isolation_probe", "exit_code": 1})).status_code == 204
            assert await ready_signals.wait(token, timeout=0.1) == {"failure_stage": "isolation_probe", "exit_code": 1}
        finally:
            ready_signals.unregister(token)

    asyncio.run(request())


def test_temporary_callback_server_exposes_no_other_routes():
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=callback_app), base_url="http://test") as client:
            return (
                await client.get("/"),
                await client.get("/docs"),
                await client.get("/openapi.json"),
                await client.get("/internal/ready"),
                await client.post("/internal/ready"),
                await client.post("/internal/failed"),
            )

    home, docs, schema, wrong_method, unauthorized, private_failure = asyncio.run(request())
    assert [response.status_code for response in (home, docs, schema, wrong_method, unauthorized, private_failure)] == [404, 404, 404, 405, 404, 404]


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

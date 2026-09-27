import ast
import asyncio
import base64
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from control_plane import (
    ControlPlaneInstances, bootstrap_control_plane, control_listener_addresses,
    control_plane_user_data, install_control_credentials, render_control_env, serve_control_plane,
)
from main import callback_app, ready_signals

REPO_SHA = "a" * 40
CALLBACK_URL = "https://cerberus.example/internal/control-ready"


def test_bootstrap_contains_one_off_netbird_key_but_no_vultr_credentials():
    script = control_plane_user_data(CALLBACK_URL, "r" * 32, "C" * 36, REPO_SHA)
    assert script.count("C" * 36) == 1
    assert "netbird up --setup-key-file" in script
    assert "systemctl stop ssh.socket ssh.service" in script
    assert script.index("systemctl stop ssh.socket ssh.service") < script.index("apt-get update")
    assert "systemctl mask ssh.socket ssh.service" in script
    assert "OpenSSH port 22 remains listening" in script
    assert script.index('umask "$saved_umask"') < script.index("git clone --depth=1")
    assert "--allow-server-ssh" in script
    assert "--enable-ssh-sftp" in script
    assert "--enable-ssh-root" not in script
    assert "--disable-ssh-auth" not in script
    assert "VULTR_API_KEY" not in script
    assert "VULTR_INFERENCE_API_KEY" not in script
    assert "CERBERUS_CONTROL_TOKEN" not in script
    assert REPO_SHA in script
    assert "ConditionPathExists=/home/cerberus/.config/cerberus/control.env" in script
    assert "PathExists=/home/cerberus/.config/cerberus/control.env" in script
    assert "serve_control_plane()" in script and "netbirdIp" in script
    launcher = script.split("cat > /usr/local/bin/cerberus-control-start <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    assert launcher.index('sys.path.insert(0, "/opt/cerberus")') < launcher.index("from control_plane import serve_control_plane")
    assert subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True).returncode == 0
    ast.parse(script.split("cat > /usr/local/bin/cerberus-control-start <<'PY'\n", 1)[1].split("\nPY\n", 1)[0])
    ast.parse(script.split("proof=$(python3 -c '", 1)[1].split("')\n", 1)[0])


def test_control_server_uses_separate_private_sockets_in_one_process(monkeypatch):
    import control_plane
    import socket
    import uvicorn

    bound = []
    served = []

    class FakeSocket:
        def setsockopt(self, *args):
            pass

        def bind(self, address):
            bound.append(address)

        def listen(self, backlog):
            pass

        def setblocking(self, value):
            pass

        def close(self):
            pass

    async def serve(sockets):
        served.extend(sockets)

    monkeypatch.setenv("CERBERUS_CONTROL_VPC_IP", "10.52.0.2")
    monkeypatch.setenv("CERBERUS_VPC_SUBNET", "10.52.0.0/24")
    monkeypatch.setattr(control_plane.subprocess, "check_output", lambda *args, **kwargs: json.dumps({
        "netbirdIp": "100.124.55.15/16", "management": {"connected": True}, "signal": {"connected": True},
    }))
    monkeypatch.setattr(control_plane, "socket", SimpleNamespace(
        AF_INET=socket.AF_INET, SOCK_STREAM=socket.SOCK_STREAM,
        SOL_SOCKET=socket.SOL_SOCKET, SO_REUSEADDR=socket.SO_REUSEADDR,
        socket=lambda *args: FakeSocket(),
    ))
    monkeypatch.setattr(uvicorn, "Config", lambda app, **kwargs: SimpleNamespace(app=app, **kwargs))
    monkeypatch.setattr(uvicorn, "Server", lambda config: SimpleNamespace(serve=serve))
    serve_control_plane()
    assert bound == [("100.124.55.15", 8000), ("10.52.0.2", 8001)]
    assert len(served) == 2
    bound.clear()
    monkeypatch.delenv("CERBERUS_VPC_SUBNET")
    serve_control_plane()
    assert bound == [("100.124.55.15", 8000)]


def test_control_listeners_keep_operator_api_on_netbird_and_vpc_callbacks_separate():
    status = {"netbirdIp": "100.124.55.15/16", "management": {"connected": True}, "signal": {"connected": True}}
    assert control_listener_addresses(status) == [("100.124.55.15", 8000)]
    assert control_listener_addresses(status, "10.52.0.2", "10.52.0.0/24") == [("100.124.55.15", 8000), ("10.52.0.2", 8001)]


@pytest.mark.parametrize("vpc_ip,vpc_subnet", [
    ("0.0.0.0", "10.52.0.0/24"), ("127.0.0.1", "10.52.0.0/24"),
    ("100.124.55.15", "100.124.0.0/16"), ("192.0.2.1", "192.0.2.0/24"),
    ("10.53.0.2", "10.52.0.0/24"), ("10.52.0.2", None),
])
def test_control_listener_refuses_public_or_unverified_vpc_address(vpc_ip, vpc_subnet):
    status = {"netbirdIp": "100.124.55.15/16", "management": {"connected": True}, "signal": {"connected": True}}
    with pytest.raises(ValueError, match="VPC"):
        control_listener_addresses(status, vpc_ip, vpc_subnet)


def test_control_launcher_resolves_repo_when_executed_outside_project(tmp_path):
    script = control_plane_user_data(CALLBACK_URL, "r" * 32, "C" * 36, REPO_SHA)
    launcher = script.split("cat > /usr/local/bin/cerberus-control-start <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    source = launcher.replace('"/opt/cerberus"', repr(str(Path(__file__).parent)))
    source = source.replace("serve_control_plane()", "print('control-plane-module-loaded')")
    path = tmp_path / "control-start.py"
    path.write_text(source)
    result = subprocess.run([sys.executable, str(path)], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0 and result.stdout.strip() == "control-plane-module-loaded"


@pytest.mark.parametrize("callback,repo_sha", [
    ("http://localhost/internal/control-ready", REPO_SHA),
    (CALLBACK_URL, "not-a-commit"),
])
def test_invalid_callback_or_commit_is_rejected(callback, repo_sha):
    with pytest.raises(ValueError):
        control_plane_user_data(callback, "r" * 32, "C" * 36, repo_sha)


def test_vultr_control_create_sends_bootstrap_only():
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(202, json={"instance": {"id": "control-123"}})

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await ControlPlaneInstances(client, "account-key").create(
                "ord", "vx1-g-2c-8g-120s", 2284, CALLBACK_URL, "r" * 32, "C" * 36, REPO_SHA
            )

    assert asyncio.run(request()) == "control-123"
    payload = json.loads(requests[0].content)
    assert payload["block_devices"] == [{"block_id": "local", "bootable": True}]
    assert payload["tags"] == ["cerberus", "cerberus-control"]
    script = base64.b64decode(payload["user_data"]).decode()
    assert "account-key" not in script
    assert "r" * 32 in script
    assert "C" * 36 in script


def test_control_bootstrap_metadata_is_replaced_after_enrollment():
    requests = []
    safe_data = base64.b64encode(b"#!/bin/sh\ntrue\n").decode()

    def respond(request):
        requests.append(request)
        if request.method == "PATCH":
            return httpx.Response(200, json={"instance": {"id": "control-123"}})
        return httpx.Response(200, json={"user_data": {"data": safe_data}})

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await ControlPlaneInstances(client, "account-key").clear_bootstrap_data("control-123")

    asyncio.run(request())
    assert json.loads(requests[0].content) == {"user_data": safe_data}
    assert requests[1].method == "GET"
    assert requests[1].url.path == "/v2/instances/control-123/user-data"


def test_control_bootstrap_scrub_retries_conflict_and_stale_metadata():
    methods = []
    safe_data = base64.b64encode(b"#!/bin/sh\ntrue\n").decode()

    def respond(request):
        methods.append(request.method)
        if request.method == "PATCH" and methods.count("PATCH") == 1:
            return httpx.Response(409, json={"error": "Instance installing"})
        if request.method == "PATCH":
            return httpx.Response(200)
        value = "old-user-data" if methods.count("GET") == 1 else safe_data
        return httpx.Response(200, json={"user_data": {"data": value}})

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await ControlPlaneInstances(client, "account-key").clear_bootstrap_data("control-123", interval=0)

    asyncio.run(request())
    assert methods == ["PATCH", "PATCH", "GET", "GET"]


def test_control_api_token_cannot_reuse_vultr_credentials():
    with pytest.raises(ValueError):
        render_control_env("A" * 36, "I" * 36, "A" * 36)


def test_control_secrets_are_transferred_only_via_ssh_stdin(monkeypatch):
    captured = {}

    def run(args, **kwargs):
        captured.update(args=args, kwargs=kwargs)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr("control_plane.subprocess.run", run)
    payload = render_control_env("A" * 36, "I" * 36, "C" * 43)
    install_control_credentials("100.124.192.2", payload)
    assert "VULTR_API_KEY=" in payload and "VULTR_INFERENCE_API_KEY=" in payload
    assert captured["kwargs"]["input"] == payload.encode()
    assert "A" * 36 not in str(captured["args"])
    assert "C" * 43 not in str(captured["args"])
    assert captured["kwargs"]["capture_output"] is True


def test_control_bootstrap_requires_api_token_before_provisioning(monkeypatch):
    monkeypatch.setattr("connectivity.load_keys", lambda: ("account-key", "inference-key"))
    monkeypatch.setattr("jobs.control_token", lambda: None)
    monkeypatch.setenv("NETBIRD_CONTROL_SETUP_KEY", "C" * 36)
    with pytest.raises(RuntimeError, match="CERBERUS_CONTROL_TOKEN"):
        asyncio.run(bootstrap_control_plane(CALLBACK_URL))


def test_control_ready_callback_requires_token_and_private_ip():
    async def request():
        token = ready_signals.register()
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=callback_app), base_url="http://test") as client:
                path = "/internal/control-ready"
                assert (await client.post(path, json={"netbird_ip": "100.124.192.2", "repo_commit": REPO_SHA, "bootstrapped": True})).status_code == 404
                headers = {"Authorization": f"Bearer {token}"}
                assert (await client.post(path, headers=headers, json={"netbird_ip": "192.0.2.1", "repo_commit": REPO_SHA, "bootstrapped": True})).status_code == 400
                proof = {"netbird_ip": "100.124.192.2", "repo_commit": REPO_SHA, "bootstrapped": True}
                assert (await client.post(path, headers=headers, json=proof)).status_code == 204
            assert await ready_signals.wait(token, timeout=0.1) == proof
        finally:
            ready_signals.unregister(token)

    asyncio.run(request())

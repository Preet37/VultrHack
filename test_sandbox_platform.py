import ast
import asyncio
import subprocess
import tomllib

import httpx
import pytest

from instance_lifecycle import docker_user_data
from sandbox_platform import build_opensandbox_config, check_private_endpoint, netbird_enrollment_user_data, opensandbox_spike_user_data


def host_state():
    return {"DefaultRuntime": "runsc", "Runtimes": {"runsc": {}}}, {
        "Name": "cerberus-internal", "Internal": True, "Driver": "bridge",
        "Options": {"com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"},
    }


def test_config_is_authenticated_and_confined_to_gvisor_internal_network():
    rendered, key = build_opensandbox_config(*host_state())
    config = tomllib.loads(rendered)
    assert len(key) >= 32
    assert config["server"] == {"host": "127.0.0.1", "port": 8080, "api_key": key}
    assert config["runtime"] == {"type": "docker", "execd_image": "opensandbox/execd:v1.0.22"}
    assert config["secure_runtime"] == {"type": "gvisor", "docker_runtime": "runsc"}
    assert config["docker"]["network_mode"] == "cerberus-internal"
    assert config["docker"]["no_new_privileges"] is True
    assert "egress" not in config
    assert "credential_proxy" not in config


@pytest.mark.parametrize("docker_info,network", [
    ({"DefaultRuntime": "runc", "Runtimes": {"runsc": {}}}, host_state()[1]),
    ({"DefaultRuntime": "runsc", "Runtimes": {}}, host_state()[1]),
    (host_state()[0], {"Name": "bridge", "Internal": False, "Driver": "bridge"}),
    (host_state()[0], {"Name": "cerberus-internal", "Internal": False, "Driver": "bridge"}),
    (host_state()[0], {"Name": "cerberus-internal", "Internal": True, "Driver": "bridge"}),
    (host_state()[0], {"Name": "cerberus-internal", "Internal": True, "Driver": "bridge", "Options": {"com.docker.network.bridge.host_binding_ipv4": "0.0.0.0"}}),
])
def test_insecure_runtime_or_network_is_rejected(docker_info, network):
    with pytest.raises(ValueError, match="gVisor|internal"):
        build_opensandbox_config(docker_info, network)


def test_spike_bootstrap_is_local_only_pinned_and_syntactically_valid():
    script = docker_user_data("https://cerberus.example/internal/ready", "ready-token", opensandbox_spike=True)
    assert "opensandbox-server==0.2.3" in script
    assert "opensandbox==0.1.16" in script
    assert "docker network create --internal --driver bridge --opt com.docker.network.bridge.host_binding_ipv4=127.0.0.1 cerberus-internal" in script
    assert "sandbox_platform.py" in script
    assert "build_opensandbox_config" in script
    assert '"http://$server_host:8080/health"' in script
    assert "sandbox.commands.run('hostname; uname -a')" in script
    assert "HostIp" in script
    assert "await sandbox.destroy()" in script
    assert "--data-binary \"$proof\"" in script
    assert "account-key" not in script
    assert subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True).returncode == 0
    ast.parse(script.split("/root/opensandbox-venv/bin/python3 - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0])


def test_private_server_binds_only_to_connected_netbird_address():
    status = {
        "profileName": "cerberus", "management": {"connected": True},
        "signal": {"connected": True}, "netbirdIp": "100.124.192.1/16",
    }
    rendered, _ = build_opensandbox_config(*host_state(), netbird_status=status)
    assert tomllib.loads(rendered)["server"]["host"] == "100.124.192.1"


@pytest.mark.parametrize("status", [
    {"management": {"connected": False}, "signal": {"connected": True}, "netbirdIp": "100.124.192.1/16"},
    {"management": {"connected": True}, "signal": {"connected": False}, "netbirdIp": "100.124.192.1/16"},
    {"management": {"connected": True}, "signal": {"connected": True}, "netbirdIp": "0.0.0.0"},
    {"management": {"connected": True}, "signal": {"connected": True}, "netbirdIp": "192.0.2.10/24"},
    {"management": {"connected": True}, "signal": {"connected": True}, "netbirdIp": ""},
])
def test_private_binding_rejects_disconnected_or_non_mesh_addresses(status):
    with pytest.raises(ValueError, match="NetBird"):
        build_opensandbox_config(*host_state(), netbird_status=status)


def test_netbird_spike_binds_server_to_peer_and_runs_fixed_local_check():
    script = docker_user_data("https://cerberus.example/internal/ready", "ready-token", opensandbox_spike=True, netbird_setup_key="A" * 36)
    assert "netbird up --setup-key-file" in script
    assert "netbird_status=status" in script
    assert 'data["netbird_ip"]' in script
    assert script.count("A" * 36) == 1
    assert "account-key" not in script
    assert "--data-binary \"$proof\"" in script
    assert subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True).returncode == 0


def test_private_endpoint_is_healthy_and_refuses_unauthenticated_listing():
    paths = []

    def respond(request):
        paths.append(str(request.url))
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "healthy"})
        return httpx.Response(401)

    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await check_private_endpoint(client, "100.124.192.2")

    asyncio.run(request())
    assert paths == ["http://100.124.192.2:8080/health", "http://100.124.192.2:8080/v1/sandboxes"]


def test_private_endpoint_rejects_unauthenticated_access():
    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"status": "healthy"}))) as client:
            await check_private_endpoint(client, "100.124.192.2")

    with pytest.raises(RuntimeError, match="unauthenticated"):
        asyncio.run(request())


def test_private_endpoint_rejects_public_address_before_request():
    async def request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: pytest.fail("Network call"))) as client:
            await check_private_endpoint(client, "192.0.2.1")

    with pytest.raises(ValueError, match="NetBird"):
        asyncio.run(request())


def test_one_off_netbird_key_is_used_only_from_a_root_only_file():
    script = netbird_enrollment_user_data("A" * 36)
    assert "netbird=0.79.0" in script
    assert "netbird up --setup-key-file /root/cerberus-netbird-setup.key" in script
    assert "umask 077" in script
    assert "netbird status --check ready" in script
    assert script.count("A" * 36) == 1
    assert subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True).returncode == 0


@pytest.mark.parametrize("key", ["", "short", "invalid\nkey", "bad key", "A" * 129])
def test_invalid_netbird_key_is_rejected(key):
    with pytest.raises(ValueError):
        netbird_enrollment_user_data(key)


def test_weak_api_key_is_rejected_without_echoing_it(monkeypatch):
    monkeypatch.setattr("sandbox_platform.secrets.token_urlsafe", lambda _: "short-key")
    with pytest.raises(ValueError) as error:
        build_opensandbox_config(*host_state())
    assert "short-key" not in str(error.value)

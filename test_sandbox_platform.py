import ast
import subprocess
import tomllib

import pytest

from instance_lifecycle import docker_user_data
from sandbox_platform import build_opensandbox_config, opensandbox_spike_user_data


def host_state():
    return {"DefaultRuntime": "runsc", "Runtimes": {"runsc": {}}}, {
        "Name": "cerberus-internal", "Internal": True, "Driver": "bridge"
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
])
def test_insecure_runtime_or_network_is_rejected(docker_info, network):
    with pytest.raises(ValueError, match="gVisor|internal"):
        build_opensandbox_config(docker_info, network)


def test_spike_bootstrap_is_local_only_pinned_and_syntactically_valid():
    script = docker_user_data("https://cerberus.example/internal/ready", "ready-token", opensandbox_spike=True)
    assert "opensandbox-server==0.2.3" in script
    assert "opensandbox==0.1.16" in script
    assert "docker network create --internal --driver bridge cerberus-internal" in script
    assert "sandbox_platform.py" in script
    assert "build_opensandbox_config" in script
    assert "localhost:8080" in script
    assert "sandbox.commands.run('hostname; uname -a')" in script
    assert "await sandbox.destroy()" in script
    assert "--data-binary \"$proof\"" in script
    assert "account-key" not in script
    assert subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True).returncode == 0
    ast.parse(script.split("/root/opensandbox-venv/bin/python3 - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0])


def test_weak_api_key_is_rejected_without_echoing_it(monkeypatch):
    monkeypatch.setattr("sandbox_platform.secrets.token_urlsafe", lambda _: "short-key")
    with pytest.raises(ValueError) as error:
        build_opensandbox_config(*host_state())
    assert "short-key" not in str(error.value)

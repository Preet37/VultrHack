import ast
import asyncio
import base64
import copy
import json
import subprocess
import tomllib
import zlib
from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest

from instance_lifecycle import docker_user_data
from sandbox_platform import (
    assert_closed_probe_port, build_opensandbox_config, check_private_endpoint, host_drop_packets,
    install_forward_drop_probe, install_host_drop_probe, install_ipv6_drop_probe, netbird_enrollment_user_data, opensandbox_spike_user_data,
    recent_host_drop_log, verified_probe_bridge,
)


def host_state():
    return {"DefaultRuntime": "runsc", "Runtimes": {"runsc": {}}, "ServerVersion": "28.5.1"}, {
        "Name": "cerberus-internal", "Internal": True, "Driver": "bridge", "EnableIPv6": False,
        "Options": {"com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"},
    }


def embedded_smoke_source(script):
    marker = " | base64 -d | /root/opensandbox-venv/bin/python3 -c 'import sys,zlib; exec(zlib.decompress(sys.stdin.buffer.read()))'"
    encoded = script.split(marker, 1)[0].rsplit("printf '%s' ", 1)[1]
    return zlib.decompress(base64.b64decode(encoded)).decode()


def probe_state():
    network = host_state()[1]
    network.update({"Id": "a" * 64, "IPAM": {"Config": [{"Subnet": "172.23.0.0/16", "Gateway": "172.23.0.1"}]}})
    bridge = "br-" + "a" * 12
    links = [{"ifname": bridge, "linkinfo": {"info_kind": "bridge"}}]
    addresses = [{"ifname": bridge, "addr_info": [{"family": "inet", "local": "172.23.0.1", "prefixlen": 16}]}]
    return network, links, addresses


def test_docker_without_internal_dns_forwarding_fix_is_rejected():
    docker_info, network = host_state()
    with pytest.raises(ValueError, match="Docker 26"):
        build_opensandbox_config({**docker_info, "ServerVersion": "25.0.5"}, network)


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
    (host_state()[0], {**host_state()[1], "EnableIPv6": True}),
])
def test_insecure_runtime_or_network_is_rejected(docker_info, network):
    with pytest.raises(ValueError, match="gVisor|internal"):
        build_opensandbox_config(docker_info, network)


def test_spike_bootstrap_is_local_only_pinned_and_syntactically_valid():
    script = docker_user_data("https://cerberus.example/internal/ready", "ready-token", opensandbox_spike=True)
    assert "opensandbox-server==0.2.3" in script
    assert "opensandbox==0.1.16" in script
    assert "docker network create --internal --ipv6=false --driver bridge --opt com.docker.network.bridge.host_binding_ipv4=127.0.0.1 cerberus-internal" in script
    assert "sandbox_platform.py" in script
    assert "build_opensandbox_config" in script
    assert "os.umask(0o077)" in script
    assert '"http://$server_host:8080/health"' in script
    smoke = embedded_smoke_source(script)
    assert "sandbox.commands.run('hostname; uname -a')" in smoke
    assert "sandbox.commands.run('nc -w 3 192.0.2.1 65000')" in smoke
    assert "sandbox.commands.run('nslookup example.com')" in smoke
    assert "sandbox.commands.run(f'nc -w 3 {gateway} 65000')" in smoke
    assert smoke.index("assert_closed_probe_port(gateway)") < smoke.index("install_host_drop_probe(bridge)") < smoke.index("install_forward_drop_probe(bridge)") < smoke.index("install_ipv6_drop_probe(bridge)") < smoke.index("sandbox = await Sandbox.create")
    assert "after <= before" in smoke
    assert "'host_drop_packets_delta': after - before" in smoke
    assert "'kernel_drop_log': recent_host_drop_log(bridge, gateway, since)" in smoke
    assert "set(networks) != {'cerberus-internal'}" in smoke
    assert "HostIp" in smoke
    assert "await sandbox.destroy()" in smoke
    assert "--data-binary \"$proof\"" in script
    assert "account-key" not in script
    assert subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True).returncode == 0
    ast.parse(smoke)


@pytest.mark.parametrize("change", [
    lambda network, links, addresses: network.update({"Id": "not-a-network-id"}),
    lambda network, links, addresses: network.update({"Internal": False}),
    lambda network, links, addresses: network.update({"EnableIPv6": True}),
    lambda network, links, addresses: network.pop("EnableIPv6"),
    lambda network, links, addresses: network.update({"Name": "bridge"}),
    lambda network, links, addresses: network["Options"].update({"com.docker.network.bridge.name": "custom"}),
    lambda network, links, addresses: network["IPAM"]["Config"][0].update({"Gateway": "172.24.0.1"}),
    lambda network, links, addresses: links[0].update({"ifname": "docker0"}),
    lambda network, links, addresses: links[0]["linkinfo"].update({"info_kind": "veth"}),
    lambda network, links, addresses: addresses[0]["addr_info"][0].update({"local": "172.23.0.2"}),
    lambda network, links, addresses: addresses[0]["addr_info"][0].update({"prefixlen": 24}),
])
def test_host_probe_rejects_unverified_network_or_gateway(change):
    network, links, addresses = copy.deepcopy(probe_state())
    change(network, links, addresses)
    with pytest.raises(ValueError, match="Host probe"):
        verified_probe_bridge(network, links, addresses)


def test_host_probe_refuses_bridge_subnet_overlapping_test_net_1():
    network, links, addresses = probe_state()
    network["IPAM"]["Config"][0].update({"Subnet": "192.0.2.0/24", "Gateway": "192.0.2.1"})
    addresses[0]["addr_info"][0].update({"local": "192.0.2.1", "prefixlen": 24})
    with pytest.raises(ValueError, match="Host probe"):
        verified_probe_bridge(network, links, addresses)


def test_host_probe_derives_bridge_from_network_id_and_checks_real_gateway():
    assert verified_probe_bridge(*probe_state()) == ("br-" + "a" * 12, "172.23.0.1")


def test_closed_port_check_binds_only_the_verified_gateway_without_listening(monkeypatch):
    bound = []

    class ProbeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            bound.append("closed")

        def bind(self, address):
            bound.append(address)

    monkeypatch.setattr("sandbox_platform.socket.socket", lambda family, kind: ProbeSocket())
    assert_closed_probe_port("172.23.0.1")
    assert bound == [("172.23.0.1", 65000), "closed"]


def test_host_probe_fails_closed_when_probe_port_is_in_use(monkeypatch):
    class OccupiedPort:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def bind(self, address):
            raise OSError("port in use")

    monkeypatch.setattr("sandbox_platform.socket.socket", lambda family, kind: OccupiedPort())
    with pytest.raises(OSError, match="port in use"):
        assert_closed_probe_port("172.23.0.1")


def test_host_probe_installs_closed_input_chain_before_attaching_bridge(monkeypatch):
    calls = []

    def run(command, **kwargs):
        assert kwargs == {"check": True}
        calls.append(command)

    monkeypatch.setattr("sandbox_platform.subprocess.run", run)
    install_host_drop_probe("br-" + "a" * 12)
    assert len(calls) == 7
    assert calls[0][4:] == ["-N", "CERBERUS_OS_HOST"]
    assert calls[1][4:] == ["-A", "CERBERUS_OS_HOST", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]
    assert "LOG" in calls[2] and "cerberus-os-drop " in calls[2]
    assert calls[3][4:] == ["-A", "CERBERUS_OS_HOST", "-j", "DROP"]
    assert calls[4][4:] == ["-I", "INPUT", "1", "-i", "br-" + "a" * 12, "-j", "CERBERUS_OS_HOST"]
    assert calls[5][4:] == ["-C", "INPUT", "-i", "br-" + "a" * 12, "-j", "CERBERUS_OS_HOST"]
    assert calls[6][4:] == ["-C", "CERBERUS_OS_HOST", "-j", "DROP"]
    assert all(command[:4] == ["iptables", "-w", "-t", "filter"] for command in calls)


def test_forward_probe_only_blocks_packets_leaving_the_verified_bridge(monkeypatch):
    calls = []
    monkeypatch.setattr("sandbox_platform.subprocess.run", lambda command, **kwargs: calls.append(command))
    install_forward_drop_probe("br-" + "a" * 12)
    assert calls[0][4:] == ["-N", "CERBERUS_OS_FWD"]
    assert "LOG" in calls[1] and "cerberus-fwd-drop " in calls[1]
    assert calls[2][4:] == ["-A", "CERBERUS_OS_FWD", "-j", "DROP"]
    assert calls[3][4:] == ["-I", "FORWARD", "1", "-i", "br-" + "a" * 12, "!", "-o", "br-" + "a" * 12, "-j", "CERBERUS_OS_FWD"]
    assert calls[4][4:] == ["-C", "FORWARD", "-i", "br-" + "a" * 12, "!", "-o", "br-" + "a" * 12, "-j", "CERBERUS_OS_FWD"]
    assert calls[5][4:] == ["-C", "CERBERUS_OS_FWD", "-j", "DROP"]


def test_forward_probe_does_not_attach_without_drop_rule(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if "DROP" in command:
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr("sandbox_platform.subprocess.run", run)
    with pytest.raises(subprocess.CalledProcessError):
        install_forward_drop_probe("br-" + "a" * 12)
    assert not any("FORWARD" in command for command in calls)


def test_ipv6_probe_blocks_host_and_external_forwarding_on_scoped_bridge(monkeypatch):
    calls = []
    monkeypatch.setattr("sandbox_platform.subprocess.run", lambda command, **kwargs: calls.append(command))
    install_ipv6_drop_probe("br-" + "a" * 12)
    assert all(call[:4] == ["ip6tables", "-w", "-t", "filter"] for call in calls)
    assert [call[5] for call in calls if call[4] == "-N"] == ["CERBERUS_OS_HOST6", "CERBERUS_OS_FWD6"]
    assert any(call[4:] == ["-I", "INPUT", "1", "-i", "br-" + "a" * 12, "-j", "CERBERUS_OS_HOST6"] for call in calls)
    assert any(call[4:] == ["-I", "FORWARD", "1", "-i", "br-" + "a" * 12, "!", "-o", "br-" + "a" * 12, "-j", "CERBERUS_OS_FWD6"] for call in calls)
    assert sum(call[4] == "-A" and call[-1] == "DROP" for call in calls) == 2


def test_host_probe_does_not_attach_incomplete_drop_chain(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if "DROP" in command:
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr("sandbox_platform.subprocess.run", run)
    with pytest.raises(subprocess.CalledProcessError):
        install_host_drop_probe("br-" + "a" * 12)
    assert not any("INPUT" in command for command in calls)


@pytest.mark.parametrize("packets", [0, 3])
def test_host_probe_reads_actual_drop_rule_packet_counter(monkeypatch, packets):
    def check_output(command, **kwargs):
        assert command == ["iptables", "-w", "-t", "filter", "-L", "CERBERUS_OS_HOST", "--line-numbers", "-n", "-v", "-x"]
        assert kwargs == {"text": True}
        return ("Chain CERBERUS_OS_HOST (1 references)\n"
                " pkts bytes target prot opt in out source destination\n"
                " 1 99 5940 ACCEPT all -- * * 0.0.0.0/0 0.0.0.0/0\n"
                " 2 1 60 LOG all -- * * 0.0.0.0/0 0.0.0.0/0\n"
                f" 3 {packets} 180 DROP all -- * * 0.0.0.0/0 0.0.0.0/0\n")

    monkeypatch.setattr("sandbox_platform.subprocess.check_output", check_output)
    assert host_drop_packets() == packets


def test_host_probe_rejects_missing_drop_counter(monkeypatch):
    monkeypatch.setattr("sandbox_platform.subprocess.check_output", lambda *args, **kwargs: "Chain CERBERUS_OS_HOST (1 references)\n")
    with pytest.raises(RuntimeError, match="counter"):
        host_drop_packets()


def test_kernel_log_is_genuine_scoped_bounded_and_optional(monkeypatch):
    line = "cerberus-os-drop IN=br-aaaaaaaaaaaa OUT= SRC=172.23.0.2 DST=172.23.0.1 DPT=65000 " + "X" * 700
    journal = "cerberus-os-drop IN=br-other OUT= DST=172.23.0.1 DPT=65000\n" + line + "\n"

    def run(command, **kwargs):
        assert command == ["journalctl", "-k", "--since", "@123", "-n", "100", "--no-pager", "--output=cat"]
        assert kwargs == {"capture_output": True, "text": True, "timeout": 5}
        return SimpleNamespace(returncode=0, stdout=journal)

    monkeypatch.setattr("sandbox_platform.subprocess.run", run)
    assert recent_host_drop_log("br-aaaaaaaaaaaa", "172.23.0.1", 124) == line[:512]
    assert recent_host_drop_log("br-bbbbbbbbbbbb", "172.23.0.1", 124) is None
    monkeypatch.setattr("sandbox_platform.subprocess.run", lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=""))
    assert recent_host_drop_log("br-aaaaaaaaaaaa", "172.23.0.1", 124) is None


@pytest.mark.parametrize("runtime", ["runsc", None])
@pytest.mark.parametrize("extra_container", [False, True])
@pytest.mark.parametrize("dns_exit", [1, 0])
@pytest.mark.parametrize("test_net_exit,host_exit,counters,succeeds", [
    (1, 2, (0, 1), True),
    (0, 2, (0, 1), False),
    (1, 0, (0, 1), False),
    (1, 2, (0, 0), False),
])
def test_generated_smoke_proof_requires_denials_and_host_counter(test_net_exit, host_exit, counters, succeeds, dns_exit, extra_container, runtime):
    script = opensandbox_spike_user_data()
    encoded = script.split("printf '%s' ", 1)[1].split(" | base64 -d |", 1)[0]
    embedded = zlib.decompress(base64.b64decode(encoded)).decode()
    module = {}
    exec(compile(ast.parse(embedded), "embedded_sandbox_platform", "exec"), module)
    assert module["verified_probe_bridge"](*probe_state()) == ("br-" + "a" * 12, "172.23.0.1")

    smoke = embedded_smoke_source(script)
    function = next(node for node in ast.parse(smoke).body if isinstance(node, ast.AsyncFunctionDef) and node.name == "check")
    saved = {}
    values = {
        "/root/.opensandbox-key": "test-only-placeholder-key",
        "/root/.sandbox.toml": '[server]\nhost = "127.0.0.1"\n',
    }
    network, links, addresses = probe_state()
    responses = {
        ("docker", "network", "inspect", "cerberus-internal"): json.dumps([network]),
        ("ip", "-j", "-d", "link", "show", "dev", "br-" + "a" * 12): json.dumps(links),
        ("ip", "-j", "addr", "show", "dev", "br-" + "a" * 12): json.dumps(addresses),
        ("docker", "ps", "-q"): "test-container\nsecond-container" if extra_container else "test-container",
        ("docker", "inspect", "test-container"): json.dumps([{
            "NetworkSettings": {"Networks": {"cerberus-internal": {"NetworkID": network["Id"]}}, "Ports": {}},
            "HostConfig": {"Runtime": runtime},
        }]),
        ("docker", "inspect", "second-container"): json.dumps([{
            "NetworkSettings": {"Networks": {"cerberus-internal": {"NetworkID": network["Id"]}}, "Ports": {}},
            "HostConfig": {"Runtime": "runsc"},
        }]),
    }
    events = []

    def check_output(command, **kwargs):
        return responses[tuple(command)]

    class FakePath:
        def __init__(self, path):
            self.path = path

        def read_text(self):
            return values[self.path]

        def write_text(self, text):
            saved[self.path] = text

    class FakeCommands:
        async def run(self, command):
            events.append(command)
            codes = {"hostname; uname -a": 0, "nc -w 3 192.0.2.1 65000": test_net_exit,
                     "nslookup example.com": dns_exit, "nc -w 3 172.23.0.1 65000": host_exit}
            return SimpleNamespace(exit_code=codes[command], logs=SimpleNamespace(stdout=[SimpleNamespace(text="sandbox\nLinux test\n")]))

    class FakeSandbox:
        commands = FakeCommands()

        @classmethod
        async def create(cls, *args, **kwargs):
            assert events == ["firewall-installed", "forward-installed", "ipv6-installed"]
            return cls()

        async def destroy(self):
            events.append("destroyed")

    packet_counts = iter(counters)
    namespace = {
        "Path": FakePath, "Sandbox": FakeSandbox, "ConnectionConfig": SimpleNamespace,
        "timedelta": timedelta, "json": json, "tomllib": tomllib,
        "subprocess": SimpleNamespace(check_output=check_output), "time": SimpleNamespace(time=lambda: 124),
        "verified_probe_bridge": module["verified_probe_bridge"],
        "assert_closed_probe_port": lambda gateway: None,
        "install_host_drop_probe": lambda bridge: events.append("firewall-installed"),
        "install_forward_drop_probe": lambda bridge: events.append("forward-installed"),
        "install_ipv6_drop_probe": lambda bridge: events.append("ipv6-installed"),
        "host_drop_packets": lambda: next(packet_counts),
        "recent_host_drop_log": lambda bridge, gateway, since: None,
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), "smoke", "exec"), namespace)
    if not succeeds or dns_exit == 0 or extra_container:
        with pytest.raises(RuntimeError, match="isolation probe|exactly one"):
            asyncio.run(namespace["check"]())
        assert saved == {}
    else:
        asyncio.run(namespace["check"]())
        proof = json.loads(saved["/root/opensandbox-proof.json"])
        assert proof == {"hostname": "sandbox", "uname": "Linux test", "exit_code": 0, "isolation": {
            "network_id": "a" * 64, "bridge": "br-" + "a" * 12, "gateway": "172.23.0.1",
            "test_net_1": {"destination": "192.0.2.1:65000", "exit_code": 1},
            "dns_external": {"destination": "example.com", "exit_code": 1},
            "host_gateway": {"destination": "172.23.0.1:65000", "exit_code": 2},
            "host_drop_packets_before": 0, "host_drop_packets_after": 1, "host_drop_packets_delta": 1,
            "kernel_drop_log": None,
        }}
        assert "test-only-placeholder-key" not in saved["/root/opensandbox-proof.json"]
    assert events[-1] == "destroyed"


def test_private_sandbox_bootstrap_stays_within_conservative_user_data_budget():
    script = docker_user_data("http://100.124.55.15:8000/internal/ready", "R" * 36, True, "A" * 36, True)
    assert len(base64.b64encode(script.encode())) < 16 * 1024


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
    assert "saved_umask=$(umask)" in script
    assert "umask 077" in script
    assert 'umask "$saved_umask"' in script
    assert script.index("umask 077") < script.index("netbird up --setup-key-file") < script.index('umask "$saved_umask"')
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

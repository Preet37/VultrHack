import base64
import inspect
import ipaddress
import json
import re
import secrets
import shlex
import socket
import subprocess
import zlib

INTERNAL_NETWORK = "cerberus-internal"
HOST_BIND_OPTION = "com.docker.network.bridge.host_binding_ipv4"
BRIDGE_NAME_OPTION = "com.docker.network.bridge.name"
HOST_PROBE_CHAIN = "CERBERUS_OS_HOST"
HOST_PROBE_LOG_PREFIX = "cerberus-os-drop "
PROBE_PORT = 65000


def build_opensandbox_config(docker_info, network, netbird_status=None):
    if docker_info.get("DefaultRuntime") != "runsc" or "runsc" not in docker_info.get("Runtimes", {}):
        raise ValueError("Docker must have gVisor runsc installed as its default runtime")
    if (
        network.get("Name") != INTERNAL_NETWORK
        or network.get("Internal") is not True
        or network.get("Driver") != "bridge"
        or (network.get("Options") or {}).get(HOST_BIND_OPTION) != "127.0.0.1"
    ):
        raise ValueError("OpenSandbox requires an internal Docker bridge with localhost-only published ports")

    host = "127.0.0.1"
    if netbird_status is not None:
        if (
            not isinstance(netbird_status, dict)
            or not isinstance(netbird_status.get("management"), dict)
            or not isinstance(netbird_status.get("signal"), dict)
            or netbird_status["management"].get("connected") is not True
            or netbird_status["signal"].get("connected") is not True
        ):
            raise ValueError("NetBird management and signal must be connected")
        try:
            address = ipaddress.ip_interface(netbird_status["netbirdIp"]).ip
        except (KeyError, TypeError, ValueError):
            raise ValueError("NetBird must assign a valid overlay IPv4 address") from None
        if address not in ipaddress.ip_network("100.64.0.0/10"):
            raise ValueError("NetBird address must be inside the overlay range")
        host = str(address)

    api_key = secrets.token_urlsafe(32)
    if len(api_key) < 32:
        raise ValueError("Generated OpenSandbox API key is invalid")
    config = f'''[server]
host = {json.dumps(host)}
port = 8080
api_key = {json.dumps(api_key)}

[runtime]
type = "docker"
execd_image = "opensandbox/execd:v1.0.22"

[docker]
network_mode = "{INTERNAL_NETWORK}"
drop_capabilities = ["AUDIT_WRITE", "MKNOD", "NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_TIME", "SYS_TTY_CONFIG"]
no_new_privileges = true
pids_limit = 512

[secure_runtime]
type = "gvisor"
docker_runtime = "runsc"
'''
    return config, api_key


def verified_probe_bridge(network, links, addresses):
    if not isinstance(network, dict) or (
        network.get("Name") != INTERNAL_NETWORK
        or network.get("Internal") is not True
        or network.get("Driver") != "bridge"
    ):
        raise ValueError("Host probe requires the dedicated internal Docker bridge")
    options = network.get("Options") or {}
    network_id = network.get("Id")
    if (
        not isinstance(options, dict)
        or options.get(HOST_BIND_OPTION) != "127.0.0.1"
        or BRIDGE_NAME_OPTION in options
        or not isinstance(network_id, str)
        or not re.fullmatch(r"[0-9a-f]{64}", network_id)
    ):
        raise ValueError("Host probe requires an unmodified internal bridge network ID")
    bridge = "br-" + network_id[:12]
    try:
        configs = network["IPAM"]["Config"]
        if not isinstance(configs, list) or len(configs) != 1:
            raise ValueError
        subnet = ipaddress.IPv4Network(configs[0]["Subnet"])
        gateway = ipaddress.IPv4Address(configs[0]["Gateway"])
        link = links[0]
        address = addresses[0]
        valid = (
            len(links) == len(addresses) == 1
            and gateway in subnet
            and not subnet.overlaps(ipaddress.IPv4Network("192.0.2.0/24"))
            and gateway not in (subnet.network_address, subnet.broadcast_address)
            and link["ifname"] == address["ifname"] == bridge
            and link["linkinfo"]["info_kind"] == "bridge"
            and any(
                item.get("family") == "inet"
                and item.get("local") == str(gateway)
                and item.get("prefixlen") == subnet.prefixlen
                for item in address["addr_info"]
            )
        )
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        raise ValueError("Host probe could not verify the Docker bridge gateway") from None
    if not valid:
        raise ValueError("Host probe could not verify the Docker bridge gateway")
    return bridge, str(gateway)


def assert_closed_probe_port(gateway):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((gateway, PROBE_PORT))


def install_host_drop_probe(bridge):
    base = ["iptables", "-w", "-t", "filter"]
    subprocess.run(base + ["-N", HOST_PROBE_CHAIN], check=True)
    subprocess.run(base + ["-A", HOST_PROBE_CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True)
    subprocess.run(base + ["-A", HOST_PROBE_CHAIN, "-m", "limit", "--limit", "2/second", "--limit-burst", "4", "-j", "LOG", "--log-prefix", HOST_PROBE_LOG_PREFIX], check=True)
    subprocess.run(base + ["-A", HOST_PROBE_CHAIN, "-j", "DROP"], check=True)
    subprocess.run(base + ["-I", "INPUT", "1", "-i", bridge, "-j", HOST_PROBE_CHAIN], check=True)
    subprocess.run(base + ["-C", "INPUT", "-i", bridge, "-j", HOST_PROBE_CHAIN], check=True)
    subprocess.run(base + ["-C", HOST_PROBE_CHAIN, "-j", "DROP"], check=True)


def host_drop_packets():
    output = subprocess.check_output(
        ["iptables", "-w", "-t", "filter", "-L", HOST_PROBE_CHAIN, "--line-numbers", "-n", "-v", "-x"],
        text=True,
    )
    if not output.startswith(f"Chain {HOST_PROBE_CHAIN} ("):
        raise RuntimeError("Host DROP probe chain is missing")
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0] == "3" and fields[3] == "DROP" and fields[1].isdigit():
            return int(fields[1])
    raise RuntimeError("Host DROP probe counter is missing")


def recent_host_drop_log(bridge, gateway, since):
    try:
        result = subprocess.run(
            ["journalctl", "-k", "--since", f"@{int(since) - 1}", "-n", "100", "--no-pager", "--output=cat"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    for line in reversed(result.stdout.splitlines()):
        if all(part in line for part in (HOST_PROBE_LOG_PREFIX, f"IN={bridge} ", f"DST={gateway} ", f"DPT={PROBE_PORT}")):
            return line[:512]
    return None


async def check_private_endpoint(client, netbird_ip):
    try:
        address = ipaddress.ip_address(netbird_ip)
    except (TypeError, ValueError):
        raise ValueError("NetBird endpoint requires an overlay IPv4 address") from None
    if address not in ipaddress.ip_network("100.64.0.0/10"):
        raise ValueError("NetBird endpoint requires an overlay IPv4 address")
    base = f"http://{address}:8080"
    health = await client.get(f"{base}/health", timeout=15)
    health.raise_for_status()
    if health.json().get("status") != "healthy":
        raise RuntimeError("OpenSandbox did not report healthy over NetBird")
    unauthenticated = await client.get(f"{base}/v1/sandboxes", timeout=15)
    if unauthenticated.status_code not in (401, 403):
        raise RuntimeError("OpenSandbox allowed unauthenticated sandbox listing")


def netbird_enrollment_user_data(setup_key, ssh_sftp=False):
    if not isinstance(setup_key, str) or not re.fullmatch(r"[A-Za-z0-9-]{32,128}", setup_key):
        raise ValueError("A valid one-off NetBird setup key is required")
    ssh_flags = " --allow-server-ssh --enable-ssh-sftp" if ssh_sftp else ""
    return (
        "curl -fsSL https://pkgs.netbird.io/debian/public.key | gpg --batch --yes --dearmor -o /usr/share/keyrings/netbird-archive-keyring.gpg\n"
        "printf '%s\\n' 'deb [signed-by=/usr/share/keyrings/netbird-archive-keyring.gpg] https://pkgs.netbird.io/debian stable main' > /etc/apt/sources.list.d/netbird.list\n"
        "apt-get update\n"
        "apt-get install -y netbird=0.79.0\n"
        "systemctl enable --now netbird\n"
        "saved_umask=$(umask)\n"
        "umask 077\n"
        f"printf '%s' {shlex.quote(setup_key)} > /root/cerberus-netbird-setup.key\n"
        "trap 'rm -f /root/cerberus-netbird-setup.key' EXIT\n"
        f"netbird up --setup-key-file /root/cerberus-netbird-setup.key{ssh_flags}\n"
        "rm /root/cerberus-netbird-setup.key\n"
        'umask "$saved_umask"\n'
        "netbird status --check ready\n"
    )


def opensandbox_spike_user_data(netbird=False):
    source = (
        "import ipaddress\nimport json\nimport re\nimport secrets\nimport socket\nimport subprocess\n"
        f"INTERNAL_NETWORK = {INTERNAL_NETWORK!r}\nHOST_BIND_OPTION = {HOST_BIND_OPTION!r}\n"
        f"BRIDGE_NAME_OPTION = {BRIDGE_NAME_OPTION!r}\nHOST_PROBE_CHAIN = {HOST_PROBE_CHAIN!r}\n"
        f"HOST_PROBE_LOG_PREFIX = {HOST_PROBE_LOG_PREFIX!r}\nPROBE_PORT = {PROBE_PORT!r}\n\n"
        + "\n".join(inspect.getsource(function) for function in (
            build_opensandbox_config, verified_probe_bridge, assert_closed_probe_port, install_host_drop_probe,
            host_drop_packets, recent_host_drop_log,
        ))
    )
    source = base64.b64encode(zlib.compress(source.encode(), level=9)).decode()
    status_line = "status = json.loads(subprocess.check_output(['netbird', 'status', '--json']))\n" if netbird else ""
    proof_line = 'data["netbird_ip"] = tomllib.loads(Path("/root/.sandbox.toml").read_text())["server"]["host"]; ' if netbird else ""
    return (
        f"printf '%s' {shlex.quote(source)} | base64 -d | python3 -c 'import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))' > /root/sandbox_platform.py\n"
        "apt-get install -y python3-venv iptables iproute2\n"
        "python3 -m venv /root/opensandbox-venv\n"
        "/root/opensandbox-venv/bin/pip install --disable-pip-version-check --no-input opensandbox-server==0.2.3 opensandbox==0.1.16\n"
        "docker network create --internal --driver bridge --opt com.docker.network.bridge.host_binding_ipv4=127.0.0.1 cerberus-internal\n"
        "docker pull opensandbox/execd:v1.0.22\n"
        "PYTHONPATH=/root python3 - <<'PY'\n"
        "import json\n"
        "import os\n"
        "import subprocess\n"
        "from pathlib import Path\n"
        "from sandbox_platform import build_opensandbox_config\n"
        "info = json.loads(subprocess.check_output(['docker', 'info', '--format', '{{json .}}']))\n"
        "network = json.loads(subprocess.check_output(['docker', 'network', 'inspect', 'cerberus-internal']))[0]\n"
        f"{status_line}"
        f"config, key = build_opensandbox_config(info, network{', netbird_status=status' if netbird else ''})\n"
        "os.umask(0o077)\n"
        "Path('/root/.sandbox.toml').write_text(config)\n"
        "Path('/root/.sandbox.toml').chmod(0o600)\n"
        "Path('/root/.opensandbox-key').write_text(key)\n"
        "Path('/root/.opensandbox-key').chmod(0o600)\n"
        "PY\n"
        "/root/opensandbox-venv/bin/opensandbox-server --config /root/.sandbox.toml > /var/log/cerberus-opensandbox.log 2>&1 &\n"
        "server_host=$(python3 -c 'import tomllib; from pathlib import Path; print(tomllib.loads(Path(\"/root/.sandbox.toml\").read_text())[\"server\"][\"host\"])')\n"
        "for attempt in $(seq 1 45); do if curl -fsS \"http://$server_host:8080/health\" >/dev/null 2>&1; then break; fi; sleep 2; done\n"
        "curl -fsS \"http://$server_host:8080/health\" >/dev/null\n"
        "/root/opensandbox-venv/bin/python3 - <<'PY'\n"
        "import asyncio\n"
        "import json\n"
        "from datetime import timedelta\n"
        "from pathlib import Path\n"
        "import tomllib\n"
        "import subprocess\n"
        "import sys\n"
        "import time\n"
        "sys.path.insert(0, '/root')\n"
        "from opensandbox import Sandbox\n"
        "from opensandbox.config import ConnectionConfig\n"
        "from sandbox_platform import verified_probe_bridge, assert_closed_probe_port, install_host_drop_probe, host_drop_packets, recent_host_drop_log\n"
        "async def check():\n"
        "    key = Path('/root/.opensandbox-key').read_text()\n"
        "    domain = tomllib.loads(Path('/root/.sandbox.toml').read_text())['server']['host'] + ':8080'\n"
        "    network = json.loads(subprocess.check_output(['docker', 'network', 'inspect', 'cerberus-internal']))[0]\n"
        "    bridge_name = 'br-' + network['Id'][:12]\n"
        "    links = json.loads(subprocess.check_output(['ip', '-j', '-d', 'link', 'show', 'dev', bridge_name]))\n"
        "    addresses = json.loads(subprocess.check_output(['ip', '-j', 'addr', 'show', 'dev', bridge_name]))\n"
        "    bridge, gateway = verified_probe_bridge(network, links, addresses)\n"
        "    assert_closed_probe_port(gateway)\n"
        "    install_host_drop_probe(bridge)\n"
        "    sandbox = await Sandbox.create('busybox:1.37.0', timeout=timedelta(minutes=2), connection_config=ConnectionConfig(domain=domain, api_key=key, use_server_proxy=True))\n"
        "    try:\n"
        "        containers = subprocess.check_output(['docker', 'ps', '-q'], text=True).split()\n"
        "        if not containers:\n"
        "            raise RuntimeError('OpenSandbox container was not found')\n"
        "        attached = False\n"
        "        for container_id in containers:\n"
        "            inspected = json.loads(subprocess.check_output(['docker', 'inspect', container_id], text=True))[0]\n"
        "            networks = inspected['NetworkSettings'].get('Networks') or {}\n"
        "            if 'cerberus-internal' in networks:\n"
        "                if set(networks) != {'cerberus-internal'} or networks['cerberus-internal'].get('NetworkID') != network['Id'] or inspected['HostConfig'].get('Runtime') not in (None, '', 'runsc'):\n"
        "                    raise RuntimeError('OpenSandbox container is not on the verified gVisor bridge')\n"
        "                attached = True\n"
        "            for bindings in (inspected['NetworkSettings'].get('Ports') or {}).values():\n"
        "                for binding in bindings or []:\n"
        "                    if binding['HostIp'] not in ('127.0.0.1', '::1'):\n"
        "                        raise RuntimeError('OpenSandbox published a port beyond loopback')\n"
        "        if not attached:\n"
        "            raise RuntimeError('OpenSandbox has no container on the verified bridge')\n"
        "        result = await sandbox.commands.run('hostname; uname -a')\n"
        "        if result.exit_code != 0:\n"
        "            raise RuntimeError('OpenSandbox smoke command failed')\n"
        "        lines = [line for item in result.logs.stdout for line in item.text.splitlines() if line]\n"
        "        if len(lines) < 2:\n"
        "            raise RuntimeError('OpenSandbox smoke output missing')\n"
        f"        test_net = await sandbox.commands.run('nc -w 3 192.0.2.1 {PROBE_PORT}')\n"
        "        if not isinstance(test_net.exit_code, int) or test_net.exit_code == 0:\n"
        "            raise RuntimeError('TEST-NET-1 isolation probe did not fail')\n"
        "        before = host_drop_packets()\n"
        "        since = time.time()\n"
        f"        host_probe = await sandbox.commands.run(f'nc -w 3 {{gateway}} {PROBE_PORT}')\n"
        "        after = host_drop_packets()\n"
        "        if not isinstance(host_probe.exit_code, int) or host_probe.exit_code == 0 or after <= before:\n"
        "            raise RuntimeError('Host DROP isolation probe did not register a denied packet')\n"
        "        isolation = {'network_id': network['Id'], 'bridge': bridge, 'gateway': gateway,\n"
        f"                     'test_net_1': {{'destination': '192.0.2.1:{PROBE_PORT}', 'exit_code': test_net.exit_code}},\n"
        f"                     'host_gateway': {{'destination': f'{{gateway}}:{PROBE_PORT}', 'exit_code': host_probe.exit_code}},\n"
        "                     'host_drop_packets_before': before, 'host_drop_packets_after': after,\n"
        "                     'host_drop_packets_delta': after - before,\n"
        "                     'kernel_drop_log': recent_host_drop_log(bridge, gateway, since)}\n"
        "        Path('/root/opensandbox-proof.json').write_text(json.dumps({'hostname': lines[0], 'uname': lines[1], 'exit_code': result.exit_code, 'isolation': isolation}))\n"
        "    finally:\n"
        "        await sandbox.destroy()\n"
        "asyncio.run(check())\n"
        "PY\n"
        "export CERBERUS_PROOF=\"$proof\"\n"
        f"proof=$(python3 -c 'import json,os,tomllib; from pathlib import Path; data=json.loads(os.environ[\"CERBERUS_PROOF\"]); data[\"opensandbox\"]=json.loads(Path(\"/root/opensandbox-proof.json\").read_text()); {proof_line}print(json.dumps(data))')\n"
    )

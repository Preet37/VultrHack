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
VPC_INTERNAL_SUBNET = "172.29.240.0/24"
HOST_BIND_OPTION = "com.docker.network.bridge.host_binding_ipv4"
BRIDGE_NAME_OPTION = "com.docker.network.bridge.name"
HOST_PROBE_CHAIN = "CERBERUS_OS_HOST"
HOST_PROBE_LOG_PREFIX = "cerberus-os-drop "
FORWARD_PROBE_CHAIN = "CERBERUS_OS_FWD"
FORWARD_PROBE_LOG_PREFIX = "cerberus-fwd-drop "
IPV6_HOST_CHAIN = "CERBERUS_OS_HOST6"
IPV6_FORWARD_CHAIN = "CERBERUS_OS_FWD6"
PROBE_PORT = 65000


def validated_vpc_network(value):
    try:
        subnet = ipaddress.ip_network(value, strict=True)
    except (TypeError, ValueError):
        raise ValueError("VPC subnet must be a private IPv4 network") from None
    private_ranges = (ipaddress.ip_network(block) for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if not isinstance(subnet, ipaddress.IPv4Network) or not any(subnet.subnet_of(block) for block in private_ranges):
        raise ValueError("VPC subnet must be a private IPv4 network")
    return subnet


def verified_vpc_address(vpc_subnet, interfaces):
    subnet = validated_vpc_network(vpc_subnet)
    try:
        addresses = [
            ipaddress.IPv4Address(entry["local"])
            for interface in interfaces if not interface["ifname"].startswith(("br-", "docker", "wt")) and interface["ifname"] != "lo"
            for entry in interface["addr_info"] if entry["family"] == "inet" and ipaddress.IPv4Address(entry["local"]) in subnet
        ]
    except (KeyError, TypeError, ValueError):
        raise ValueError("VPC host address could not be verified") from None
    if len(addresses) != 1 or addresses[0] in (subnet.network_address, subnet.broadcast_address):
        raise ValueError("VPC host requires exactly one private address on the assigned subnet")
    return str(addresses[0])


def build_opensandbox_config(docker_info, network, netbird_status=None, vpc_address=None, vpc_subnet=None):
    if docker_info.get("DefaultRuntime") != "runsc" or "runsc" not in docker_info.get("Runtimes", {}):
        raise ValueError("Docker must have gVisor runsc installed as its default runtime")
    version = re.match(r"^(\d+)\.(\d+)(?:\.|$)", str(docker_info.get("ServerVersion", "")))
    if version is None or (int(version[1]), int(version[2])) < (26, 0):
        raise ValueError("Docker 26 or newer is required for internal network DNS isolation")
    if (
        network.get("Name") != INTERNAL_NETWORK
        or network.get("Internal") is not True
        or network.get("Driver") != "bridge"
        or network.get("EnableIPv6") is not False
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
    if vpc_address is not None or vpc_subnet is not None:
        if netbird_status is not None:
            raise ValueError("VPC and NetBird endpoints cannot share a sandbox server")
        subnet = validated_vpc_network(vpc_subnet)
        try:
            address = ipaddress.IPv4Address(vpc_address)
            docker_subnet = ipaddress.ip_network(network["IPAM"]["Config"][0]["Subnet"])
        except (KeyError, IndexError, TypeError, ValueError):
            raise ValueError("VPC sandbox endpoint needs a verified bridge and address") from None
        if address not in subnet or address in (subnet.network_address, subnet.broadcast_address) or subnet.overlaps(docker_subnet) or docker_subnet != ipaddress.ip_network(VPC_INTERNAL_SUBNET):
            raise ValueError("VPC sandbox address or dedicated Docker subnet is invalid")
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
        or network.get("EnableIPv6") is not False
    ):
        raise ValueError("Host probe requires the dedicated internal Docker bridge without IPv6")
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


def install_forward_drop_probe(bridge):
    base = ["iptables", "-w", "-t", "filter"]
    subprocess.run(base + ["-N", FORWARD_PROBE_CHAIN], check=True)
    subprocess.run(base + ["-A", FORWARD_PROBE_CHAIN, "-m", "limit", "--limit", "2/second", "--limit-burst", "4", "-j", "LOG", "--log-prefix", FORWARD_PROBE_LOG_PREFIX], check=True)
    subprocess.run(base + ["-A", FORWARD_PROBE_CHAIN, "-j", "DROP"], check=True)
    subprocess.run(base + ["-I", "FORWARD", "1", "-i", bridge, "!", "-o", bridge, "-j", FORWARD_PROBE_CHAIN], check=True)
    subprocess.run(base + ["-C", "FORWARD", "-i", bridge, "!", "-o", bridge, "-j", FORWARD_PROBE_CHAIN], check=True)
    subprocess.run(base + ["-C", FORWARD_PROBE_CHAIN, "-j", "DROP"], check=True)


def install_ipv6_drop_probe(bridge):
    base = ["ip6tables", "-w", "-t", "filter"]
    for chain, hook, match, prefix in (
        (IPV6_HOST_CHAIN, "INPUT", ["-i", bridge], "cerberus-os6-drop "),
        (IPV6_FORWARD_CHAIN, "FORWARD", ["-i", bridge, "!", "-o", bridge], "cerberus-fwd6-drop "),
    ):
        subprocess.run(base + ["-N", chain], check=True)
        subprocess.run(base + ["-A", chain, "-m", "limit", "--limit", "2/second", "--limit-burst", "4", "-j", "LOG", "--log-prefix", prefix], check=True)
        subprocess.run(base + ["-A", chain, "-j", "DROP"], check=True)
        subprocess.run(base + ["-I", hook, "1", *match, "-j", chain], check=True)
        subprocess.run(base + ["-C", hook, *match, "-j", chain], check=True)
        subprocess.run(base + ["-C", chain, "-j", "DROP"], check=True)


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


async def check_private_endpoint(client, netbird_ip, vpc_subnet=None):
    try:
        address = ipaddress.ip_address(netbird_ip)
    except (TypeError, ValueError):
        raise ValueError("VPC or NetBird endpoint requires a private IPv4 address") from None
    if vpc_subnet is not None:
        subnet = validated_vpc_network(vpc_subnet)
        if not isinstance(address, ipaddress.IPv4Address) or address not in subnet or address in (subnet.network_address, subnet.broadcast_address):
            raise ValueError("VPC endpoint is outside the approved private subnet")
    elif address not in ipaddress.ip_network("100.64.0.0/10"):
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


def opensandbox_spike_user_data(netbird=False, report_stages=False, vpc_subnet=None):
    def stage_line(name):
        return f"cerberus_report_stage {name}\n" if report_stages else f"CERBERUS_STAGE={name}\n"

    if vpc_subnet is not None:
        vpc_subnet = str(validated_vpc_network(vpc_subnet))
    if netbird and vpc_subnet:
        raise ValueError("VPC and NetBird sandbox modes cannot be combined")
    functions = (
        build_opensandbox_config, verified_probe_bridge, assert_closed_probe_port, install_host_drop_probe,
        install_forward_drop_probe, install_ipv6_drop_probe, host_drop_packets, recent_host_drop_log,
    )
    if vpc_subnet:
        functions = (validated_vpc_network, verified_vpc_address) + functions
    source = (
        "import ipaddress\nimport json\nimport re\nimport secrets\nimport socket\nimport subprocess\n"
        f"INTERNAL_NETWORK = {INTERNAL_NETWORK!r}\nVPC_INTERNAL_SUBNET = {VPC_INTERNAL_SUBNET!r}\nHOST_BIND_OPTION = {HOST_BIND_OPTION!r}\n"
        f"BRIDGE_NAME_OPTION = {BRIDGE_NAME_OPTION!r}\nHOST_PROBE_CHAIN = {HOST_PROBE_CHAIN!r}\n"
        f"HOST_PROBE_LOG_PREFIX = {HOST_PROBE_LOG_PREFIX!r}\nFORWARD_PROBE_CHAIN = {FORWARD_PROBE_CHAIN!r}\n"
        f"FORWARD_PROBE_LOG_PREFIX = {FORWARD_PROBE_LOG_PREFIX!r}\nIPV6_HOST_CHAIN = {IPV6_HOST_CHAIN!r}\n"
        f"IPV6_FORWARD_CHAIN = {IPV6_FORWARD_CHAIN!r}\nPROBE_PORT = {PROBE_PORT!r}\n\n"
        + "\n".join(inspect.getsource(function) for function in functions)
    )
    source = base64.b64encode(zlib.compress(source.encode(), level=9)).decode()
    status_line = "status = json.loads(subprocess.check_output(['netbird', 'status', '--json']))\n" if netbird else ""
    if vpc_subnet:
        status_line = "interfaces = json.loads(subprocess.check_output(['ip', '-j', 'addr']))\n" + f"vpc_ip = verified_vpc_address({vpc_subnet!r}, interfaces)\n"
    config_args = ", netbird_status=status" if netbird else f", vpc_address=vpc_ip, vpc_subnet={vpc_subnet!r}" if vpc_subnet else ""
    proof_line = 'data["netbird_ip"] = tomllib.loads(Path("/root/.sandbox.toml").read_text())["server"]["host"]; ' if netbird else 'data["vpc_ip"] = tomllib.loads(Path("/root/.sandbox.toml").read_text())["server"]["host"]; ' if vpc_subnet else ""
    subnet_option = f"--subnet={VPC_INTERNAL_SUBNET} " if vpc_subnet else ""
    firewall_line = (
        f"command -v iptables >/dev/null 2>&1 && iptables -I INPUT -p tcp -s {vpc_subnet} --dport 8080 -j ACCEPT || :\n"
        if vpc_subnet else ""
    )
    script = (
        f"printf '%s' {shlex.quote(source)} | base64 -d | python3 -c 'import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))' > /root/sandbox_platform.py\n"
        f"{stage_line('opensandbox_dependencies')}"
        "python3 -c 'import json; from pathlib import Path; p=Path(\"/etc/docker/daemon.json\"); config=json.loads(p.read_text()); config[\"default-runtime\"]=\"runsc\"; p.write_text(json.dumps(config))'\n"
        "systemctl restart docker\n"
        "apt-get install -y python3-venv iptables iproute2\n"
        "python3 -m venv /root/opensandbox-venv\n"
        "/root/opensandbox-venv/bin/pip install --disable-pip-version-check --no-input opensandbox-server==0.2.3 opensandbox==0.1.16\n"
        f"{stage_line('network_create')}"
        f"docker network create --internal --ipv6=false --driver bridge {subnet_option}--opt com.docker.network.bridge.host_binding_ipv4=127.0.0.1 cerberus-internal\n"
        "docker pull opensandbox/execd:v1.0.22\n"
        f"{stage_line('opensandbox_config')}"
        "PYTHONPATH=/root python3 - <<'PY'\n"
        "import json\n"
        "import os\n"
        "import subprocess\n"
        "from pathlib import Path\n"
        f"from sandbox_platform import build_opensandbox_config{', verified_vpc_address' if vpc_subnet else ''}\n"
        "info = json.loads(subprocess.check_output(['docker', 'info', '--format', '{{json .}}']))\n"
        "network = json.loads(subprocess.check_output(['docker', 'network', 'inspect', 'cerberus-internal']))[0]\n"
        f"{status_line}"
        f"config, key = build_opensandbox_config(info, network{config_args})\n"
        "os.umask(0o077)\n"
        "Path('/root/.sandbox.toml').write_text(config)\n"
        "Path('/root/.sandbox.toml').chmod(0o600)\n"
        "Path('/root/.opensandbox-key').write_text(key)\n"
        "Path('/root/.opensandbox-key').chmod(0o600)\n"
        "PY\n"
        f"{stage_line('opensandbox_server')}"
        "/root/opensandbox-venv/bin/opensandbox-server --config /root/.sandbox.toml > /var/log/cerberus-opensandbox.log 2>&1 &\n"
        "server_host=$(python3 -c 'import tomllib; from pathlib import Path; print(tomllib.loads(Path(\"/root/.sandbox.toml\").read_text())[\"server\"][\"host\"])')\n"
        "for attempt in $(seq 1 45); do if curl -fsS \"http://$server_host:8080/health\" >/dev/null 2>&1; then break; fi; sleep 2; done\n"
        "curl -fsS \"http://$server_host:8080/health\" >/dev/null\n"
        f"{firewall_line}"
        f"{stage_line('isolation_probe')}"
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
        "from sandbox_platform import verified_probe_bridge, assert_closed_probe_port, install_host_drop_probe, install_forward_drop_probe, install_ipv6_drop_probe, host_drop_packets, recent_host_drop_log\n"
        "async def check():\n"
        "    key = Path('/root/.opensandbox-key').read_text()\n"
        "    domain = tomllib.loads(Path('/root/.sandbox.toml').read_text())['server']['host'] + ':8080'\n"
        "    Path('/root/cerberus-stage').write_text('bridge_inspect')\n"
        "    network = json.loads(subprocess.check_output(['docker', 'network', 'inspect', 'cerberus-internal']))[0]\n"
        "    bridge_name = 'br-' + network['Id'][:12]\n"
        "    links = json.loads(subprocess.check_output(['ip', '-j', '-d', 'link', 'show', 'dev', bridge_name]))\n"
        "    addresses = json.loads(subprocess.check_output(['ip', '-j', 'addr', 'show', 'dev', bridge_name]))\n"
        "    bridge, gateway = verified_probe_bridge(network, links, addresses)\n"
        "    assert_closed_probe_port(gateway)\n"
        "    Path('/root/cerberus-stage').write_text('firewall_ipv4')\n"
        "    install_host_drop_probe(bridge)\n"
        "    install_forward_drop_probe(bridge)\n"
        "    Path('/root/cerberus-stage').write_text('firewall_ipv6')\n"
        "    install_ipv6_drop_probe(bridge)\n"
        "    Path('/root/cerberus-stage').write_text('sandbox_create')\n"
        "    sandbox = await Sandbox.create('busybox:1.37.0', timeout=timedelta(minutes=2), connection_config=ConnectionConfig(domain=domain, api_key=key, use_server_proxy=True))\n"
        "    try:\n"
        "        Path('/root/cerberus-stage').write_text('docker_isolation')\n"
        "        containers = subprocess.check_output(['docker', 'ps', '-q'], text=True).split()\n"
        "        if not containers:\n"
        "            raise RuntimeError('OpenSandbox container was not found')\n"
        "        attached = 0\n"
        "        for container_id in containers:\n"
        "            inspected = json.loads(subprocess.check_output(['docker', 'inspect', container_id], text=True))[0]\n"
        "            networks = inspected['NetworkSettings'].get('Networks') or {}\n"
        "            if 'cerberus-internal' in networks:\n"
        "                if set(networks) != {'cerberus-internal'} or networks['cerberus-internal'].get('NetworkID') != network['Id'] or inspected['HostConfig'].get('Runtime') not in (None, '', 'runsc'):\n"
        "                    raise RuntimeError('OpenSandbox container is not on the verified gVisor bridge')\n"
        "                attached += 1\n"
        "            for bindings in (inspected['NetworkSettings'].get('Ports') or {}).values():\n"
        "                for binding in bindings or []:\n"
        "                    if binding['HostIp'] not in ('127.0.0.1', '::1'):\n"
        "                        raise RuntimeError('OpenSandbox published a port beyond loopback')\n"
        "        if attached != 1:\n"
        "            raise RuntimeError('OpenSandbox bridge must contain exactly one sandbox container')\n"
        "        Path('/root/cerberus-stage').write_text('smoke_command')\n"
        "        result = await sandbox.commands.run('hostname; uname -a')\n"
        "        if result.exit_code != 0:\n"
        "            raise RuntimeError('OpenSandbox smoke command failed')\n"
        "        lines = [line for item in result.logs.stdout for line in item.text.splitlines() if line]\n"
        "        if len(lines) < 2:\n"
        "            raise RuntimeError('OpenSandbox smoke output missing')\n"
        "        Path('/root/cerberus-stage').write_text('external_probe')\n"
        f"        test_net = await sandbox.commands.run('nc -w 3 192.0.2.1 {PROBE_PORT}')\n"
        "        if not isinstance(test_net.exit_code, int) or test_net.exit_code == 0:\n"
        "            raise RuntimeError('TEST-NET-1 isolation probe did not fail')\n"
        "        Path('/root/cerberus-stage').write_text('dns_probe')\n"
        "        dns_probe = await sandbox.commands.run('nslookup example.com')\n"
        "        if type(dns_probe.exit_code) is not int or dns_probe.exit_code == 0:\n"
        "            raise RuntimeError('External DNS isolation probe did not fail')\n"
        "        Path('/root/cerberus-stage').write_text('host_probe')\n"
        "        before = host_drop_packets()\n"
        "        since = time.time()\n"
        f"        host_probe = await sandbox.commands.run(f'nc -w 3 {{gateway}} {PROBE_PORT}')\n"
        "        after = host_drop_packets()\n"
        "        if not isinstance(host_probe.exit_code, int) or host_probe.exit_code == 0 or after <= before:\n"
        "            raise RuntimeError('Host DROP isolation probe did not register a denied packet')\n"
        "        isolation = {'network_id': network['Id'], 'bridge': bridge, 'gateway': gateway,\n"
        f"                     'test_net_1': {{'destination': '192.0.2.1:{PROBE_PORT}', 'exit_code': test_net.exit_code}},\n"
        "                     'dns_external': {'destination': 'example.com', 'exit_code': dns_probe.exit_code},\n"
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
    prefix, rest = script.split("/root/opensandbox-venv/bin/python3 - <<'PY'\n", 1)
    smoke, tail = rest.split("\nPY\n", 1)
    payload = base64.b64encode(zlib.compress(smoke.encode(), level=9)).decode()
    return prefix + f"printf '%s' {shlex.quote(payload)} | base64 -d | /root/opensandbox-venv/bin/python3 -c 'import sys,zlib; exec(zlib.decompress(sys.stdin.buffer.read()))'\n" + tail

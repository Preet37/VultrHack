import base64
import inspect
import ipaddress
import json
import re
import secrets
import shlex

INTERNAL_NETWORK = "cerberus-internal"
HOST_BIND_OPTION = "com.docker.network.bridge.host_binding_ipv4"


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


def netbird_enrollment_user_data(setup_key):
    if not isinstance(setup_key, str) or not re.fullmatch(r"[A-Za-z0-9-]{32,128}", setup_key):
        raise ValueError("A valid one-off NetBird setup key is required")
    return (
        "curl -fsSL https://pkgs.netbird.io/debian/public.key | gpg --batch --yes --dearmor -o /usr/share/keyrings/netbird-archive-keyring.gpg\n"
        "printf '%s\\n' 'deb [signed-by=/usr/share/keyrings/netbird-archive-keyring.gpg] https://pkgs.netbird.io/debian stable main' > /etc/apt/sources.list.d/netbird.list\n"
        "apt-get update\n"
        "apt-get install -y netbird=0.79.0\n"
        "systemctl enable --now netbird\n"
        "umask 077\n"
        f"printf '%s' {shlex.quote(setup_key)} > /root/cerberus-netbird-setup.key\n"
        "trap 'rm -f /root/cerberus-netbird-setup.key' EXIT\n"
        "netbird up --setup-key-file /root/cerberus-netbird-setup.key\n"
        "rm /root/cerberus-netbird-setup.key\n"
        "netbird status --check ready\n"
    )


def opensandbox_spike_user_data(netbird=False):
    source = (
        "import ipaddress\nimport json\nimport secrets\n"
        f"INTERNAL_NETWORK = {INTERNAL_NETWORK!r}\nHOST_BIND_OPTION = {HOST_BIND_OPTION!r}\n\n"
        + inspect.getsource(build_opensandbox_config)
    )
    source = base64.b64encode(source.encode()).decode()
    status_line = "status = json.loads(subprocess.check_output(['netbird', 'status', '--json']))\n" if netbird else ""
    proof_line = 'data["netbird_ip"] = tomllib.loads(Path("/root/.sandbox.toml").read_text())["server"]["host"]; ' if netbird else ""
    return (
        f"printf '%s' {shlex.quote(source)} | base64 -d > /root/sandbox_platform.py\n"
        "apt-get install -y python3-venv\n"
        "python3 -m venv /root/opensandbox-venv\n"
        "/root/opensandbox-venv/bin/pip install --disable-pip-version-check --no-input opensandbox-server==0.2.3 opensandbox==0.1.16\n"
        "docker network create --internal --driver bridge --opt com.docker.network.bridge.host_binding_ipv4=127.0.0.1 cerberus-internal\n"
        "docker pull opensandbox/execd:v1.0.22\n"
        "PYTHONPATH=/root python3 - <<'PY'\n"
        "import json\n"
        "import subprocess\n"
        "from pathlib import Path\n"
        "from sandbox_platform import build_opensandbox_config\n"
        "info = json.loads(subprocess.check_output(['docker', 'info', '--format', '{{json .}}']))\n"
        "network = json.loads(subprocess.check_output(['docker', 'network', 'inspect', 'cerberus-internal']))[0]\n"
        f"{status_line}"
        f"config, key = build_opensandbox_config(info, network{', netbird_status=status' if netbird else ''})\n"
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
        "from opensandbox import Sandbox\n"
        "from opensandbox.config import ConnectionConfig\n"
        "async def check():\n"
        "    key = Path('/root/.opensandbox-key').read_text()\n"
        "    domain = tomllib.loads(Path('/root/.sandbox.toml').read_text())['server']['host'] + ':8080'\n"
        "    sandbox = await Sandbox.create('busybox:1.37.0', timeout=timedelta(minutes=2), connection_config=ConnectionConfig(domain=domain, api_key=key, use_server_proxy=True))\n"
        "    try:\n"
        "        containers = subprocess.check_output(['docker', 'ps', '-q'], text=True).split()\n"
        "        if not containers:\n"
        "            raise RuntimeError('OpenSandbox container was not found')\n"
        "        for container_id in containers:\n"
        "            inspected = json.loads(subprocess.check_output(['docker', 'inspect', container_id], text=True))[0]\n"
        "            for bindings in (inspected['NetworkSettings'].get('Ports') or {}).values():\n"
        "                for binding in bindings or []:\n"
        "                    if binding['HostIp'] not in ('127.0.0.1', '::1'):\n"
        "                        raise RuntimeError('OpenSandbox published a port beyond loopback')\n"
        "        result = await sandbox.commands.run('hostname; uname -a')\n"
        "        if result.exit_code != 0:\n"
        "            raise RuntimeError('OpenSandbox smoke command failed')\n"
        "        lines = [line for item in result.logs.stdout for line in item.text.splitlines() if line]\n"
        "        if len(lines) < 2:\n"
        "            raise RuntimeError('OpenSandbox smoke output missing')\n"
        "        Path('/root/opensandbox-proof.json').write_text(json.dumps({'hostname': lines[0], 'uname': lines[1], 'exit_code': result.exit_code}))\n"
        "    finally:\n"
        "        await sandbox.destroy()\n"
        "asyncio.run(check())\n"
        "PY\n"
        "export CERBERUS_PROOF=\"$proof\"\n"
        f"proof=$(python3 -c 'import json,os,tomllib; from pathlib import Path; data=json.loads(os.environ[\"CERBERUS_PROOF\"]); data[\"opensandbox\"]=json.loads(Path(\"/root/opensandbox-proof.json\").read_text()); {proof_line}print(json.dumps(data))')\n"
    )

import base64
import json
import secrets
import shlex
from pathlib import Path

INTERNAL_NETWORK = "cerberus-internal"


def build_opensandbox_config(docker_info, network):
    if docker_info.get("DefaultRuntime") != "runsc" or "runsc" not in docker_info.get("Runtimes", {}):
        raise ValueError("Docker must have gVisor runsc installed as its default runtime")
    if network.get("Name") != INTERNAL_NETWORK or network.get("Internal") is not True or network.get("Driver") != "bridge":
        raise ValueError("OpenSandbox requires the dedicated internal Docker bridge")

    api_key = secrets.token_urlsafe(32)
    if len(api_key) < 32:
        raise ValueError("Generated OpenSandbox API key is invalid")
    config = f'''[server]
host = "127.0.0.1"
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


def opensandbox_spike_user_data():
    source = base64.b64encode(Path(__file__).read_bytes()).decode()
    return (
        f"printf '%s' {shlex.quote(source)} | base64 -d > /root/sandbox_platform.py\n"
        "apt-get install -y python3-venv\n"
        "python3 -m venv /root/opensandbox-venv\n"
        "/root/opensandbox-venv/bin/pip install --disable-pip-version-check --no-input opensandbox-server==0.2.3 opensandbox==0.1.16\n"
        "docker network create --internal --driver bridge cerberus-internal\n"
        "docker pull opensandbox/execd:v1.0.22\n"
        "PYTHONPATH=/root python3 - <<'PY'\n"
        "import json\n"
        "import subprocess\n"
        "from pathlib import Path\n"
        "from sandbox_platform import build_opensandbox_config\n"
        "info = json.loads(subprocess.check_output(['docker', 'info', '--format', '{{json .}}']))\n"
        "network = json.loads(subprocess.check_output(['docker', 'network', 'inspect', 'cerberus-internal']))[0]\n"
        "config, key = build_opensandbox_config(info, network)\n"
        "Path('/root/.sandbox.toml').write_text(config)\n"
        "Path('/root/.sandbox.toml').chmod(0o600)\n"
        "Path('/root/.opensandbox-key').write_text(key)\n"
        "Path('/root/.opensandbox-key').chmod(0o600)\n"
        "PY\n"
        "/root/opensandbox-venv/bin/opensandbox-server --config /root/.sandbox.toml > /var/log/cerberus-opensandbox.log 2>&1 &\n"
        "for attempt in $(seq 1 45); do if curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1; then break; fi; sleep 2; done\n"
        "curl -fsS http://127.0.0.1:8080/health >/dev/null\n"
        "/root/opensandbox-venv/bin/python3 - <<'PY'\n"
        "import asyncio\n"
        "import json\n"
        "from datetime import timedelta\n"
        "from pathlib import Path\n"
        "from opensandbox import Sandbox\n"
        "from opensandbox.config import ConnectionConfig\n"
        "async def check():\n"
        "    key = Path('/root/.opensandbox-key').read_text()\n"
        "    sandbox = await Sandbox.create('busybox:1.37.0', timeout=timedelta(minutes=2), connection_config=ConnectionConfig(domain='localhost:8080', api_key=key, use_server_proxy=True))\n"
        "    try:\n"
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
        "proof=$(python3 -c 'import json,os; from pathlib import Path; data=json.loads(os.environ[\"CERBERUS_PROOF\"]); data[\"opensandbox\"]=json.loads(Path(\"/root/opensandbox-proof.json\").read_text()); print(json.dumps(data))')\n"
    )

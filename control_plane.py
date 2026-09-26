import argparse
import asyncio
import base64
import ipaddress
import os
import re
import shlex
import subprocess
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from instance_lifecycle import API_URL, DEFAULT_VX1_PLAN, VultrInstances
from sandbox_platform import netbird_enrollment_user_data

REPO_URL = "https://github.com/Preet37/VultrHack.git"


def control_plane_user_data(callback_url, ready_token, setup_key, repo_sha):
    url = urlsplit(callback_url)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path != "/internal/control-ready":
        raise ValueError("Control readiness callback must use the HTTPS control-ready route")
    if not ready_token or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", ready_token):
        raise ValueError("Control readiness token is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", repo_sha):
        raise ValueError("A pinned repository commit is required")

    return (
        "#!/bin/sh\n"
        "set -eu\n"
        "export DEBIAN_FRONTEND=noninteractive\n"
        "apt-get update\n"
        "apt-get install -y git python3-venv curl ca-certificates gnupg\n"
        "id -u cerberus >/dev/null 2>&1 || useradd --create-home --shell /bin/bash cerberus\n"
        "systemctl mask --now ssh.socket ssh.service sshd.service || true\n"
        + netbird_enrollment_user_data(setup_key, ssh_sftp=True)
        + f"git clone --depth=1 {shlex.quote(REPO_URL)} /opt/cerberus\n"
        + f"test \"$(git -C /opt/cerberus rev-parse HEAD)\" = {shlex.quote(repo_sha)}\n"
        "python3 -m venv /opt/cerberus-venv\n"
        "/opt/cerberus-venv/bin/pip install --disable-pip-version-check --no-input -r /opt/cerberus/requirements.txt\n"
        "install -d -m 700 -o cerberus -g cerberus /home/cerberus/.config/cerberus\n"
        "cat > /usr/local/bin/cerberus-control-start <<'PY'\n"
        "#!/usr/bin/python3\n"
        "import ipaddress\n"
        "import json\n"
        "import os\n"
        "import subprocess\n"
        "status = json.loads(subprocess.check_output(['netbird', 'status', '--json']))\n"
        "address = ipaddress.ip_interface(status['netbirdIp']).ip\n"
        "if status['management']['connected'] is not True or status['signal']['connected'] is not True or address not in ipaddress.ip_network('100.64.0.0/10'):\n"
        "    raise SystemExit('NetBird control peer is not ready')\n"
        "os.execv('/opt/cerberus-venv/bin/uvicorn', ['uvicorn', 'main:app', '--host', str(address), '--port', '8000', '--workers', '1'])\n"
        "PY\n"
        "chmod 755 /usr/local/bin/cerberus-control-start\n"
        "cat > /etc/systemd/system/cerberus.service <<'UNIT'\n"
        "[Unit]\n"
        "Description=Cerberus control-plane API\n"
        "Requires=netbird.service\n"
        "After=network-online.target netbird.service\n"
        "ConditionPathExists=/home/cerberus/.config/cerberus/control.env\n"
        "[Service]\n"
        "User=cerberus\n"
        "Group=cerberus\n"
        "WorkingDirectory=/opt/cerberus\n"
        "Environment=PYTHONDONTWRITEBYTECODE=1\n"
        "EnvironmentFile=/home/cerberus/.config/cerberus/control.env\n"
        "ExecStart=/usr/local/bin/cerberus-control-start\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "NoNewPrivileges=true\n"
        "ProtectSystem=strict\n"
        "ProtectHome=read-only\n"
        "PrivateTmp=true\n"
        "UNIT\n"
        "cat > /etc/systemd/system/cerberus.path <<'UNIT'\n"
        "[Unit]\n"
        "Description=Start Cerberus after private credentials arrive\n"
        "[Path]\n"
        "PathExists=/home/cerberus/.config/cerberus/control.env\n"
        "Unit=cerberus.service\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
        "UNIT\n"
        "systemctl daemon-reload\n"
        "systemctl enable --now cerberus.path\n"
        "proof=$(python3 -c 'import ipaddress,json,subprocess; status=json.loads(subprocess.check_output([\"netbird\",\"status\",\"--json\"])); address=ipaddress.ip_interface(status[\"netbirdIp\"]).ip; print(json.dumps({\"netbird_ip\":str(address),\"repo_commit\":\""
        + repo_sha
        + "\",\"bootstrapped\":True}))')\n"
        + f"curl --fail --silent --show-error --retry 12 --retry-delay 5 --max-time 15 -X POST -H {shlex.quote(f'Authorization: Bearer {ready_token}')} -H 'Content-Type: application/json' --data-binary \"$proof\" {shlex.quote(callback_url)}\n"
    )


class ControlPlaneInstances(VultrInstances):
    async def create(self, region, plan, os_id, callback_url, ready_token, setup_key, repo_sha):
        script = control_plane_user_data(callback_url, ready_token, setup_key, repo_sha)
        label = f"cerberus-control-{uuid4().hex[:12]}"
        return await self.create_with_user_data(region, plan, os_id, label, ["cerberus", "cerberus-control"], script, (ready_token, setup_key))

    async def clear_bootstrap_data(self, instance_id):
        safe_data = base64.b64encode(b"#!/bin/sh\ntrue\n").decode()
        url = f"{API_URL}/{instance_id}"
        response = await self.client.patch(url, headers=self.headers, json={"user_data": safe_data})
        response.raise_for_status()
        verified = await self.client.get(f"{url}/user-data", headers=self.headers)
        verified.raise_for_status()
        if verified.json()["user_data"]["data"] != safe_data:
            raise RuntimeError("Control-plane bootstrap user-data was not cleared")


def render_control_env(api_key, inference_key, api_token, region="ord", plan=DEFAULT_VX1_PLAN):
    if any(not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value) for value in (api_key, inference_key, api_token)) or api_token in (api_key, inference_key):
        raise ValueError("Control-plane credentials must be valid and distinct single-line tokens")
    if not re.fullmatch(r"[a-z]{3}", region) or not re.fullmatch(r"vx1-[a-z0-9-]+-\d+s", plan):
        raise ValueError("Control-plane region or plan is invalid")
    return (
        f"VULTR_API_KEY={api_key}\n"
        f"VULTR_INFERENCE_API_KEY={inference_key}\n"
        f"CERBERUS_CONTROL_TOKEN={api_token}\n"
        f"VULTR_REGION={region}\n"
        f"VULTR_PLAN={plan}\n"
    )


def install_control_credentials(netbird_ip, payload):
    try:
        address = ipaddress.ip_address(netbird_ip)
    except ValueError:
        raise ValueError("Control-plane peer needs a NetBird IPv4 address") from None
    if address not in ipaddress.ip_network("100.64.0.0/10"):
        raise ValueError("Control-plane peer needs a NetBird IPv4 address")
    target = "/home/cerberus/.config/cerberus/control.env"
    command = f"umask 077; cat > {target}.tmp && test -s {target}.tmp && mv {target}.tmp {target}"
    try:
        subprocess.run(["netbird", "ssh", f"cerberus@{address}", command], input=payload.encode(), capture_output=True, check=True, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise RuntimeError("NetBird SSH credential transfer failed") from None


async def bootstrap_control_plane(callback_url, region=None, plan=None, port=8000):
    import httpx
    import uvicorn

    from connectivity import load_keys
    from jobs import control_token
    from main import callback_app, ready_signals

    api_key, _ = load_keys()
    setup_key = os.getenv("NETBIRD_CONTROL_SETUP_KEY")
    if not setup_key:
        raise RuntimeError("Set NETBIRD_CONTROL_SETUP_KEY in the owner-only local .env")
    env_file = Path(__file__).with_name(".env")
    if env_file.exists() and env_file.stat().st_mode & 0o077:
        raise RuntimeError("Restrict .env to its owner (chmod 600 .env) before control-plane enrollment")
    if control_token() is None:
        raise RuntimeError("Configure a separate CERBERUS_CONTROL_TOKEN before provisioning")
    netbird_enrollment_user_data(setup_key, ssh_sftp=True)
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=Path(__file__).parent, text=True).strip():
        raise RuntimeError("Commit local changes before provisioning the control plane")
    repo_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=Path(__file__).parent, text=True).strip()
    remote = subprocess.check_output(["git", "ls-remote", "origin", "refs/heads/main"], cwd=Path(__file__).parent, text=True).split()[0]
    if repo_sha != remote:
        raise RuntimeError("Push the current main commit before provisioning the control plane")

    token = ready_signals.register()
    server = uvicorn.Server(uvicorn.Config(callback_app, host="127.0.0.1", port=port, log_level="warning", access_log=False))
    server_task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            if server_task.done():
                await server_task
                raise RuntimeError("Control readiness callback server did not start")
            await asyncio.sleep(0.1)
        async with httpx.AsyncClient(timeout=60) as client:
            api = ControlPlaneInstances(client, api_key)
            instance_id = None
            ready = False
            try:
                instance_id = await api.create(region or os.getenv("VULTR_REGION", "ord"), plan or os.getenv("VULTR_PLAN", DEFAULT_VX1_PLAN), 2284, callback_url, token, setup_key, repo_sha)
                print(f"Created control-plane VX1 {instance_id}")
                await api.wait_active(instance_id)
                proof = await ready_signals.wait(token, timeout=600)
                if proof["repo_commit"] != repo_sha:
                    raise RuntimeError("Control plane booted an unexpected repository commit")
                await api.clear_bootstrap_data(instance_id)
                ready = True
                print(f"Control-plane bootstrap ready on NetBird {proof['netbird_ip']} (instance {instance_id})")
                return instance_id, proof["netbird_ip"]
            finally:
                if instance_id and not ready:
                    await api.destroy(instance_id)
    finally:
        ready_signals.unregister(token)
        server.should_exit = True
        await server_task


def main():
    parser = argparse.ArgumentParser(description="Provision a persistent NetBird-only Cerberus control-plane VX1")
    parser.add_argument("--callback-url", required=True, help="Public HTTPS URL ending in /internal/control-ready")
    parser.add_argument("--region")
    parser.add_argument("--plan")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--execute", action="store_true", help="Authorize creating a persistent VX1 and deleting it if bootstrap fails")
    args = parser.parse_args()
    if not args.execute:
        parser.error("Pass --execute to authorize persistent provisioning and failure teardown")
    asyncio.run(bootstrap_control_plane(args.callback_url, args.region, args.plan, args.port))


if __name__ == "__main__":
    main()

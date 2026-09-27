import argparse
import asyncio
import base64
import ipaddress
import os
import re
import secrets
import shlex
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID, uuid4

API_URL = "https://api.vultr.com/v2/instances"
DEFAULT_VX1_PLAN = "vx1-g-2c-8g-120s"


def validated_vpc_id(value):
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError
    except (TypeError, ValueError, AttributeError):
        raise ValueError("VPC ID must be a canonical UUID") from None
    return value


def validated_vpc_subnet(value):
    try:
        subnet = ipaddress.ip_network(value, strict=True)
    except (TypeError, ValueError):
        raise ValueError("VPC subnet must be a private IPv4 network") from None
    private_ranges = (ipaddress.ip_network(block) for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if not isinstance(subnet, ipaddress.IPv4Network) or not any(subnet.subnet_of(block) for block in private_ranges):
        raise ValueError("VPC subnet must be a private IPv4 network")
    return subnet


def block_public_ssh_user_data(stage_url=None, ready_token=None):
    progress = (
        "import urllib.request as u\n"
        f"try:u.urlopen(u.Request({stage_url!r},b'{{\"stage\":\"bootstrap_started\"}}',{{'Authorization':{'Bearer ' + ready_token!r},'Content-Type':'application/json'}}),timeout=5).close()\n"
        "except Exception:pass\n"
    ) if stage_url is not None else ""
    return (
        "systemctl stop ssh.socket ssh.service\n"
        "systemctl mask ssh.socket ssh.service\n"
        "python3 - <<'PY'\n"
        "import subprocess\n"
        "listeners = subprocess.check_output(['ss', '-ltnH'], text=True).splitlines()\n"
        "if any(line.split()[3].rsplit(':', 1)[-1] == '22' for line in listeners):\n"
        "    raise SystemExit('OpenSSH port 22 remains listening')\n"
        f"{progress}"
        "PY\n"
    )


class ReadySignals:
    def __init__(self):
        self._events = {}
        self._proofs = {}
        self._stages = {}

    def register(self):
        token = secrets.token_urlsafe(32)
        self._events[token] = asyncio.Event()
        return token

    def has(self, token):
        return token in self._events

    def update_stage(self, token, stage):
        if token not in self._events:
            return False
        self._stages[token] = stage
        return True

    def stage(self, token):
        return self._stages.get(token)

    def signal(self, token, proof):
        event = self._events.get(token)
        if event is None:
            return False
        self._proofs[token] = proof
        event.set()
        return True

    async def wait(self, token, timeout=600):
        await asyncio.wait_for(self._events[token].wait(), timeout)
        return self._proofs[token]

    def unregister(self, token):
        self._events.pop(token, None)
        self._proofs.pop(token, None)
        self._stages.pop(token, None)


def docker_user_data(callback_url, ready_token, opensandbox_spike=False, netbird_setup_key=None, private_callback=False, vpc_callback=False, vpc_subnet=None):
    if netbird_setup_key is not None and not opensandbox_spike:
        raise ValueError("NetBird enrollment requires the authenticated OpenSandbox spike")
    url = urlsplit(callback_url)
    if vpc_callback:
        if not opensandbox_spike or netbird_setup_key is not None or private_callback:
            raise ValueError("VPC callback requires a keyless OpenSandbox spike")
        subnet = validated_vpc_subnet(vpc_subnet)
        try:
            address = ipaddress.ip_address(url.hostname)
            port = url.port
        except (TypeError, ValueError):
            raise ValueError("VPC callback requires a private IPv4 target") from None
        if url.scheme != "http" or not isinstance(address, ipaddress.IPv4Address) or address not in subnet or address in (subnet.network_address, subnet.broadcast_address) or port != 8001 or url.path != "/internal/ready" or url.username or url.password or url.query or url.fragment:
            raise ValueError("VPC callback must target the control VPC address on port 8001")
    elif private_callback:
        if not opensandbox_spike or netbird_setup_key is None:
            raise ValueError("Private callback requires an enrolled NetBird OpenSandbox smoke")
        try:
            address = ipaddress.ip_address(url.hostname)
            port = url.port
        except (TypeError, ValueError):
            raise ValueError("Private callback must target the NetBird control peer") from None
        if url.scheme != "http" or address not in ipaddress.ip_network("100.64.0.0/10") or port != 8000 or url.path != "/internal/ready" or url.username or url.password or url.query or url.fragment:
            raise ValueError("Private callback must target the NetBird control peer on port 8000")
    elif url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("Ready callback must be a public HTTPS URL without credentials or a query string")
    if not ready_token:
        raise ValueError("Ready token is required")
    script = (
        "#!/bin/sh\n"
        "set -eu\n"
        f"{block_public_ssh_user_data(callback_url.replace('/internal/ready', '/internal/stage') if vpc_callback else None, ready_token if vpc_callback else None)}"
        "test -c /dev/kvm\n"
        "test -r /dev/kvm\n"
        "test -w /dev/kvm\n"
        "grep -Eq '(vmx|svm)' /proc/cpuinfo\n"
        "export DEBIAN_FRONTEND=noninteractive\n"
        "apt-get update\n"
    )
    if private_callback or vpc_callback:
        script += "apt-get install -y curl ca-certificates gnupg\n"
    if private_callback:
        from sandbox_platform import netbird_enrollment_user_data

        script += netbird_enrollment_user_data(netbird_setup_key)
    if private_callback or vpc_callback:
        script += f"CERBERUS_AUTH_HEADER={shlex.quote(f'Authorization: Bearer {ready_token}')}\n"
        failure_url = callback_url.replace("/internal/ready", "/internal/failed")
        progress_url = callback_url.replace("/internal/ready", "/internal/stage")
        script += (
            "CERBERUS_STAGE=docker_install\n"
            "cerberus_report_failure() {\n"
            "    result=$?\n"
            "    trap - EXIT\n"
            "    if [ \"$result\" -ne 0 ]; then\n"
            "        if [ \"$CERBERUS_STAGE\" = isolation_probe ] && [ -s /root/cerberus-stage ]; then\n"
            "            CERBERUS_STAGE=$(cat /root/cerberus-stage)\n"
            "        fi\n"
            f"        printf '{{\"stage\":\"%s\",\"exit_code\":%s}}' \"$CERBERUS_STAGE\" \"$result\" | curl -fsS --max-time 10 -X POST -H \"$CERBERUS_AUTH_HEADER\" -H 'Content-Type: application/json' --data-binary @- {shlex.quote(failure_url)} >/dev/null 2>&1 || :\n"
            "    fi\n"
            "}\n"
            "trap cerberus_report_failure EXIT\n"
            "cerberus_report_stage() {\n"
            "    CERBERUS_STAGE=$1\n"
            f"    printf '{{\"stage\":\"%s\"}}' \"$CERBERUS_STAGE\" | curl -fsS --max-time 10 -X POST -H \"$CERBERUS_AUTH_HEADER\" -H 'Content-Type: application/json' --data-binary @- {shlex.quote(progress_url)} >/dev/null 2>&1 || :\n"
            "}\n"
            "cerberus_report_stage docker_install\n"
        )
    script += ("apt-get install -y docker.io\n" if private_callback or vpc_callback else "apt-get install -y docker.io curl ca-certificates gnupg\n")
    script += "systemctl enable --now docker\n"
    if private_callback or vpc_callback:
        script += "cerberus_report_stage gvisor_install\n"
    script += (
        "curl -fsSL https://gvisor.dev/archive.key | gpg --batch --yes --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg\n"
        "printf '%s\\n' \"deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main\" > /etc/apt/sources.list.d/gvisor.list\n"
        "apt-get update\n"
        "apt-get install -y runsc\n"
        "runsc install\n"
        "python3 -c 'import json; from pathlib import Path; p=Path(\"/etc/docker/daemon.json\"); config=json.loads(p.read_text()); config[\"default-runtime\"]=\"runsc\"; p.write_text(json.dumps(config))'\n"
        "systemctl restart docker\n"
    )
    if private_callback or vpc_callback:
        script += "cerberus_report_stage runtime_smoke\n"
    script += (
        "sandbox_output=$(docker run --rm --runtime=runsc --network=none --read-only --cap-drop=ALL --pids-limit=32 busybox:1.37.0 sh -c 'hostname; uname -a')\n"
        "export SANDBOX_OUTPUT=\"$sandbox_output\"\n"
        "test \"$(docker info --format '{{.DefaultRuntime}}')\" = runsc\n"
        "proof=$(python3 -c 'import json,os,platform,re; flags=open(\"/proc/cpuinfo\").read(); cpu=re.search(r\"\\b(vmx|svm)\\b\",flags).group(1); sandbox=os.environ[\"SANDBOX_OUTPUT\"].splitlines(); print(json.dumps({\"hostname\":platform.node(),\"uname\":\" \".join(os.uname()),\"cpu_virt\":cpu,\"kvm_device\":os.path.exists(\"/dev/kvm\"),\"kvm_access\":os.access(\"/dev/kvm\",os.R_OK|os.W_OK),\"runtime\":\"runsc\",\"sandbox_hostname\":sandbox[0],\"sandbox_uname\":sandbox[1],\"exit_code\":0}))')\n"
    )
    if netbird_setup_key is not None and not private_callback:
        from sandbox_platform import netbird_enrollment_user_data

        script += netbird_enrollment_user_data(netbird_setup_key)
    if opensandbox_spike:
        from sandbox_platform import opensandbox_spike_user_data

        script += opensandbox_spike_user_data(netbird=netbird_setup_key is not None, report_stages=private_callback or vpc_callback, vpc_subnet=vpc_subnet if vpc_callback else None)
    callback_stage = "cerberus_report_stage ready_callback\n" if private_callback or vpc_callback else ""
    auth_header = '"$CERBERUS_AUTH_HEADER"' if private_callback or vpc_callback else shlex.quote(f"Authorization: Bearer {ready_token}")
    return script + callback_stage + (
        f"curl -fsS --retry 12 --retry-delay 5 --max-time 15 -X POST "
        f"-H {auth_header} -H 'Content-Type: application/json' "
        f"--data-binary \"$proof\" {shlex.quote(callback_url)}\n"
    )


class VultrInstances:
    def __init__(self, client, api_key):
        self.client = client
        self.headers = {"Authorization": f"Bearer {api_key}"}

    async def create(self, region, plan, os_id, callback_url, ready_token, opensandbox_spike=False, netbird_setup_key=None, private_callback=False, vpc_callback=False, vpc_subnet=None, vpc_id=None):
        script = docker_user_data(callback_url, ready_token, opensandbox_spike, netbird_setup_key, private_callback, vpc_callback, vpc_subnet)
        return await self.create_with_user_data(
            region, plan, os_id, f"cerberus-{uuid4().hex[:12]}", ["cerberus"], script,
            (ready_token, netbird_setup_key), vpc_ids=[vpc_id] if vpc_callback else None,
        )

    async def create_with_user_data(self, region, plan, os_id, label, tags, script, secrets_to_redact=(), vpc_ids=None):
        if not plan.startswith("vx1-") or not re.search(r"-\d+s$", plan):
            raise ValueError("A VX1 plan with local NVMe storage is required")
        payload = {
            "region": region,
            "plan": plan,
            "os_id": os_id,
            "block_devices": [{"block_id": "local", "bootable": True}],
            "label": label,
            "tags": tags,
            "user_data": base64.b64encode(script.encode()).decode(),
        }
        if vpc_ids is not None:
            if not isinstance(vpc_ids, (list, tuple)) or len(vpc_ids) != 1:
                raise ValueError("Exactly one VPC ID is required for a disposable host")
            payload["attach_vpc"] = [validated_vpc_id(vpc_ids[0])]
        response = await self.client.post(API_URL, headers=self.headers, json=payload)
        if response.status_code == 400:
            detail = str(response.json().get("error", "Invalid instance parameters"))
            for secret in (self.headers["Authorization"][7:], payload["user_data"], *secrets_to_redact):
                if secret:
                    detail = detail.replace(secret, "[redacted]")
            detail = detail.replace("\n", " ").replace("\r", " ")[:200]
            raise ValueError(f"Vultr rejected instance configuration: {detail}")
        response.raise_for_status()
        return response.json()["instance"]["id"]

    async def create_vpc(self, region, description, vpc_subnet):
        subnet = validated_vpc_subnet(vpc_subnet)
        if not re.fullmatch(r"[a-z]{3}", region) or not re.fullmatch(r"[a-z0-9-]{3,64}", description):
            raise ValueError("VPC region or description is invalid")
        response = await self.client.post("https://api.vultr.com/v2/vpcs", headers=self.headers, json={
            "region": region, "description": description,
            "v4_subnet": str(subnet.network_address), "v4_subnet_mask": subnet.prefixlen,
        })
        response.raise_for_status()
        vpc = response.json()["vpc"]
        validated_vpc_id(vpc["id"])
        if vpc.get("region") != region or validated_vpc_subnet(f"{vpc['v4_subnet']}/{vpc['v4_subnet_mask']}") != subnet:
            raise ValueError("Vultr created a VPC outside the approved region or subnet")
        return vpc

    async def attach_vpc(self, instance_id, vpc_id, vpc_subnet, timeout=120, interval=5):
        validated_vpc_id(instance_id)
        validated_vpc_id(vpc_id)
        validated_vpc_subnet(vpc_subnet)
        response = await self.client.post(f"{API_URL}/{instance_id}/vpcs/attach", headers=self.headers, json={"vpc_id": vpc_id})
        if response.status_code != 409:
            response.raise_for_status()
        return await self.wait_vpc_attachment(instance_id, vpc_id, vpc_subnet, timeout=timeout, interval=interval)

    async def get_vpc(self, vpc_id):
        response = await self.client.get(f"https://api.vultr.com/v2/vpcs/{validated_vpc_id(vpc_id)}", headers=self.headers)
        response.raise_for_status()
        vpc = response.json()["vpc"]
        if vpc.get("id") != vpc_id:
            raise ValueError("Vultr returned a different VPC")
        return vpc

    async def list_instance_vpcs(self, instance_id):
        response = await self.client.get(f"{API_URL}/{instance_id}/vpcs", headers=self.headers)
        response.raise_for_status()
        vpcs = response.json()["vpcs"]
        if not isinstance(vpcs, list):
            raise ValueError("Vultr returned invalid instance VPC attachments")
        return vpcs

    async def wait_vpc_attachment(self, instance_id, vpc_id, vpc_subnet, timeout=120, interval=5):
        vpc_id = validated_vpc_id(vpc_id)
        subnet = validated_vpc_subnet(vpc_subnet)
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            matches = [vpc for vpc in await self.list_instance_vpcs(instance_id) if vpc.get("id") == vpc_id]
            if len(matches) > 1:
                raise ValueError("Vultr returned duplicate VPC attachments")
            if matches and matches[0].get("ip_address"):
                try:
                    address = ipaddress.IPv4Address(matches[0]["ip_address"])
                except (TypeError, ValueError):
                    raise ValueError("Vultr returned an invalid VPC address") from None
                if address not in subnet or address in (subnet.network_address, subnet.broadcast_address):
                    raise ValueError("Vultr returned an address outside the approved VPC")
                return str(address)
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"VPC attachment was not confirmed for instance {instance_id}")
            await asyncio.sleep(min(interval, remaining))

    async def wait_active(self, instance_id, timeout=600, interval=5):
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            response = await self.client.get(f"{API_URL}/{instance_id}", headers=self.headers)
            response.raise_for_status()
            instance = response.json()["instance"]
            if instance["status"] == "active" and instance["power_status"] == "running":
                return instance
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"Instance {instance_id} did not become active")
            await asyncio.sleep(min(interval, remaining))

    async def destroy(self, instance_id, timeout=300, interval=5):
        url = f"{API_URL}/{instance_id}"
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            response = await self.client.delete(url, headers=self.headers)
            if response.status_code == 404:
                return
            if response.status_code != 409:
                response.raise_for_status()
                break
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"Instance {instance_id} could not be deleted while Vultr reports a conflict")
            await asyncio.sleep(min(interval, remaining))
        while True:
            response = await self.client.get(url, headers=self.headers)
            if response.status_code == 404:
                return
            response.raise_for_status()
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"Instance {instance_id} was not confirmed destroyed")
            await asyncio.sleep(min(interval, remaining))


@asynccontextmanager
async def temporary_instance(api, region, plan, os_id, callback_url, ready_token, opensandbox_spike=False, netbird_setup_key=None, private_callback=False, vpc_callback=False, vpc_subnet=None, vpc_id=None):
    vpc_options = {"vpc_callback": True, "vpc_subnet": vpc_subnet, "vpc_id": vpc_id} if vpc_callback else {}
    instance_id = await api.create(region, plan, os_id, callback_url, ready_token, opensandbox_spike, netbird_setup_key, private_callback, **vpc_options)
    try:
        yield instance_id
    finally:
        await api.destroy(instance_id)


async def verify_instance(callback_url, host, port, region, plan, os_id, opensandbox_spike=False, netbird_test=False):
    import httpx
    import uvicorn

    from connectivity import load_keys
    from main import callback_app, ready_signals

    api_key, _ = load_keys()
    setup_key = os.getenv("NETBIRD_SANDBOX_SETUP_KEY") if netbird_test else None
    if netbird_test and not setup_key:
        raise RuntimeError("Set NETBIRD_SANDBOX_SETUP_KEY in the ignored .env before enrollment")
    env_file = Path(__file__).with_name(".env")
    if netbird_test and env_file.exists() and env_file.stat().st_mode & 0o077:
        raise RuntimeError("Restrict .env to its owner (chmod 600 .env) before NetBird enrollment")
    docker_user_data(callback_url, "validation", opensandbox_spike, setup_key)
    region = region or os.getenv("VULTR_REGION", "ewr")
    plan = plan or os.getenv("VULTR_PLAN", DEFAULT_VX1_PLAN)
    token = ready_signals.register()
    server = uvicorn.Server(uvicorn.Config(callback_app, host=host, port=port, log_level="warning", access_log=False))
    server_task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            if server_task.done():
                await server_task
                raise RuntimeError("Callback server did not start")
            await asyncio.sleep(0.1)
        async with httpx.AsyncClient(timeout=60) as client:
            api = VultrInstances(client, api_key)
            async with temporary_instance(api, region, plan, os_id, callback_url, token, opensandbox_spike, setup_key) as instance_id:
                print(f"Created instance {instance_id}")
                await api.wait_active(instance_id)
                print(f"Instance {instance_id} active; waiting for Docker readiness")
                proof = await ready_signals.wait(token)
                print(f"Host proof: {proof['hostname']} | {proof['uname']}")
                print(f"CPU virt: {proof['cpu_virt']} | /dev/kvm: {proof['kvm_device']} | read/write: {proof['kvm_access']} | Docker runtime: {proof['runtime']}")
                print(f"Sandbox output: {proof['sandbox_hostname']} | {proof['sandbox_uname']} | exit code: {proof['exit_code']}")
                if opensandbox_spike:
                    print(f"OpenSandbox output: {proof['opensandbox']['hostname']} | {proof['opensandbox']['uname']} | exit code: {proof['opensandbox']['exit_code']}")
                if netbird_test:
                    from sandbox_platform import check_private_endpoint

                    await check_private_endpoint(client, proof["netbird_ip"])
                    print("NetBird private OpenSandbox health and authentication checks passed")
                print(f"Instance {instance_id} healthy; destroying it")
            print(f"Instance {instance_id} confirmed destroyed")
    finally:
        ready_signals.unregister(token)
        server.should_exit = True
        await server_task


def main():
    parser = argparse.ArgumentParser(description="Provision one temporary Vultr instance and verify Docker readiness")
    parser.add_argument("--callback-url", required=True, help="Public HTTPS URL forwarding to /internal/ready on this process")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--region")
    parser.add_argument("--plan")
    parser.add_argument("--os-id", type=int, default=2284)
    parser.add_argument("--opensandbox-spike", action="store_true", help="Run a local OpenSandbox gVisor smoke check")
    parser.add_argument("--netbird-test", action="store_true", help="Enroll one NetBird peer and check the private API")
    parser.add_argument("--execute", action="store_true", help="Authorize instance creation and subsequent destruction")
    args = parser.parse_args()
    if not args.execute:
        parser.error("Pass --execute to authorize creating and destroying one instance")
    if args.netbird_test and not args.opensandbox_spike:
        parser.error("--netbird-test requires --opensandbox-spike")
    asyncio.run(verify_instance(args.callback_url, args.host, args.port, args.region, args.plan, args.os_id, args.opensandbox_spike, args.netbird_test))


if __name__ == "__main__":
    main()

import asyncio
import ipaddress
import json
import os
import re
import secrets
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

import httpx
from dotenv import load_dotenv

from connectivity import check_connectivity, load_keys

TERMINAL = {"completed", "failed"}
SECRET_NAMES = (
    "VULTR_API_KEY", "vultr_api_key", "VULTR_INFERENCE_API_KEY", "VULTR_INFERENCE_KEY",
    "vultr_inference_api_key", "OPENAI_API_KEY", "NETBIRD_SANDBOX_SETUP_KEY", "NETBIRD_CONTROL_SETUP_KEY",
)


def control_token():
    env_file = Path(__file__).with_name(".env")
    if env_file.exists() and env_file.stat().st_mode & 0o077:
        return None
    load_dotenv(env_file)
    token = os.getenv("CERBERUS_CONTROL_TOKEN")
    if not token or len(token) < 32 or token in (os.getenv(name) for name in SECRET_NAMES):
        return None
    return token


@dataclass
class Job:
    id: str = field(default_factory=lambda: uuid4().hex)
    kind: str = "connectivity"
    status: str = "queued"
    result: dict | None = None
    error: str | None = None
    events: list[dict] = field(default_factory=list)
    condition: asyncio.Condition = field(default_factory=asyncio.Condition)

    def __post_init__(self):
        if not self.events:
            self.events.append({"sequence": 0, "step": self.kind, "status": "queued"})

    async def publish(self, status, step=None):
        async with self.condition:
            self.status = status
            self.events.append({"sequence": len(self.events), "step": step or self.kind, "status": status})
            self.condition.notify_all()

    async def stream(self):
        cursor = 0
        while True:
            async with self.condition:
                await self.condition.wait_for(lambda: len(self.events) > cursor or self.status in TERMINAL)
                batch = self.events[cursor:]
                cursor = len(self.events)
                finished = self.status in TERMINAL
            for event in batch:
                yield event
            if finished:
                return


class JobRegistry:
    def __init__(self, max_jobs=32):
        self.max_jobs = max_jobs
        self.jobs = {}
        self.tasks = set()

    def create(self, kind="connectivity", setup_key=None, signals=None):
        if kind not in ("connectivity", "sandbox_smoke"):
            raise ValueError("Unsupported job type")
        if kind == "sandbox_smoke":
            if not setup_key or signals is None:
                raise ValueError("Sandbox job requires a one-off key and readiness signals")
            if any(job.kind == kind and job.status not in TERMINAL for job in self.jobs.values()):
                return None
        if len(self.jobs) >= self.max_jobs:
            completed = next((job_id for job_id, job in self.jobs.items() if job.status in TERMINAL), None)
            if completed is None:
                return None
            self.jobs.pop(completed)
        job = Job(kind=kind)
        self.jobs[job.id] = job
        worker = run_connectivity_job(job) if kind == "connectivity" else run_sandbox_smoke_job(job, setup_key, signals)
        task = asyncio.create_task(worker)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return job


async def run_connectivity_job(job):
    await job.publish("running")
    try:
        api_key, inference_key = load_keys()
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            models, region_count = await check_connectivity(client, api_key, inference_key)
        job.result = {"models": models, "region_count": region_count}
    except Exception:
        job.error = "Connectivity check failed"
        await job.publish("failed")
    else:
        await job.publish("completed")


async def run_sandbox_smoke_job(job, setup_key, signals):
    from instance_lifecycle import DEFAULT_VX1_PLAN, VultrInstances, temporary_instance
    from sandbox_platform import HOST_PROBE_LOG_PREFIX, PROBE_PORT, check_private_endpoint

    instance_id = None
    token = None
    failure_stage = None
    await job.publish("running", "preflight")
    try:
        status = json.loads(subprocess.check_output(["netbird", "status", "--json"], text=True))
        address = ipaddress.ip_interface(status["netbirdIp"]).ip
        if status["management"]["connected"] is not True or status["signal"]["connected"] is not True or address not in ipaddress.ip_network("100.64.0.0/10"):
            raise ValueError("Connected NetBird control peer required")
        api_key, _ = load_keys()
        token = signals.register()
        await job.publish("running", "provisioning")
        async with httpx.AsyncClient(timeout=60, trust_env=False) as client:
            api = VultrInstances(client, api_key)
            callback = f"http://{address}:8000/internal/ready"
            async with temporary_instance(api, os.getenv("VULTR_REGION", "ord"), os.getenv("VULTR_PLAN", DEFAULT_VX1_PLAN), 2284, callback, token, True, setup_key, True) as instance_id:
                await api.wait_active(instance_id)
                await job.publish("running", "bootstrap")
                proof = await signals.wait(token, timeout=600)
                if "failure_stage" in proof:
                    failure_stage = proof["failure_stage"]
                    raise RuntimeError("Sandbox bootstrap reported a bounded failure stage")
                sandbox = proof.get("opensandbox")
                isolation = sandbox.get("isolation") if isinstance(sandbox, dict) else None
                if "netbird_ip" not in proof or not isinstance(isolation, dict) or "gvisor" not in sandbox.get("uname", "").lower():
                    raise ValueError("OpenSandbox gVisor isolation proof missing")
                network_id, bridge, gateway = (isolation.get(name) for name in ("network_id", "bridge", "gateway"))
                before, after, delta = (isolation.get(name) for name in ("host_drop_packets_before", "host_drop_packets_after", "host_drop_packets_delta"))
                log = isolation.get("kernel_drop_log")
                if (
                    not isinstance(network_id, str) or not re.fullmatch(r"[0-9a-f]{64}", network_id)
                    or bridge != "br-" + network_id[:12] or not isinstance(gateway, str)
                    or type(before) is not int or type(after) is not int or type(delta) is not int
                    or delta <= 0 or after - before != delta
                    or any(
                        not isinstance(isolation.get(name), dict)
                        or isolation[name].get("destination") != destination
                        or type(isolation[name].get("exit_code")) is not int
                        or isolation[name]["exit_code"] <= 0
                        for name, destination in (("test_net_1", f"192.0.2.1:{PROBE_PORT}"), ("dns_external", "example.com"), ("host_gateway", f"{gateway}:{PROBE_PORT}"))
                    )
                    or not isinstance(log, str) or len(log) > 512
                    or not all(part in log for part in (HOST_PROBE_LOG_PREFIX, f"IN={bridge} ", f"DST={gateway} ", f"DPT={PROBE_PORT}"))
                ):
                    raise ValueError("Host isolation enforcement evidence missing")
                await job.publish("running", "private_check")
                await check_private_endpoint(client, proof["netbird_ip"])
                await job.publish("running", "teardown")
        job.result = {
            "instance_id": instance_id,
            "host": {key: proof[key] for key in ("hostname", "uname", "cpu_virt", "kvm_device", "kvm_access")},
            "sandbox": {key: proof[key] for key in ("sandbox_hostname", "sandbox_uname", "exit_code")},
            "opensandbox": {
                "hostname": sandbox["hostname"], "uname": sandbox["uname"], "exit_code": sandbox["exit_code"],
                "isolation": {
                    "network_id": network_id, "bridge": bridge, "gateway": gateway,
                    "test_net_1": {key: isolation["test_net_1"][key] for key in ("destination", "exit_code")},
                    "dns_external": {key: isolation["dns_external"][key] for key in ("destination", "exit_code")},
                    "host_gateway": {key: isolation["host_gateway"][key] for key in ("destination", "exit_code")},
                    "host_drop_packets_before": before, "host_drop_packets_after": after,
                    "host_drop_packets_delta": delta, "kernel_drop_log": log,
                },
            },
            "destroyed": True,
        }
    except Exception:
        if failure_stage:
            job.error = f"Sandbox bootstrap failed at {failure_stage}; verify cleanup of instance {instance_id}"
        else:
            job.error = f"Sandbox smoke failed; verify cleanup of instance {instance_id}" if instance_id else "Sandbox smoke failed before an instance ID was confirmed"
        await job.publish("failed", "teardown")
    else:
        await job.publish("completed", "complete")
    finally:
        if token is not None:
            signals.unregister(token)

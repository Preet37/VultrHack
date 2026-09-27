import asyncio
import ipaddress
import json
import os
import re
import secrets
import subprocess
import time
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
        self.arm_token = None
        self.arm_expires = 0.0
        self.arm_hold_seconds = 0

    def arm_sandbox(self, ttl_seconds=120, diagnostic_hold_seconds=0):
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 300 or type(diagnostic_hold_seconds) is not int or not 0 <= diagnostic_hold_seconds <= 300:
            raise ValueError("Sandbox arm and diagnostic hold must be bounded")
        if self.arm_token and time.monotonic() < self.arm_expires:
            return None
        if any(job.kind == "sandbox_smoke" and job.status not in TERMINAL for job in self.jobs.values()):
            return None
        self.arm_token = secrets.token_urlsafe(32)
        self.arm_expires = time.monotonic() + ttl_seconds
        self.arm_hold_seconds = diagnostic_hold_seconds
        return self.arm_token

    def consume_sandbox_arm(self, token):
        if not self.arm_token or time.monotonic() >= self.arm_expires:
            self.arm_token = None
            self.arm_expires = 0.0
            self.arm_hold_seconds = 0
            return None
        if not isinstance(token, str) or not secrets.compare_digest(token, self.arm_token):
            return None
        hold = self.arm_hold_seconds
        self.arm_token = None
        self.arm_expires = 0.0
        self.arm_hold_seconds = 0
        return hold

    def create(self, kind="connectivity", setup_key=None, signals=None, vpc_mode=False, target=None, diagnostic_hold_seconds=None):
        if kind not in ("connectivity", "sandbox_smoke", "scan"):
            raise ValueError("Unsupported job type")
        if kind == "sandbox_smoke":
            if signals is None or (not setup_key and not vpc_mode) or (setup_key and vpc_mode):
                raise ValueError("Sandbox job requires one private network mode and readiness signals")
            if any(job.kind == kind and job.status not in TERMINAL for job in self.jobs.values()):
                return None
        if kind == "scan":
            if target not in SCAN_TARGETS:
                raise ValueError("Unknown scan target")
            # One scan at a time: each boots a target subprocess on its own port.
            if any(job.kind == kind and job.status not in TERMINAL for job in self.jobs.values()):
                return None
        if len(self.jobs) >= self.max_jobs:
            completed = next((job_id for job_id, job in self.jobs.items() if job.status in TERMINAL), None)
            if completed is None:
                return None
            self.jobs.pop(completed)
        job = Job(kind=kind)
        self.jobs[job.id] = job
        if kind == "connectivity":
            worker = run_connectivity_job(job)
        elif kind == "scan":
            worker = run_scan_job(job, target)
        elif vpc_mode:
            options = {"diagnostic_hold_seconds": diagnostic_hold_seconds} if diagnostic_hold_seconds is not None else {}
            worker = run_sandbox_smoke_job(job, setup_key, signals, vpc_mode=True, **options)
        else:
            worker = run_sandbox_smoke_job(job, setup_key, signals)
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


# Only our own seeded, deliberately-vulnerable targets may be scanned this way.
# This job starts the target as a local subprocess, so it must NEVER be pointed
# at an arbitrary user-supplied repo -- untrusted repositories run only inside
# the disposable gVisor sandbox. The web endpoint accepts a target *name*, never
# a path or URL, and it is resolved against this fixed allowlist.
SCAN_TARGETS = {
    "seeded_flask": Path(__file__).with_name("targets") / "seeded_flask",
    "snipstash": Path(__file__).with_name("targets") / "snipstash",
}


async def run_scan_job(job, target_name):
    """Full find -> prove -> patch -> re-prove loop over one scan target.

    Gets a reachable target from a TargetRunner -- a local subprocess today, a
    disposable gVisor sandbox once that seam is wired -- runs the finder +
    remediation loop in a worker thread (both are blocking), and streams a step
    per phase. The result records ``triage_source`` so the caller can see whether
    Vultr Serverless Inference or the offline fallback produced the plan.
    """
    from finder.pipeline import run_finder
    from finder.recon import load_manifest
    from finder.remediate import remediate
    from finder.target_runner import make_runner

    source_dir = SCAN_TARGETS.get(target_name)
    if source_dir is None:
        job.error = "Unknown scan target"
        await job.publish("failed", "start_target")
        return

    # Honor the manifest's entrypoint (default app.py) so the runner boots the
    # target the same way remediate() does. The runner mode comes from
    # CERBERUS_SCAN_RUNNER (default local); sandbox mode fails closed until the
    # sandbox dispatch primitive is injected -- it never falls back to this host.
    entrypoint = (load_manifest(str(source_dir)) or {}).get("entrypoint", "app.py")
    runner = make_runner(str(source_dir), entrypoint)
    try:
        await job.publish("running", "start_target")
        base_url = await asyncio.to_thread(runner.start)

        await job.publish("running", "finding")
        report = await asyncio.to_thread(run_finder, base_url, str(source_dir))
        await job.publish("running", f"confirmed_{len(report.findings)}")

        remediations = []
        certified = 0
        for finding in report.findings:
            await job.publish("running", f"patch_{finding.vuln_class}")
            # A single remediation failure must not discard the finder's
            # confirmed findings or the fixes already certified this run.
            try:
                res = await asyncio.to_thread(remediate, finding, str(source_dir))
            except Exception:
                remediations.append({
                    "finding_id": finding.id,
                    "vuln_class": finding.vuln_class,
                    "certified": False,
                    "error": "remediation raised before completing",
                })
                await job.publish("running", "open_" + finding.vuln_class)
                continue
            certified += 1 if res.certified else 0
            remediations.append(res.to_dict())
            await job.publish("running", ("certified_" if res.certified else "open_") + finding.vuln_class)

        job.result = {
            "target": target_name,
            "triage_source": report.triage_source,
            "confirmed_findings": len(report.findings),
            "certified_closed": certified,
            "findings": [f.to_dict() for f in report.findings],
            "remediations": remediations,
            "coverage": report.coverage.to_dict(),
        }
    except Exception:
        job.error = "Scan failed"
        await job.publish("failed", "scan")
    else:
        await job.publish("completed", "complete")
    finally:
        # Unconditional: stop() is null-guarded and safe after a failed start, so
        # a target that spawned but never became healthy is never left running.
        await asyncio.to_thread(runner.stop)


async def run_sandbox_smoke_job(job, setup_key, signals, vpc_mode=False, diagnostic_hold_seconds=None):
    from instance_lifecycle import DEFAULT_VX1_PLAN, VultrInstances, temporary_instance, validated_vpc_id, validated_vpc_subnet
    from sandbox_platform import HOST_PROBE_LOG_PREFIX, PROBE_PORT, VPC_INTERNAL_SUBNET, check_private_endpoint

    instance_id = None
    token = None
    failure_stage = None
    readiness_timed_out = False
    await job.publish("running", "preflight")
    try:
        if vpc_mode:
            vpc_id = validated_vpc_id(os.getenv("CERBERUS_VPC_ID"))
            control_id = validated_vpc_id(os.getenv("CERBERUS_CONTROL_INSTANCE_ID"))
            subnet = validated_vpc_subnet(os.getenv("CERBERUS_VPC_SUBNET"))
            control_ip = ipaddress.ip_address(os.getenv("CERBERUS_CONTROL_VPC_IP"))
            if not isinstance(control_ip, ipaddress.IPv4Address) or control_ip not in subnet or control_ip in (subnet.network_address, subnet.broadcast_address) or subnet.overlaps(ipaddress.ip_network(VPC_INTERNAL_SUBNET)):
                raise ValueError("Control VPC address or subnet is invalid")
        else:
            status = json.loads(subprocess.check_output(["netbird", "status", "--json"], text=True))
            address = ipaddress.ip_interface(status["netbirdIp"]).ip
            if status["management"]["connected"] is not True or status["signal"]["connected"] is not True or address not in ipaddress.ip_network("100.64.0.0/10"):
                raise ValueError("Connected NetBird control peer required")
        raw_hold = str(diagnostic_hold_seconds) if diagnostic_hold_seconds is not None else os.getenv("CERBERUS_DIAGNOSTIC_HOLD_SECONDS", "0")
        if not re.fullmatch(r"[0-9]{1,3}", raw_hold) or int(raw_hold) > 300:
            raise ValueError("Diagnostic hold must be between 0 and 300 seconds")
        diagnostic_hold = int(raw_hold)

        async def hold_for_diagnostics():
            if diagnostic_hold:
                await job.publish("running", "diagnostic_hold")
                await asyncio.sleep(diagnostic_hold)

        api_key, _ = load_keys()
        token = signals.register()
        await job.publish("running", "provisioning")
        async with httpx.AsyncClient(timeout=60, trust_env=False) as client:
            api = VultrInstances(client, api_key)
            region = os.getenv("VULTR_REGION", "ord")
            if vpc_mode:
                vpc = await api.get_vpc(vpc_id)
                if vpc.get("region") != region or validated_vpc_subnet(f"{vpc['v4_subnet']}/{vpc['v4_subnet_mask']}") != subnet:
                    raise ValueError("Configured VPC does not match the approved region and subnet")
                attached = await api.list_instance_vpcs(control_id)
                if len(attached) != 1 or attached[0].get("id") != vpc_id or attached[0].get("ip_address") != str(control_ip):
                    raise ValueError("Control VX1 is not attached to the approved VPC address")
                route = await client.head(f"http://{control_ip}:8001/internal/stage", timeout=5)
                if route.status_code != 405:
                    raise ValueError("Private VPC callback listener is unavailable")
                callback = f"http://{control_ip}:8001/internal/ready"
                vpc_options = {"vpc_callback": True, "vpc_subnet": str(subnet), "vpc_id": vpc_id}
            else:
                callback = f"http://{address}:8000/internal/ready"
                vpc_options = {}
            async with temporary_instance(api, region, os.getenv("VULTR_PLAN", DEFAULT_VX1_PLAN), 2284, callback, token, True, setup_key, not vpc_mode, **vpc_options) as instance_id:
                await api.wait_active(instance_id)
                if vpc_mode:
                    sandbox_ip = await api.wait_vpc_attachment(instance_id, vpc_id, str(subnet))
                    if sandbox_ip == str(control_ip):
                        raise ValueError("Disposable and control VX1 cannot share a VPC address")
                await job.publish("running", "bootstrap")
                try:
                    proof = await signals.wait(token, timeout=600)
                except TimeoutError:
                    readiness_timed_out = True
                    await hold_for_diagnostics()
                    raise
                if "failure_stage" in proof:
                    failure_stage = proof["failure_stage"]
                    await hold_for_diagnostics()
                    raise RuntimeError("Sandbox bootstrap reported a bounded failure stage")
                sandbox = proof.get("opensandbox")
                isolation = sandbox.get("isolation") if isinstance(sandbox, dict) else None
                if (vpc_mode and proof.get("vpc_ip") != sandbox_ip) or (not vpc_mode and "netbird_ip" not in proof) or not isinstance(isolation, dict) or "gvisor" not in sandbox.get("uname", "").lower():
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
                if vpc_mode:
                    await check_private_endpoint(client, sandbox_ip, vpc_subnet=str(subnet))
                else:
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
        if vpc_mode:
            job.result["vpc_ip"] = sandbox_ip
    except Exception:
        last_stage = signals.stage(token) if token is not None else None
        if failure_stage:
            job.error = f"Sandbox bootstrap failed at {failure_stage}; verify cleanup of instance {instance_id}"
        elif readiness_timed_out and last_stage:
            job.error = f"Sandbox readiness timed out after {last_stage}; verify cleanup of instance {instance_id}"
        else:
            job.error = f"Sandbox smoke failed; verify cleanup of instance {instance_id}" if instance_id else "Sandbox smoke failed before an instance ID was confirmed"
        await job.publish("failed", "teardown")
    else:
        await job.publish("completed", "complete")
    finally:
        if token is not None:
            signals.unregister(token)

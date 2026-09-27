import asyncio
import gzip
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit
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
        # Only one disposable sandbox VX1 may exist at a time, for smoke or scan.
        if any(job.kind in ("sandbox_smoke", "sandbox_scan") and job.status not in TERMINAL for job in self.jobs.values()):
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

    def create(self, kind="connectivity", setup_key=None, signals=None, vpc_mode=False, target=None, diagnostic_hold_seconds=None, diagnostic_upload=None, target_runtime="gvisor", remediate=False, repo=None, entrypoint=None):
        if kind not in ("connectivity", "sandbox_smoke", "scan", "sandbox_scan"):
            raise ValueError("Unsupported job type")
        if remediate and kind != "sandbox_scan":
            # The re-exploit pass patches against findings from a sandboxed scan
            # and must never run against a locally booted target or a smoke VM.
            raise ValueError("Remediation is only available for sandbox scans")
        if kind == "sandbox_smoke":
            if signals is None or (not setup_key and not vpc_mode) or (setup_key and vpc_mode):
                raise ValueError("Sandbox job requires one private network mode and readiness signals")
            if any(job.kind in ("sandbox_smoke", "sandbox_scan") and job.status not in TERMINAL for job in self.jobs.values()):
                return None
        if kind == "sandbox_scan":
            if signals is None or setup_key or diagnostic_hold_seconds is not None or diagnostic_upload is not None:
                raise ValueError("Sandbox scan requires readiness signals and no smoke options")
            if (target is None) == (repo is None):
                raise ValueError("Sandbox scan needs exactly one of target or repo")
            if target is not None and target not in SCAN_TARGETS:
                raise ValueError("Unknown scan target")
            # One disposable VX1 at a time, shared with sandbox smoke jobs.
            if any(job.kind in ("sandbox_smoke", "sandbox_scan") and job.status not in TERMINAL for job in self.jobs.values()):
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
        elif kind == "sandbox_scan":
            worker = run_sandbox_scan_job(job, target, signals, target_runtime=target_runtime, remediate=remediate, repo=repo, entrypoint=entrypoint)
        elif vpc_mode:
            options = {"diagnostic_hold_seconds": diagnostic_hold_seconds} if diagnostic_hold_seconds is not None else {}
            if diagnostic_upload is not None:
                options["diagnostic_upload"] = diagnostic_upload
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

# Bounds shared with the guest-side extraction guard in instance_lifecycle's
# target_run user-data: the tarball handed to one presigned GET stays tiny.
TARGET_SOURCE_MAX_FILES = 128
TARGET_SOURCE_MAX_BYTES = 8 * 1024 * 1024


def deterministic_source_tarball(source_dir, max_files=TARGET_SOURCE_MAX_FILES, max_total_bytes=TARGET_SOURCE_MAX_BYTES):
    """Pack one seeded scan target into a byte-stable tarball for staging.

    Deterministic so retries stage identical bytes: paths are sorted, volatile
    __pycache__ artifacts are dropped, and every member gets fixed metadata.
    Only regular files under the target root are allowed -- no symlinks, no
    absolute paths, no unbounded names -- because the guest extracts this tar.
    """
    root = Path(source_dir)
    if not root.is_dir():
        raise ValueError("Scan target source must be a local directory")
    entries = []
    total = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            raise ValueError("Scan target sources must not contain links")
        if not path.is_file():
            if path.is_dir():
                continue
            raise ValueError("Scan target sources must contain only regular files")
        name = relative.as_posix()
        if len(name) > 96 or any(len(part) > 64 for part in relative.parts):
            raise ValueError("Scan target path is out of bounds")
        size = path.stat().st_size
        total += size
        entries.append((name, path, size))
        if len(entries) > max_files or total > max_total_bytes:
            raise ValueError("Scan target source is too large")
    if not entries:
        raise ValueError("Scan target source is empty")
    buffer = io.BytesIO()
    gzip_file = gzip.GzipFile(filename="", mode="wb", fileobj=buffer, compresslevel=9, mtime=0)
    with tarfile.open(fileobj=gzip_file, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, path, size in entries:
            info = tarfile.TarInfo(name)
            info.size = size
            info.mtime = 0
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with open(path, "rb") as handle:
                archive.addfile(info, handle)
    gzip_file.close()
    return buffer.getvalue()


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


async def run_sandbox_smoke_job(job, setup_key, signals, vpc_mode=False, diagnostic_hold_seconds=None, diagnostic_upload=None):
    from instance_lifecycle import DEFAULT_VX1_PLAN, VultrInstances, temporary_instance, validated_vpc_id, validated_vpc_subnet
    from sandbox_platform import HOST_PROBE_LOG_PREFIX, PROBE_PORT, VPC_INTERNAL_SUBNET, check_private_endpoint

    instance_id = None
    token = None
    failure_stage = None
    readiness_timed_out = False
    failure_detail = None
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
                if diagnostic_upload is not None:
                    vpc_options["diagnostic_upload"] = diagnostic_upload
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
                    failure_detail = proof.get("failure_detail")
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
    except Exception as error:
        last_stage = signals.stage(token) if token is not None else None
        detail = f"{type(error).__name__}; stage={failure_stage or last_stage or 'none'}"
        if failure_detail:
            detail = f"{detail}; guest={failure_detail[:200]}"
        job.error = (
            f"Sandbox smoke failed ({detail}); verify cleanup of instance {instance_id}"
            if instance_id else f"Sandbox smoke failed ({detail}) before an instance ID was confirmed"
        )
        logging.getLogger(__name__).warning("Sandbox smoke failed: %s", detail)
        await job.publish("failed", "teardown")
    else:
        await job.publish("completed", "complete")
    finally:
        if token is not None:
            signals.unregister(token)


def resolve_scan_source(repo):
    """Return (source_dir, cleanup) for an arbitrary repo: local absolute dir or https git URL."""
    if repo is None:
        raise ValueError("Repo source required")
    if not isinstance(repo, str):
        raise ValueError("Repo source must be a path or https git URL")
    if repo.startswith("https://"):
        try:
            url = urlsplit(repo)
            host = url.hostname
        except ValueError:
            raise ValueError("Invalid repo URL") from None
        if not host or url.username is not None or url.password is not None or url.fragment or "/../" in url.path or url.path in ("", "/"):
            raise ValueError("Repo URL must be a plain https clone address")
        clone_dir = Path(tempfile.mkdtemp(prefix="cerberus-repo-"))
        try:
            subprocess.run(
                ["git", "-c", "credential.helper=", "clone", "--depth", "1", "--single-branch", "--", repo, str(clone_dir)],
                check=True, capture_output=True, text=True, timeout=180, env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true", "SSH_ASKPASS": "true"},
            )
        except subprocess.TimeoutExpired:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise ValueError("Repo clone timed out") from None
        except subprocess.CalledProcessError:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise ValueError("Repo clone failed") from None
        return str(clone_dir), clone_dir
    path = Path(repo).expanduser().resolve()
    if not path.is_absolute() or not path.is_dir():
        raise ValueError("Repo path must be an absolute existing directory")
    if "/../" in repo or ".." in path.parts[:-1]:
        raise ValueError("Repo path must not traverse")
    return str(path), None


async def run_sandbox_scan_job(job, target_name, signals, target_runtime="gvisor", remediate=False, repo=None, entrypoint=None):
    """Scan one seeded target running inside gVisor on a disposable VPC VX1.

    Same lifecycle discipline as the VPC smoke (preflight the approved VPC and
    control attachment, one bounded VX1, token readiness, unconditional destroy
    plus an independent 404 check), but the guest bootstrap downloads the
    deterministically packed target source over a single-object presigned GET,
    builds a minimal image, and serves it detached with ``--runtime=runsc``
    published only on the guest's provider-verified VPC IPv4. The finder then
    scans that private endpoint. The staged source object is always deleted.

    With ``remediate=True`` and at least one confirmed finding, a second pass
    follows the scan (only after the first VX1 is destroyed and confirmed 404):
    ``finder.remediate.remediate_batch`` patches all findings into one shared
    disposable copy and hosts it EXACTLY ONCE -- on a SECOND disposable VX1
    provisioned synchronously by a launcher running in a worker thread (its own
    event loop, its own boto3 client, a FRESH ReadySignals instance, and its
    own destroy + independent 404 + object-delete teardown). The re-exploit
    therefore runs in the same sandbox runtime as the proof scan, never on
    this host, and both instances and both staged objects are always cleaned.
    """
    import boto3
    from botocore.config import Config

    from diagnostic_storage import presign_source_get, validated_storage_target
    from finder.pipeline import run_finder
    from finder.recon import load_manifest
    from instance_lifecycle import API_URL, DEFAULT_VX1_PLAN, VultrInstances, temporary_instance, validated_vpc_id, validated_vpc_subnet
    from sandbox_platform import VPC_INTERNAL_SUBNET

    source_dir = SCAN_TARGETS.get(target_name) if target_name is not None else None
    repo_cleanup = None
    if repo is not None:
        source_dir, repo_cleanup = resolve_scan_source(repo)
    instance_id = None
    token = None
    failure_stage = None
    failure_detail = None
    storage = None
    bucket = None
    object_key = None
    object_deleted = False
    await job.publish("running", "preflight")
    try:
        if source_dir is None or not source_dir.is_dir():
            raise ValueError("Unknown scan target")
        vpc_id = validated_vpc_id(os.getenv("CERBERUS_VPC_ID"))
        control_id = validated_vpc_id(os.getenv("CERBERUS_CONTROL_INSTANCE_ID"))
        subnet = validated_vpc_subnet(os.getenv("CERBERUS_VPC_SUBNET"))
        control_ip = ipaddress.ip_address(os.getenv("CERBERUS_CONTROL_VPC_IP"))
        if not isinstance(control_ip, ipaddress.IPv4Address) or control_ip not in subnet or control_ip in (subnet.network_address, subnet.broadcast_address) or subnet.overlaps(ipaddress.ip_network(VPC_INTERNAL_SUBNET)):
            raise ValueError("Control VPC address or subnet is invalid")
        storage_endpoint = os.getenv("CERBERUS_S3_ENDPOINT")
        bucket = os.getenv("CERBERUS_S3_BUCKET")
        access_key = os.getenv("CERBERUS_S3_ACCESS_KEY")
        secret_key = os.getenv("CERBERUS_S3_SECRET_KEY")
        if not all((storage_endpoint, bucket, access_key, secret_key)):
            raise ValueError("Sandbox scan object storage is not configured")
        endpoint = storage_endpoint if storage_endpoint.startswith("https://") else f"https://{storage_endpoint}"
        region_name = validated_storage_target(endpoint, bucket).split(".", 1)[0].removeprefix("https://")
        storage = boto3.client(
            "s3", region_name=region_name, endpoint_url=endpoint,
            aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
        )
        payload = deterministic_source_tarball(source_dir)
        scan_entrypoint = entrypoint or (load_manifest(str(source_dir)) or {}).get("entrypoint", "app.py")
        api_key, _ = load_keys()
        token = signals.register()
        await job.publish("running", "provisioning")
        async with httpx.AsyncClient(timeout=60, trust_env=False) as client:
            api = VultrInstances(client, api_key)
            region = os.getenv("VULTR_REGION", "ord")
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
            object_key = "src/" + secrets.token_hex(16) + ".tgz"
            await asyncio.to_thread(storage.put_object, Bucket=bucket, Key=object_key, Body=payload)
            source_url = presign_source_get(storage, endpoint, bucket, object_key, expires_in=900)
            target_options = {
                "vpc_callback": True, "vpc_subnet": str(subnet), "vpc_id": vpc_id,
                "target_run": {"source_url": source_url, "entrypoint": scan_entrypoint, "runtime": target_runtime},
            }
            async with temporary_instance(api, region, os.getenv("VULTR_PLAN", DEFAULT_VX1_PLAN), 2284, callback, token, False, None, False, **target_options) as instance_id:
                await api.wait_active(instance_id)
                sandbox_ip = await api.wait_vpc_attachment(instance_id, vpc_id, str(subnet))
                if sandbox_ip == str(control_ip):
                    raise ValueError("Disposable and control VX1 cannot share a VPC address")
                await job.publish("running", "bootstrap")
                proof = await signals.wait(token, timeout=600)
                if "failure_stage" in proof:
                    failure_stage = proof["failure_stage"]
                    failure_detail = proof.get("failure_detail")
                    raise RuntimeError("Sandbox bootstrap reported a bounded failure stage")
                base_url = f"http://{sandbox_ip}:8081"
                expected_runtime = "microsandbox" if target_runtime == "microsandbox" else "runsc"
                if proof.get("runtime") != expected_runtime or proof.get("vpc_ip") != sandbox_ip or proof.get("target") != "healthy" or proof.get("endpoint") != base_url:
                    raise ValueError("Target readiness proof does not match the provider VPC attachment")
                await job.publish("running", "scanning")
                report = await asyncio.to_thread(run_finder, base_url, str(source_dir))
                await job.publish("running", "teardown")
            destroyed = await client.get(f"{API_URL}/{instance_id}", headers=api.headers)
            if destroyed.status_code != 404:
                raise RuntimeError("Disposable target VX1 was not independently confirmed destroyed")
            await asyncio.to_thread(storage.delete_object, Bucket=bucket, Key=object_key)
            object_deleted = True
        remediation = None
        if remediate and report.findings:
            # The patch + re-exploit pass runs in a worker thread and hosts the
            # shared patched copy on a SECOND disposable VX1, provisioned
            # synchronously by this launcher. Nothing untrusted ever boots on
            # the control host, and the launcher never shares the scan phase's
            # boto3 client, httpx client, or event loop.
            from concurrent.futures import Future as TaskFuture

            launcher_token = signals.register()
            proof_bridge = TaskFuture()

            async def relay_proof():
                try:
                    proof_bridge.set_result(await signals.wait(launcher_token, timeout=600))
                except BaseException as wait_error:
                    proof_bridge.set_exception(wait_error)
                finally:
                    signals.unregister(launcher_token)

            bridge_task = asyncio.create_task(relay_proof())

            def sync_launcher(dst_path, fresh_entrypoint):
                launcher_storage = boto3.client(
                    "s3", region_name=region_name, endpoint_url=endpoint,
                    aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                    config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
                )
                launcher_key = "src/" + secrets.token_hex(16) + ".tgz"
                launcher_storage.put_object(Bucket=bucket, Key=launcher_key, Body=deterministic_source_tarball(dst_path))
                launcher_url = presign_source_get(launcher_storage, endpoint, bucket, launcher_key, expires_in=900)
                second = {"instance_id": None}

                async def destroy_second_vx1():
                    second_id = second["instance_id"]
                    if second_id is None:
                        return
                    async with httpx.AsyncClient(timeout=60, trust_env=False) as launcher_client:
                        launcher_api = VultrInstances(launcher_client, api_key)
                        await launcher_api.destroy(second_id)
                        gone = await launcher_client.get(f"{API_URL}/{second_id}", headers=launcher_api.headers)
                        if gone.status_code != 404:
                            raise RuntimeError("Disposable re-exploit VX1 was not independently confirmed destroyed")

                async def _provision_and_wait():
                    async with httpx.AsyncClient(timeout=60, trust_env=False) as launcher_client:
                        launcher_api = VultrInstances(launcher_client, api_key)
                        second_id = await launcher_api.create(
                            region, os.getenv("VULTR_PLAN", DEFAULT_VX1_PLAN), 2284, callback, launcher_token,
                            False, None, False, vpc_callback=True, vpc_subnet=str(subnet), vpc_id=vpc_id,
                            target_run={"source_url": launcher_url, "entrypoint": fresh_entrypoint, "runtime": target_runtime},
                        )
                        second["instance_id"] = second_id
                        try:
                            await launcher_api.wait_active(second_id)
                            launcher_ip = await launcher_api.wait_vpc_attachment(second_id, vpc_id, str(subnet))
                            if launcher_ip == str(control_ip):
                                raise ValueError("Disposable and control VX1 cannot share a VPC address")
                            launcher_proof = await asyncio.to_thread(proof_bridge.result, 660)
                            if "failure_stage" in launcher_proof:
                                raise RuntimeError("Sandbox bootstrap reported a bounded failure stage")
                            launcher_base = f"http://{launcher_ip}:8081"
                            expected = "microsandbox" if target_runtime == "microsandbox" else "runsc"
                            if launcher_proof.get("runtime") != expected or launcher_proof.get("vpc_ip") != launcher_ip or launcher_proof.get("target") != "healthy" or launcher_proof.get("endpoint") != launcher_base:
                                raise ValueError("Target readiness proof does not match the provider VPC attachment")
                            return launcher_base
                        except Exception:
                            await destroy_second_vx1()
                            second["instance_id"] = None
                            raise
                try:
                    launcher_base = asyncio.run(_provision_and_wait())
                except Exception:
                    try:
                        launcher_storage.delete_object(Bucket=bucket, Key=launcher_key)
                    except Exception:
                        pass
                    raise

                def stop():
                    # Both teardowns are attempted even if the first fails: the
                    # second VX1's destroy (with its own 404 confirmation) and
                    # the second staged object's delete are independently best
                    # effort, surfacing the first failure.
                    first_error = None
                    try:
                        asyncio.run(destroy_second_vx1())
                    except Exception as stop_error:
                        first_error = stop_error
                    try:
                        launcher_storage.delete_object(Bucket=bucket, Key=launcher_key)
                    except Exception as stop_error:
                        if first_error is None:
                            first_error = stop_error
                    second["instance_id"] = None
                    if first_error is not None:
                        raise first_error

                return launcher_base, stop

            def _remediate_in_sandbox():
                from finder.remediate import remediate_batch

                results, functional = remediate_batch(report.findings, str(source_dir), launcher=sync_launcher)
                return {
                    "attempted": len(results),
                    "certified": sum(1 for result in results if result.certified),
                    "re-exploit_sandboxed": True,
                    "results": [
                        {
                            "finding_id": result.finding_id,
                            "vuln_class": result.vuln_class,
                            "patched": result.patched,
                            "patch_source": result.patch_source,
                            "reexploit_blocked": result.reexploit_blocked,
                            "functional_ok": result.functional_ok,
                            "validated": result.validated,
                            "validation_notes": result.validation_notes[:200],
                        }
                        for result in results[:32]
                    ],
                    "shared_functional": bool(functional),
                }

            await job.publish("running", "remediating")
            try:
                remediation = await asyncio.to_thread(_remediate_in_sandbox)
            finally:
                if not bridge_task.done():
                    bridge_task.cancel()
                    await asyncio.gather(bridge_task, return_exceptions=True)
        coverage = report.coverage.to_dict()
        job.result = {
            "instance_id": instance_id,
            "vpc_ip": sandbox_ip,
            "target": target_name,
            "target_runtime": target_runtime,
            "endpoint": base_url,
            "endpoint_health": "healthy",
            "host": {field: proof[field] for field in ("hostname", "uname", "cpu_virt", "kvm_device", "kvm_access")},
            "triage_source": report.triage_source,
            "confirmed_findings": len(report.findings),
            "findings": [finding.to_dict() for finding in report.findings][:32],
            "coverage": {
                "classes_tested": coverage["classes_tested"][:8],
                "endpoints_tested": coverage["endpoints_tested"][:32],
                "candidates_seen": coverage["candidates_seen"],
                "candidates_tested": coverage["candidates_tested"],
                "not_reached": coverage["not_reached"][:8],
                "steps_used": coverage["steps_used"],
                "wall_clock_seconds": coverage["wall_clock_seconds"],
            },
            "destroyed": True,
            "source_object_deleted": True,
        }
        if remediation is not None:
            job.result["remediation"] = remediation
    except Exception as error:
        last_stage = signals.stage(token) if token is not None else None
        detail = f"{type(error).__name__}; stage={failure_stage or last_stage or 'none'}"
        message = str(error).replace("\n", " ")
        token_secret = control_token()
        if token_secret:
            message = message.replace(token_secret, "[redacted]")
        if message:
            detail = f"{detail}; message={message[:160]}"
        if failure_detail:
            detail = f"{detail}; guest={failure_detail[:200]}"
        job.error = (
            f"Sandbox scan failed ({detail}); verify cleanup of instance {instance_id}"
            if instance_id else f"Sandbox scan failed ({detail}) before an instance ID was confirmed"
        )
        logging.getLogger(__name__).warning("Sandbox scan failed: %s", detail)
        await job.publish("failed", "teardown")
    else:
        await job.publish("completed", "complete")
    finally:
        if token is not None:
            signals.unregister(token)
        if repo_cleanup is not None:
            shutil.rmtree(repo_cleanup, ignore_errors=True)
        if storage is not None and bucket is not None and object_key is not None and not object_deleted:
            try:
                await asyncio.to_thread(storage.delete_object, Bucket=bucket, Key=object_key)
            except Exception:
                logging.getLogger(__name__).warning("Sandbox scan could not delete its staged source object")

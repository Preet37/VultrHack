import argparse
import asyncio
import ipaddress
import secrets
import time
from urllib.parse import urlsplit

import boto3
import httpx
from botocore.config import Config
from dotenv import dotenv_values

from connectivity import load_keys
from diagnostic_storage import presign_nic_post, read_nic_object
from instance_lifecycle import validated_vpc_id, validated_vpc_subnet
from jobs import control_token

VULTR_API = "https://api.vultr.com/v2"


def validated_operator_url(value):
    try:
        url = urlsplit(value)
        address = ipaddress.ip_address(url.hostname)
    except (TypeError, ValueError):
        raise ValueError("Operator URL must target the NetBird control IPv4") from None
    if url.scheme != "http" or address not in ipaddress.ip_network("100.64.0.0/10") or url.netloc != f"{address}:8000" or url.geturl() != value or url.path or url.query or url.fragment:
        raise ValueError("Operator URL must target NetBird TCP/8000 only")
    return value


def storage_client(env_file):
    cfg = dotenv_values(env_file)
    names = ("CERBERUS_S3_ENDPOINT", "CERBERUS_S3_BUCKET", "CERBERUS_S3_ACCESS_KEY", "CERBERUS_S3_SECRET_KEY")
    if not all(cfg.get(name) for name in names):
        raise RuntimeError("Object Storage diagnostics require endpoint, bucket and keys in the owner-only .env")
    endpoint = "https://" + cfg["CERBERUS_S3_ENDPOINT"]
    client = boto3.client(
        "s3", region_name=cfg["CERBERUS_S3_ENDPOINT"].split(".")[0], endpoint_url=endpoint,
        aws_access_key_id=cfg["CERBERUS_S3_ACCESS_KEY"], aws_secret_access_key=cfg["CERBERUS_S3_SECRET_KEY"],
        config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
    )
    return client, endpoint, cfg["CERBERUS_S3_BUCKET"]


async def run_approved_smoke(control_url, vpc_id, vpc_subnet, hold_seconds, env_file, s3_factory=storage_client):
    validated_operator_url(control_url)
    vpc_id = validated_vpc_id(vpc_id)
    subnet = validated_vpc_subnet(vpc_subnet)
    if type(hold_seconds) is not int or not 0 <= hold_seconds <= 300:
        raise ValueError("Diagnostic hold must be between 0 and 300 seconds")
    control_key = control_token()
    if control_key is None:
        raise RuntimeError("An owner-only local control token is required")
    api_key, _ = load_keys()
    operator_headers = {"Authorization": f"Bearer {control_key}"}
    provider_headers = {"Authorization": f"Bearer {api_key}"}
    storage, endpoint, bucket = s3_factory(env_file)
    nic_key = "nic/" + secrets.token_hex(16) + ".json"
    upload = presign_nic_post(storage, endpoint, bucket, nic_key, expires_in=900)
    async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
        vpc = await client.get(f"{VULTR_API}/vpcs/{vpc_id}", headers=provider_headers)
        vpc.raise_for_status()
        details = vpc.json()["vpc"]
        if details.get("region") != "ord" or validated_vpc_subnet(f"{details['v4_subnet']}/{details['v4_subnet_mask']}") != subnet:
            raise RuntimeError("Approved VPC region or subnet does not match the provider")
        fleet = await client.get(f"{VULTR_API}/instances", headers=provider_headers)
        fleet.raise_for_status()
        if any("cerberus" in vm.get("tags", []) and "cerberus-control" not in vm.get("tags", []) for vm in fleet.json().get("instances", [])):
            raise RuntimeError("A disposable Cerberus VX1 already exists")
        health = await client.get(f"{control_url}/health")
        if health.status_code != 200:
            raise RuntimeError("Private control API is unavailable")
        disabled = await client.post(f"{control_url}/jobs", headers=operator_headers, json={"type": "sandbox_smoke", "approve_vm": False})
        if disabled.status_code != 503:
            raise RuntimeError("The sandbox job gate must be disabled before arming")
        print("Preflight: provider, private control API and storage are ready", flush=True)
        armed = await client.post(f"{control_url}/jobs/arm-sandbox", headers=operator_headers, json={"approve_vm": True, "ttl_seconds": 120, "diagnostic_hold_seconds": hold_seconds})
        if armed.status_code != 201:
            raise RuntimeError(f"Single-use VPC job arm was rejected (HTTP {armed.status_code})")
        try:
            started = await client.post(f"{control_url}/jobs", headers=operator_headers, json={
                "type": "sandbox_smoke", "approve_vm": True,
                "arm_token": armed.json()["arm_token"], "diagnostic_upload": upload,
            })
        except httpx.HTTPError:
            raise RuntimeError("Job submission outcome is unknown; inspect the provider fleet before any retry") from None
        if started.status_code != 202:
            raise RuntimeError(f"Approved VPC job was rejected (HTTP {started.status_code}); do not retry")
        job_id = started.json()["id"]
        print(f"Single approved job: {job_id}", flush=True)
        instance_id = None
        expected_vpc_ip = None
        report = None
        deadline = time.monotonic() + 1800
        while time.monotonic() < deadline:
            if report is None:
                report = await asyncio.to_thread(read_nic_object, storage, bucket, nic_key, str(subnet))
                if report is not None:
                    print("Bounded guest NIC diagnostic received", flush=True)
            try:
                instances = await client.get(f"{VULTR_API}/instances", headers=provider_headers)
                instances.raise_for_status()
            except httpx.HTTPError:
                instances = None
            if instances is not None:
                disposable = [vm for vm in instances.json().get("instances", []) if "cerberus" in vm.get("tags", []) and "cerberus-control" not in vm.get("tags", [])]
                if disposable and instance_id is None:
                    if len(disposable) != 1:
                        raise RuntimeError("More than one disposable VX1 appeared; inspect the existing job")
                    instance_id = disposable[0]["id"]
                    print(f"Disposable VX1: {instance_id}", flush=True)
            if instance_id and expected_vpc_ip is None:
                try:
                    attachment = await client.get(f"{VULTR_API}/instances/{instance_id}/vpcs", headers=provider_headers)
                except httpx.HTTPError:
                    attachment = None
                if attachment is not None and attachment.status_code == 200:
                    matched = [item.get("ip_address") for item in attachment.json().get("vpcs", []) if item.get("id") == vpc_id]
                    if len(matched) == 1 and matched[0]:
                        expected_vpc_ip = matched[0]
            try:
                status = await client.get(f"{control_url}/jobs/{job_id}", headers=operator_headers)
                status.raise_for_status()
            except httpx.HTTPError:
                status = None
            if status is not None and status.json()["status"] in ("completed", "failed"):
                break
            await asyncio.sleep(5)
        else:
            raise TimeoutError(f"Job {job_id} is still active; inspect that job, do not start another")
        if report is None:
            report = await asyncio.to_thread(read_nic_object, storage, bucket, nic_key, str(subnet))
        if report is None:
            print("No guest NIC report: outbound HTTPS or bootstrap may have failed", flush=True)
        else:
            print("Guest NIC probe completed:", report["probe"] == "ok", flush=True)
            print("VPC subnet address present:", report["vpc_ip"] is not None if report["probe"] == "ok" else "unknown", flush=True)
            print("Provider-assigned VPC IP configured in guest:", report["vpc_ip"] == expected_vpc_ip if expected_vpc_ip and report["probe"] == "ok" else "unknown", flush=True)
        await asyncio.to_thread(storage.delete_object, Bucket=bucket, Key=nic_key)
        result = await client.get(f"{control_url}/jobs/{job_id}/result", headers=operator_headers)
        print("Sandbox job result HTTP:", result.status_code, flush=True)
        if result.status_code == 200:
            instance_id = result.json().get("instance_id") or instance_id
            print("Job reports VX1 destroyed:", result.json().get("destroyed") is True, flush=True)
        elif result.status_code == 502:
            print("Bounded job error:", result.json().get("error"), flush=True)
        if instance_id:
            deleted = None
            for _ in range(6):
                try:
                    deleted = await client.get(f"{VULTR_API}/instances/{instance_id}", headers=provider_headers)
                except httpx.HTTPError:
                    deleted = None
                if deleted is not None and deleted.status_code == 404:
                    break
                await asyncio.sleep(2)
            print("Independent VX1 deletion confirmed:", deleted is not None and deleted.status_code == 404, flush=True)
        else:
            fleet = await client.get(f"{VULTR_API}/instances", headers=provider_headers)
            if fleet.status_code == 200:
                remaining = [vm for vm in fleet.json().get("instances", []) if "cerberus" in vm.get("tags", []) and "cerberus-control" not in vm.get("tags", [])]
                print("No disposable Cerberus VX1 remains:", not remaining, flush=True)


def main(argv=None):
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Run one explicitly approved VPC smoke with bounded storage NIC diagnostics")
    parser.add_argument("--control-url", required=True)
    parser.add_argument("--vpc-id", required=True)
    parser.add_argument("--vpc-subnet", required=True)
    parser.add_argument("--hold-seconds", type=int, default=0)
    parser.add_argument("--env-file", default=str(Path(__file__).with_name(".env")))
    parser.add_argument("--execute", action="store_true", help="Authorize one billable disposable VX1 and its automatic deletion")
    args = parser.parse_args(argv)
    if not args.execute:
        parser.error("Pass --execute only after specific approval for one billable VX1")
    asyncio.run(run_approved_smoke(args.control_url, args.vpc_id, args.vpc_subnet, args.hold_seconds, args.env_file))


if __name__ == "__main__":
    main()

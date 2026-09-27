import asyncio
import base64
import io
import json
import re
import secrets
import shutil
import tarfile
import tempfile
import threading
import time
from pathlib import Path

import boto3
import httpx
import pytest
from botocore.config import Config
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import diagnostic_run
import finder.pipeline
import finder.remediate
import instance_lifecycle
import jobs
from diagnostic_receiver import validated_nic_report
from diagnostic_run import main as diagnostic_main, validated_operator_url
from diagnostic_storage import presign_nic_post, presign_source_get
from finder.models import Coverage, FinderReport, Finding
from main import app, vpc_callback_app
from test_instance_lifecycle import unpack_vpc_payload

CONTROL_TOKEN = "test-" + "x" * 40


def test_operator_url_is_validated_without_exposing_control_api():
    assert validated_operator_url("http://100.124.55.15:8000") == "http://100.124.55.15:8000"
    for url in ("http://64.177.8.46:8000", "https://100.124.55.15:8000", "http://100.124.55.15:8000/jobs", "http://user@100.124.55.15:8000", "http://100.124.55.15:8000\n"):
        with pytest.raises(ValueError):
            validated_operator_url(url)


def test_public_diagnostic_runner_requires_explicit_execute():
    with pytest.raises(SystemExit):
        diagnostic_main(["--control-url", "http://100.124.55.15:8000", "--vpc-id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "--vpc-subnet", "10.52.0.0/24"])


def test_approved_diagnostic_runner_starts_one_mock_job_without_leaking_tokens(monkeypatch, capsys):
    vpc_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    calls = []

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url, **kwargs):
            calls.append(("GET", url, None))
            if url.endswith("/vpcs/" + vpc_id):
                data = {"vpc": {"region": "ord", "v4_subnet": "10.52.0.0", "v4_subnet_mask": 24}}
            elif url.endswith("/instances"):
                data = {"instances": []} if len([c for c in calls if c[0] == "GET" and c[1].endswith("/instances")]) == 1 else {"instances": [{"id": "instance-123", "tags": ["cerberus"]}]}
            elif url.endswith("/instances/instance-123/vpcs"):
                data = {"vpcs": [{"id": vpc_id, "ip_address": "10.52.0.4"}]}
            elif url.endswith("/instances/instance-123"):
                return httpx.Response(404, request=httpx.Request("GET", url))
            elif url.endswith("/jobs/job-123/result"):
                data = {"instance_id": "instance-123", "destroyed": True}
            elif url.endswith("/jobs/job-123"):
                data = {"status": "completed"}
            else:
                data = {"healthy": True}
            return httpx.Response(200, json=data, request=httpx.Request("GET", url))

        async def head(self, url, **kwargs):
            calls.append(("HEAD", url, None))
            return httpx.Response(405, request=httpx.Request("HEAD", url))

        async def post(self, url, json=None, **kwargs):
            calls.append(("POST", url, json))
            if url.endswith("/jobs/arm-sandbox"):
                return httpx.Response(201, json={"arm_token": "A" * 43}, request=httpx.Request("POST", url))
            if json.get("approve_vm") is False:
                return httpx.Response(503, request=httpx.Request("POST", url))
            return httpx.Response(202, json={"id": "job-123"}, request=httpx.Request("POST", url))

    class FakeStorage:
        def __init__(self):
            self.deleted = []

        def get_object(self, Bucket, Key):
            return {"Body": io.BytesIO(b'{"probe":"ok","vpc_ip":"10.52.0.4"}'), "ContentType": "application/json"}

        def delete_object(self, Bucket, Key):
            self.deleted.append(Key)

    storage = FakeStorage()

    def fake_s3(env_file):
        return storage, "https://ewr1.vultrobjects.com", "cerberus-nic-demo"

    def fake_presign(client, endpoint, bucket, key, expires_in):
        assert expires_in == 900 and re.fullmatch(r"nic/[0-9a-f]{32}\.json", key)
        return {"url": "https://cerberus-nic-demo.ewr1.vultrobjects.com/", "fields": {"key": key, "policy": "x"}}

    monkeypatch.setattr(diagnostic_run, "control_token", lambda: "C" * 43)
    monkeypatch.setattr(diagnostic_run, "load_keys", lambda: ("account-key", "inference-key"))
    monkeypatch.setattr(diagnostic_run.httpx, "AsyncClient", lambda **kwargs: FakeClient())
    monkeypatch.setattr(diagnostic_run, "presign_nic_post", fake_presign)
    asyncio.run(diagnostic_run.run_approved_smoke("http://100.124.55.15:8000", vpc_id, "10.52.0.0/24", 300, "/fake/.env", s3_factory=fake_s3))
    jobs_started = [body for method, url, body in calls if method == "POST" and url.endswith("/jobs") and body.get("approve_vm") is True]
    assert len(jobs_started) == 1
    assert jobs_started[0]["arm_token"] == "A" * 43
    assert set(jobs_started[0]["diagnostic_upload"]["fields"]) == {"key", "policy"}
    assert len(storage.deleted) == 1
    output = capsys.readouterr().out
    assert "Guest NIC probe completed: True" in output
    assert "Provider-assigned VPC IP configured in guest: True" in output
    assert "Independent VX1 deletion confirmed: True" in output
    assert "account-key" not in output


def test_nic_report_validation_is_shared_by_private_object_reads():
    report = b'{"probe":"ok","vpc_ip":"10.52.0.4"}'
    assert validated_nic_report(report, "10.52.0.0/24") == {"probe": "ok", "vpc_ip": "10.52.0.4"}
    for invalid in (b'{"probe":"ok","vpc_ip":"192.0.2.1"}', b'{"probe":"ok","vpc_ip":171180036}', b'{"probe":"ok","vpc_ip":null,"secret":true}', b"x" * 257):
        with pytest.raises(ValueError):
            validated_nic_report(invalid, "10.52.0.0/24")


def test_uvicorn_deployment_includes_websocket_protocol():
    assert "websockets==15.0.1" in Path(__file__).with_name("requirements.txt").read_text().splitlines()


@pytest.fixture
def auth(monkeypatch):
    monkeypatch.setattr(jobs, "load_dotenv", lambda _: None)
    monkeypatch.setenv("CERBERUS_CONTROL_TOKEN", CONTROL_TOKEN)
    return {"Authorization": f"Bearer {CONTROL_TOKEN}"}


def wait_for_terminal(client, job_id, headers):
    for _ in range(50):
        response = client.get(f"/jobs/{job_id}", headers=headers)
        if response.json()["status"] in ("completed", "failed"):
            return response.json()
        time.sleep(0.01)
    pytest.fail("Job did not finish")


def test_jobs_require_a_separate_strong_control_token(monkeypatch):
    monkeypatch.setattr(jobs, "load_dotenv", lambda _: None)
    monkeypatch.delenv("CERBERUS_CONTROL_TOKEN", raising=False)
    with TestClient(app) as client:
        assert client.post("/jobs", json={"type": "connectivity"}).status_code == 503
        monkeypatch.setenv("CERBERUS_CONTROL_TOKEN", "short")
        assert client.post("/jobs", json={"type": "connectivity"}).status_code == 503
        monkeypatch.setenv("CERBERUS_CONTROL_TOKEN", CONTROL_TOKEN)
        monkeypatch.setenv("VULTR_API_KEY", CONTROL_TOKEN)
        assert client.post("/jobs", json={"type": "connectivity"}).status_code == 503
        monkeypatch.delenv("VULTR_API_KEY")
        monkeypatch.setenv("NETBIRD_SANDBOX_SETUP_KEY", CONTROL_TOKEN)
        assert client.post("/jobs", json={"type": "connectivity"}).status_code == 503
        monkeypatch.delenv("NETBIRD_SANDBOX_SETUP_KEY")
        monkeypatch.setenv("NETBIRD_CONTROL_SETUP_KEY", CONTROL_TOKEN)
        assert client.post("/jobs", json={"type": "connectivity"}).status_code == 503
        monkeypatch.delenv("NETBIRD_CONTROL_SETUP_KEY")
        assert client.post("/jobs", json={"type": "connectivity"}).status_code == 401
        assert client.get("/jobs/nonexistent").status_code == 401


def test_control_api_rejects_group_readable_dotenv(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("placeholder")
    env_file.chmod(0o644)
    monkeypatch.setattr("jobs.Path", lambda _: env_file)
    monkeypatch.setattr(jobs, "load_dotenv", lambda _: None)
    monkeypatch.setenv("CERBERUS_CONTROL_TOKEN", CONTROL_TOKEN)
    with TestClient(app) as client:
        assert client.post("/jobs", json={"type": "connectivity"}, headers={"Authorization": f"Bearer {CONTROL_TOKEN}"}).status_code == 503


def test_connectivity_job_result_and_websocket_replay(auth, monkeypatch):
    monkeypatch.setattr(jobs, "load_keys", lambda: ("account-key", "inference-key"))

    async def check(client, api_key, inference_key):
        assert (api_key, inference_key) == ("account-key", "inference-key")
        return ["example-model"], 1

    monkeypatch.setattr(jobs, "check_connectivity", check)
    with TestClient(app) as client:
        started = client.post("/jobs", json={"type": "connectivity"}, headers=auth)
        assert started.status_code == 202
        job_id = started.json()["id"]
        assert wait_for_terminal(client, job_id, auth)["status"] == "completed"
        result = client.get(f"/jobs/{job_id}/result", headers=auth)
        assert result.status_code == 200
        assert result.json() == {"models": ["example-model"], "region_count": 1}
        with client.websocket_connect(f"/jobs/{job_id}/events") as websocket:
            websocket.send_json({"token": CONTROL_TOKEN})
            events = [websocket.receive_json() for _ in range(3)]
        assert [event["status"] for event in events] == ["queued", "running", "completed"]
        assert [event["sequence"] for event in events] == [0, 1, 2]
        assert CONTROL_TOKEN not in str(events)


def test_websocket_streams_live_job_events(auth, monkeypatch):
    gate = threading.Event()
    monkeypatch.setattr(jobs, "load_keys", lambda: ("account-key", "inference-key"))

    async def check(client, api_key, inference_key):
        await asyncio.to_thread(gate.wait, 1)
        return ["example-model"], 1

    monkeypatch.setattr(jobs, "check_connectivity", check)
    try:
        with TestClient(app) as client:
            job_id = client.post("/jobs", json={"type": "connectivity"}, headers=auth).json()["id"]
            assert client.get(f"/jobs/{job_id}/result", headers=auth).status_code == 202
            with client.websocket_connect(f"/jobs/{job_id}/events") as websocket:
                websocket.send_json({"token": CONTROL_TOKEN})
                assert websocket.receive_json()["status"] == "queued"
                assert websocket.receive_json()["status"] == "running"
                gate.set()
                assert websocket.receive_json()["status"] == "completed"
    finally:
        gate.set()


def test_failed_job_does_not_disclose_upstream_exception(auth, monkeypatch):
    monkeypatch.setattr(jobs, "load_keys", lambda: ("account-key", "inference-key"))

    async def check(client, api_key, inference_key):
        raise RuntimeError("sensitive-upstream-detail")

    monkeypatch.setattr(jobs, "check_connectivity", check)
    with TestClient(app) as client:
        job_id = client.post("/jobs", json={"type": "connectivity"}, headers=auth).json()["id"]
        assert wait_for_terminal(client, job_id, auth)["status"] == "failed"
        result = client.get(f"/jobs/{job_id}/result", headers=auth)
        assert result.status_code == 502
        assert "sensitive-upstream-detail" not in result.text


def test_sandbox_job_requires_feature_gate_explicit_approval_and_one_off_key(auth, monkeypatch):
    monkeypatch.delenv("CERBERUS_ENABLE_SANDBOX_JOBS", raising=False)
    with TestClient(app) as client:
        body = {"type": "sandbox_smoke", "approve_vm": True, "netbird_setup_key": "A" * 36}
        assert client.post("/jobs", headers=auth, json=body).status_code == 503
        monkeypatch.setenv("CERBERUS_ENABLE_SANDBOX_JOBS", "true")
        assert client.post("/jobs", headers=auth, json={**body, "approve_vm": False}).status_code == 400
        invalid = client.post("/jobs", headers=auth, json={**body, "netbird_setup_key": "short"})
        assert invalid.status_code == 400 and "short" not in invalid.text
        assert client.post("/jobs", headers=auth, json={"type": "connectivity", "netbird_setup_key": "A" * 36}).status_code == 400


def test_vpc_sandbox_job_needs_no_setup_key_but_still_requires_explicit_approval(auth, monkeypatch):
    seen = []

    async def fake_vpc_smoke(job, key, signals, vpc_mode=False):
        seen.append((key, vpc_mode))
        job.result = {"destroyed": True}
        await job.publish("completed")

    monkeypatch.setenv("CERBERUS_ENABLE_SANDBOX_JOBS", "true")
    monkeypatch.setenv("CERBERUS_VPC_ID", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    monkeypatch.setenv("CERBERUS_CONTROL_INSTANCE_ID", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    monkeypatch.setenv("CERBERUS_CONTROL_VPC_IP", "10.52.0.2")
    monkeypatch.setenv("CERBERUS_VPC_SUBNET", "10.52.0.0/24")
    monkeypatch.setattr(jobs, "run_sandbox_smoke_job", fake_vpc_smoke)
    with TestClient(app) as client:
        assert client.post("/jobs", headers=auth, json={"type": "sandbox_smoke"}).status_code == 400
        r = client.post("/jobs", headers=auth, json={"type": "sandbox_smoke", "approve_vm": True})
        assert r.status_code == 202
        assert wait_for_terminal(client, r.json()["id"], auth)["status"] == "completed"
    assert seen == [(None, True)]


@pytest.mark.parametrize("hold_seconds", [0, 300])
def test_single_use_arm_starts_only_one_approved_vpc_job_with_gate_off(auth, monkeypatch, hold_seconds):
    seen = []

    async def fake_smoke(job, key, signals, vpc_mode=False, diagnostic_hold_seconds=None, diagnostic_upload=None):
        seen.append((key, vpc_mode, diagnostic_hold_seconds, diagnostic_upload))
        job.result = {"destroyed": True}
        await job.publish("completed")

    monkeypatch.delenv("CERBERUS_ENABLE_SANDBOX_JOBS", raising=False)
    for name, value in (("CERBERUS_VPC_ID", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                        ("CERBERUS_CONTROL_INSTANCE_ID", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
                        ("CERBERUS_CONTROL_VPC_IP", "10.52.0.2"), ("CERBERUS_VPC_SUBNET", "10.52.0.0/24")):
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(jobs, "run_sandbox_smoke_job", fake_smoke)
    with TestClient(app) as client:
        assert client.post("/jobs/arm-sandbox", json={"approve_vm": True}).status_code == 401
        assert client.post("/jobs/arm-sandbox", headers=auth, json={"approve_vm": False}).status_code == 400
        assert client.post("/jobs/arm-sandbox", headers=auth, json={"approve_vm": "true"}).status_code == 422
        assert client.post("/jobs/arm-sandbox", headers=auth, json={"approve_vm": True, "ttl_seconds": True}).status_code == 422
        assert client.post("/jobs/arm-sandbox", headers=auth, json={"approve_vm": True, "diagnostic_hold_seconds": True}).status_code == 422
        assert client.post("/jobs/arm-sandbox", headers=auth, json={"approve_vm": True, "ttl_seconds": 301}).status_code == 400
        assert client.post("/jobs/arm-sandbox", headers=auth, json={"approve_vm": True, "diagnostic_hold_seconds": 301}).status_code == 400
        armed = client.post("/jobs/arm-sandbox", headers=auth, json={"approve_vm": True, "ttl_seconds": 120, "diagnostic_hold_seconds": hold_seconds})
        assert armed.status_code == 201
        assert armed.json()["diagnostic_hold_seconds"] == hold_seconds
        arm_token = armed.json()["arm_token"]
        assert len(arm_token) >= 32
        assert client.post("/jobs/arm-sandbox", headers=auth, json={"approve_vm": True}).status_code == 429
        assert client.post("/jobs", headers=auth, json={"type": "connectivity", "arm_token": arm_token}).status_code == 400
        assert client.post("/jobs", headers=auth, json={"type": "scan", "target": "seeded_flask", "arm_token": arm_token}).status_code == 400
        body = {"type": "sandbox_smoke", "approve_vm": True}
        assert client.post("/jobs", headers=auth, json=body).status_code == 503
        assert client.post("/jobs", headers=auth, json={**body, "arm_token": "wrong"}).status_code == 403
        assert client.post("/jobs", headers=auth, json={**body, "arm_token": arm_token, "netbird_setup_key": "A" * 36}).status_code == 400
        start = client.post("/jobs", headers=auth, json={**body, "arm_token": arm_token})
        assert start.status_code == 202
        assert wait_for_terminal(client, start.json()["id"], auth)["status"] == "completed"
        assert client.post("/jobs", headers=auth, json={**body, "arm_token": arm_token}).status_code == 403
        result = client.get(f"/jobs/{start.json()['id']}/result", headers=auth)
        with client.websocket_connect(f"/jobs/{start.json()['id']}/events") as websocket:
            websocket.send_json({"token": CONTROL_TOKEN})
            events = [websocket.receive_json() for _ in range(2)]
    with TestClient(vpc_callback_app) as client:
        assert client.post("/jobs/arm-sandbox", headers=auth, json={"approve_vm": True}).status_code == 404
    assert seen == [(None, True, hold_seconds, None)]
    assert arm_token not in str(result.json()) + str(events)


def test_armed_vpc_job_accepts_only_a_bounded_presigned_nic_upload(auth, monkeypatch):
    seen = []

    async def fake_smoke(job, key, signals, vpc_mode=False, diagnostic_hold_seconds=None, diagnostic_upload=None):
        seen.append((key, vpc_mode, diagnostic_upload))
        job.result = {"destroyed": True}
        await job.publish("completed")

    client = boto3.client(
        "s3", region_name="ord1", endpoint_url="https://ord1.vultrobjects.com",
        aws_access_key_id="test-access", aws_secret_access_key="test-secret",
        config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
    )
    form = presign_nic_post(client, "https://ord1.vultrobjects.com", "cerberus-nic-demo", "nic/" + "a" * 32 + ".json")
    monkeypatch.delenv("CERBERUS_ENABLE_SANDBOX_JOBS", raising=False)
    for name, value in (("CERBERUS_VPC_ID", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                        ("CERBERUS_CONTROL_INSTANCE_ID", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
                        ("CERBERUS_CONTROL_VPC_IP", "10.52.0.2"), ("CERBERUS_VPC_SUBNET", "10.52.0.0/24")):
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(jobs, "run_sandbox_smoke_job", fake_smoke)
    with TestClient(app) as api:
        armed = api.post("/jobs/arm-sandbox", headers=auth, json={"approve_vm": True})
        assert armed.status_code == 201
        body = {"type": "sandbox_smoke", "approve_vm": True, "arm_token": armed.json()["arm_token"]}
        assert api.post("/jobs", headers=auth, json={**body, "diagnostic_upload": {**form, "url": "http://invalid.example/"}}).status_code == 400
        started = api.post("/jobs", headers=auth, json={**body, "diagnostic_upload": form})
        assert started.status_code == 202
        assert wait_for_terminal(api, started.json()["id"], auth)["status"] == "completed"
        assert api.post("/jobs", headers=auth, json={**body, "diagnostic_upload": form}).status_code == 403
        result = api.get(f"/jobs/{started.json()['id']}/result", headers=auth)
    assert seen == [(None, True, form)]
    assert form["fields"]["policy"] not in result.text
    assert "test-secret" not in result.text


def test_sandbox_arm_expires_without_creating_a_job():
    registry = jobs.JobRegistry()
    with pytest.raises(ValueError):
        registry.arm_sandbox(ttl_seconds=120, diagnostic_hold_seconds=301)
    registry.jobs["active"] = jobs.Job(kind="sandbox_smoke", status="running")
    assert registry.arm_sandbox(ttl_seconds=120) is None
    registry.jobs["active"].status = "completed"
    token = registry.arm_sandbox(ttl_seconds=120)
    registry.arm_expires = 0
    assert not registry.consume_sandbox_arm(token)
    assert not registry.consume_sandbox_arm(token)


def test_sandbox_job_events_and_result_never_include_setup_key(auth, monkeypatch):
    seen = []

    async def fake_smoke(job, key, signals):
        seen.append((key, signals))
        await job.publish("running", "provisioning")
        job.result = {"sandbox": {"hostname": "sandbox", "uname": "Linux 4.19.0-gvisor", "exit_code": 0}, "destroyed": True}
        await job.publish("completed", "teardown")

    monkeypatch.setenv("CERBERUS_ENABLE_SANDBOX_JOBS", "true")
    monkeypatch.setattr(jobs, "run_sandbox_smoke_job", fake_smoke)
    with TestClient(app) as client:
        start = client.post("/jobs", headers=auth, json={"type": "sandbox_smoke", "approve_vm": True, "netbird_setup_key": "A" * 36})
        assert start.status_code == 202
        job_id = start.json()["id"]
        assert wait_for_terminal(client, job_id, auth)["type"] == "sandbox_smoke"
        result = client.get(f"/jobs/{job_id}/result", headers=auth)
        with client.websocket_connect(f"/jobs/{job_id}/events") as websocket:
            websocket.send_json({"token": CONTROL_TOKEN})
            events = [websocket.receive_json() for _ in range(3)]
    assert result.status_code == 200
    assert seen[0][0] == "A" * 36
    assert "A" * 36 not in str(result.json()) + str(events)
    assert [event["step"] for event in events] == ["sandbox_smoke", "provisioning", "teardown"]


def test_job_type_and_lookup_are_bounded(auth):
    with TestClient(app) as client:
        assert client.post("/jobs", json={"type": "shell"}, headers=auth).status_code == 422
        assert client.get("/jobs/nonexistent", headers=auth).status_code == 404
        assert client.get("/jobs/nonexistent/result", headers=auth).status_code == 404


def test_registry_refuses_to_start_when_active_jobs_fill_capacity():
    registry = jobs.JobRegistry(max_jobs=1)
    registry.jobs["running"] = jobs.Job(id="running", status="running")
    assert registry.create() is None


@pytest.mark.parametrize("readiness_fails,missing_log,dns_exit,failed_stage,hold", [
    (False, False, 1, None, 0), (False, True, 1, None, 0), (True, False, 1, None, 5),
    (False, False, 0, None, 0), (False, False, 1, "opensandbox_config", 5),
])
def test_sandbox_worker_proves_private_path_and_cleans_up(monkeypatch, readiness_fails, missing_log, dns_exit, failed_stage, hold):
    calls = []
    destroyed = False
    proof = {
        "hostname": "vx1", "uname": "Linux vx1", "cpu_virt": "svm", "kvm_device": True,
        "kvm_access": True, "sandbox_hostname": "smoke", "sandbox_uname": "Linux gvisor",
        "exit_code": 0, "netbird_ip": "100.124.192.2",
        "opensandbox": {"hostname": "opensandbox", "uname": "Linux 4.19.0-gvisor", "exit_code": 0,
            "api_key": "scoped-secret-should-stay-private", "isolation": {
            "network_id": "a" * 64, "bridge": "br-aaaaaaaaaaaa", "gateway": "172.23.0.1",
            "unexpected": "secret-in-proof",
            "test_net_1": {"destination": "192.0.2.1:65000", "exit_code": 1},
            "dns_external": {"destination": "example.com", "exit_code": dns_exit},
            "host_gateway": {"destination": "172.23.0.1:65000", "exit_code": 1},
            "host_drop_packets_before": 0, "host_drop_packets_after": 1, "host_drop_packets_delta": 1,
            "kernel_drop_log": None if missing_log else "cerberus-os-drop IN=br-aaaaaaaaaaaa OUT= DST=172.23.0.1 DPT=65000",
        }},
    }

    class Signals:
        unregistered = False

        def register(self):
            return "R" * 36

        async def wait(self, token, timeout):
            if readiness_fails:
                raise TimeoutError("No callback")
            if failed_stage:
                return {"failure_stage": failed_stage, "exit_code": 1}
            return proof

        def stage(self, token):
            return "network_create" if readiness_fails else None

        def unregister(self, token):
            self.unregistered = token == "R" * 36

    def respond(request):
        nonlocal destroyed
        calls.append((request.method, request.url.path))
        if request.method == "POST":
            script = unpack_vpc_payload(base64.b64decode(json.loads(request.content)["user_data"]).decode())
            assert "http://100.124.55.15:8000/internal/ready" in script
            assert script.count("A" * 36) == 1
            assert "account-key" not in script
            return httpx.Response(202, json={"instance": {"id": "instance-123"}})
        if request.method == "DELETE":
            destroyed = True
            return httpx.Response(204)
        if request.url.path == "/v2/instances/instance-123":
            return httpx.Response(404 if destroyed else 200, json={"instance": {"status": "active", "power_status": "running"}})
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "healthy"})
        return httpx.Response(401)

    held = []

    async def fake_sleep(seconds):
        assert not destroyed
        held.append(seconds)

    monkeypatch.setenv("CERBERUS_DIAGNOSTIC_HOLD_SECONDS", str(hold))
    monkeypatch.setattr(jobs.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(jobs, "load_keys", lambda: ("account-key", "inference-key"))
    monkeypatch.setattr(jobs.subprocess, "check_output", lambda *args, **kwargs: json.dumps({
        "netbirdIp": "100.124.55.15/16", "management": {"connected": True}, "signal": {"connected": True},
    }))
    client_type = httpx.AsyncClient
    monkeypatch.setattr(jobs.httpx, "AsyncClient", lambda **kwargs: client_type(transport=httpx.MockTransport(respond), **kwargs))
    signals = Signals()
    job = jobs.Job(kind="sandbox_smoke")
    asyncio.run(jobs.run_sandbox_smoke_job(job, "A" * 36, signals))
    assert destroyed and signals.unregistered
    assert held == ([hold] if hold else [])
    assert ("DELETE", "/v2/instances/instance-123") in calls
    assert calls[-1] == ("GET", "/v2/instances/instance-123")
    assert job.status == ("failed" if readiness_fails or missing_log or dns_exit == 0 or failed_stage else "completed")
    assert "A" * 36 not in str(job.error) + str(job.events)
    if failed_stage:
        assert failed_stage in job.error
    if readiness_fails:
        assert "stage=network_create" in job.error and "TimeoutError" in job.error
    if not readiness_fails and not missing_log and dns_exit != 0 and not failed_stage:
        assert job.result["destroyed"] is True
        assert job.result["opensandbox"]["exit_code"] == 0
        assert "A" * 36 not in str(job.result) + str(job.events)
        assert "scoped-secret-should-stay-private" not in str(job.result) + str(job.events)
        assert "secret-in-proof" not in str(job.result) + str(job.events)


@pytest.mark.parametrize("reported_ip", ["10.52.0.3", "10.52.0.4"])
def test_vpc_worker_proves_private_connection_without_a_netbird_setup_key(monkeypatch, reported_ip):
    vpc_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    control_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    destroyed = False
    calls = []
    proof = {
        "hostname": "vx1", "uname": "Linux vx1", "cpu_virt": "svm", "kvm_device": True, "kvm_access": True,
        "sandbox_hostname": "smoke", "sandbox_uname": "Linux gvisor", "exit_code": 0, "vpc_ip": reported_ip,
        "opensandbox": {"hostname": "sandbox", "uname": "Linux 4.19.0-gvisor", "exit_code": 0, "isolation": {
            "network_id": "a" * 64, "bridge": "br-aaaaaaaaaaaa", "gateway": "172.23.0.1",
            "test_net_1": {"destination": "192.0.2.1:65000", "exit_code": 1},
            "dns_external": {"destination": "example.com", "exit_code": 1},
            "host_gateway": {"destination": "172.23.0.1:65000", "exit_code": 1},
            "host_drop_packets_before": 0, "host_drop_packets_after": 1, "host_drop_packets_delta": 1,
            "kernel_drop_log": "cerberus-os-drop IN=br-aaaaaaaaaaaa OUT= DST=172.23.0.1 DPT=65000",
        }},
    }

    class Signals:
        def register(self):
            return "R" * 36

        async def wait(self, token, timeout):
            return proof

        def stage(self, token):
            return None

        def unregister(self, token):
            pass

    def respond(request):
        nonlocal destroyed
        calls.append((request.method, request.url.path))
        path = request.url.path
        if path == f"/v2/vpcs/{vpc_id}":
            return httpx.Response(200, json={"vpc": {"id": vpc_id, "region": "ord", "v4_subnet": "10.52.0.0", "v4_subnet_mask": 24}})
        if path == f"/v2/instances/{control_id}/vpcs":
            return httpx.Response(200, json={"vpcs": [{"id": vpc_id, "ip_address": "10.52.0.2"}]})
        if request.method == "HEAD" and request.url.host == "10.52.0.2":
            return httpx.Response(405)
        if request.method == "POST":
            payload = json.loads(request.content)
            script = unpack_vpc_payload(base64.b64decode(payload["user_data"]).decode())
            assert payload["attach_vpc"] == [vpc_id]
            assert "netbird up" not in script and "account-key" not in script
            return httpx.Response(202, json={"instance": {"id": "instance-123"}})
        if path == "/v2/instances/instance-123/vpcs":
            return httpx.Response(200, json={"vpcs": [{"id": vpc_id, "ip_address": "10.52.0.3"}]})
        if request.method == "DELETE":
            destroyed = True
            return httpx.Response(204)
        if path == "/v2/instances/instance-123":
            return httpx.Response(404 if destroyed else 200, json={"instance": {"status": "active", "power_status": "running"}})
        if path == "/health":
            return httpx.Response(200, json={"status": "healthy"})
        return httpx.Response(401)

    for name, value in (("CERBERUS_VPC_ID", vpc_id), ("CERBERUS_CONTROL_INSTANCE_ID", control_id),
                        ("CERBERUS_CONTROL_VPC_IP", "10.52.0.2"), ("CERBERUS_VPC_SUBNET", "10.52.0.0/24"),
                        ("VULTR_REGION", "ord")):
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(jobs, "load_keys", lambda: ("account-key", "inference-key"))
    monkeypatch.setenv("CERBERUS_DIAGNOSTIC_HOLD_SECONDS", "301")
    client_type = httpx.AsyncClient
    monkeypatch.setattr(jobs.httpx, "AsyncClient", lambda **kwargs: client_type(transport=httpx.MockTransport(respond), **kwargs))
    job = jobs.Job(kind="sandbox_smoke")
    asyncio.run(jobs.run_sandbox_smoke_job(job, None, Signals(), vpc_mode=True, diagnostic_hold_seconds=0))
    assert job.status == ("completed" if reported_ip == "10.52.0.3" else "failed") and destroyed
    if reported_ip == "10.52.0.3":
        assert job.result["destroyed"] and job.result["opensandbox"]["isolation"]["dns_external"]["exit_code"] == 1
        assert job.result["vpc_ip"] == "10.52.0.3"
        assert "account-key" not in str(job.result) + str(job.events)
    else:
        assert job.result is None and ("GET", "/health") not in calls
    assert calls.index(("GET", f"/v2/instances/{control_id}/vpcs")) < calls.index(("POST", "/v2/instances"))
    assert ("GET", "/v2/instances/instance-123") == calls[-1]


@pytest.mark.parametrize("bad_attachment", [True, False])
def test_vpc_job_refuses_unverified_control_network_before_provision(monkeypatch, bad_attachment):
    vpc_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    control_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    seen = []

    class Signals:
        def register(self):
            return "R" * 36

        def stage(self, token):
            return None

        def unregister(self, token):
            pass

    def respond(request):
        seen.append((request.method, request.url.path))
        if request.method == "POST":
            pytest.fail("VPC preflight must reject this without creating a VM")
        if request.url.path == f"/v2/vpcs/{vpc_id}":
            return httpx.Response(200, json={"vpc": {"id": vpc_id, "region": "ord", "v4_subnet": "10.52.0.0", "v4_subnet_mask": 24}})
        if request.url.path == f"/v2/instances/{control_id}/vpcs":
            return httpx.Response(200, json={"vpcs": [{"id": vpc_id, "ip_address": "10.52.0.4" if bad_attachment else "10.52.0.2"}]})
        return httpx.Response(404 if not bad_attachment else 200)

    for name, value in (("CERBERUS_VPC_ID", vpc_id), ("CERBERUS_CONTROL_INSTANCE_ID", control_id),
                        ("CERBERUS_CONTROL_VPC_IP", "10.52.0.2"), ("CERBERUS_VPC_SUBNET", "10.52.0.0/24"),
                        ("VULTR_REGION", "ord")):
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(jobs, "load_keys", lambda: ("account-key", "inference-key"))
    client_type = httpx.AsyncClient
    monkeypatch.setattr(jobs.httpx, "AsyncClient", lambda **kwargs: client_type(transport=httpx.MockTransport(respond), **kwargs))
    job = jobs.Job(kind="sandbox_smoke")
    asyncio.run(jobs.run_sandbox_smoke_job(job, None, Signals(), vpc_mode=True))
    assert job.status == "failed" and job.result is None
    assert all(method != "POST" for method, _ in seen)


def test_registry_allows_only_one_active_sandbox_vm():
    registry = jobs.JobRegistry()
    registry.jobs["busy"] = jobs.Job(id="busy", kind="sandbox_smoke", status="running")
    assert registry.create("sandbox_smoke", "A" * 36, object()) is None


def test_sandbox_job_refuses_disconnected_control_peer(monkeypatch):
    monkeypatch.setattr(jobs.subprocess, "check_output", lambda *args, **kwargs: json.dumps({
        "netbirdIp": "100.124.55.15/16", "management": {"connected": False}, "signal": {"connected": True},
    }))
    monkeypatch.setattr(jobs, "load_keys", lambda: pytest.fail("No account or VM API call should occur"))
    job = jobs.Job(kind="sandbox_smoke")
    asyncio.run(jobs.run_sandbox_smoke_job(job, "A" * 36, object()))
    assert job.status == "failed"
    assert "A" * 36 not in str(job.events) + str(job.error)


def test_sandbox_job_rejects_unbounded_diagnostic_hold_before_provision(monkeypatch):
    monkeypatch.setenv("CERBERUS_DIAGNOSTIC_HOLD_SECONDS", "301")
    monkeypatch.setattr(jobs.subprocess, "check_output", lambda *args, **kwargs: json.dumps({
        "netbirdIp": "100.124.55.15/16", "management": {"connected": True}, "signal": {"connected": True},
    }))
    monkeypatch.setattr(jobs, "load_keys", lambda: pytest.fail("No VM must be created with an unbounded diagnostic hold"))
    job = jobs.Job(kind="sandbox_smoke")
    asyncio.run(jobs.run_sandbox_smoke_job(job, "A" * 36, object()))
    assert job.status == "failed" and job.result is None


def test_websocket_requires_first_message_not_query_token(auth):
    with TestClient(app) as client:
        with client.websocket_connect(f"/jobs/nonexistent/events?token={CONTROL_TOKEN}") as websocket:
            websocket.send_json({"token": "wrong"})
            with pytest.raises(WebSocketDisconnect) as error:
                websocket.receive_json()
        assert error.value.code == 1008


# --- Scan job: the full find -> prove -> patch -> re-prove loop over a web API ---

def test_scan_rejects_unknown_target(auth):
    with TestClient(app) as client:
        resp = client.post("/jobs", json={"type": "scan", "target": "../etc"}, headers=auth)
        assert resp.status_code == 400
        # No target at all is also rejected: the endpoint takes a name, not a path.
        assert client.post("/jobs", json={"type": "scan"}, headers=auth).status_code == 400


def test_scan_rejects_sandbox_credentials(auth):
    with TestClient(app) as client:
        resp = client.post(
            "/jobs",
            json={"type": "scan", "target": "seeded_flask", "approve_vm": True},
            headers=auth,
        )
        assert resp.status_code == 400


def test_scan_jobs_are_disabled_by_default(auth, monkeypatch):
    monkeypatch.delenv("CERBERUS_ENABLE_LOCAL_SCAN_JOBS", raising=False)
    with TestClient(app) as client:
        assert client.post("/jobs", json={"type": "scan", "target": "seeded_flask"}, headers=auth).status_code == 503


def test_scan_seeded_flask_runs_full_loop(auth, monkeypatch):
    pytest.importorskip("flask", reason="seeded target app requires Flask")
    monkeypatch.setenv("CERBERUS_ENABLE_LOCAL_SCAN_JOBS", "true")
    with TestClient(app) as client:
        start = client.post("/jobs", json={"type": "scan", "target": "seeded_flask"}, headers=auth)
        assert start.status_code == 202
        job_id = start.json()["id"]
        # A real scan boots the target and runs the whole loop (finder wall-clock
        # cap plus five sequential patch/re-exploit cycles); give it ample room so
        # a loaded CI box does not fail the assert while the scan is still healthy.
        for _ in range(1800):
            if client.get(f"/jobs/{job_id}", headers=auth).json()["status"] in ("completed", "failed"):
                break
            time.sleep(0.1)
        status = client.get(f"/jobs/{job_id}", headers=auth).json()["status"]
        assert status == "completed", f"scan did not complete: {status}"
        result = client.get(f"/jobs/{job_id}/result", headers=auth).json()
        assert result["confirmed_findings"] == 5
        assert result["certified_closed"] == 5
        assert {f["vuln_class"] for f in result["findings"]} == {
            "sqli", "path_traversal", "command_injection", "ssrf", "auth_bypass"
        }
        # The report must record which brain produced the plan (Vultr inference or
        # the offline fallback) so a run never implies the model ran when it did not.
        assert result["triage_source"]


# --- Sandbox scan jobs: a seeded target runs inside gVisor on a disposable VPC VX1 ---

VPC_ENV = {
    "CERBERUS_VPC_ID": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "CERBERUS_CONTROL_INSTANCE_ID": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "CERBERUS_CONTROL_VPC_IP": "10.52.0.2",
    "CERBERUS_VPC_SUBNET": "10.52.0.0/24",
    "VULTR_REGION": "ord",
}
S3_ENV = {
    "CERBERUS_S3_ENDPOINT": "ord1.vultrobjects.com",  # scheme-less, like the operator .env
    "CERBERUS_S3_BUCKET": "cerberus-target-src",
    "CERBERUS_S3_ACCESS_KEY": "test-access",
    "CERBERUS_S3_SECRET_KEY": "test-secret",
}


class FakeScanStorage:
    def __init__(self, delegate):
        self._delegate = delegate
        self.meta = delegate.meta
        self.objects = {}
        self.deleted = []

    def generate_presigned_url(self, *args, **kwargs):
        return self._delegate.generate_presigned_url(*args, **kwargs)

    def put_object(self, Bucket, Key, Body):
        self.objects[(Bucket, Key)] = Body

    def delete_object(self, Bucket, Key):
        self.deleted.append((Bucket, Key))
        self.objects.pop((Bucket, Key), None)


def fake_scan_proof(vpc_ip="10.52.0.3", target="healthy", runtime="runsc"):
    return {
        "hostname": "vx1", "uname": "Linux vx1", "cpu_virt": "svm", "kvm_device": True, "kvm_access": True,
        "runtime": runtime, "sandbox_hostname": "smoke", "sandbox_uname": "Linux gvisor", "exit_code": 0,
        "vpc_ip": vpc_ip, "target": target, "endpoint": f"http://{vpc_ip}:8081",
    }


def fake_finder_report(target):
    finding = Finding(
        id="sqli-1", vuln_class="sqli", endpoint="/product", param="id",
        input_to_sink="query:id -> product()", sink_file="app.py", sink_line=42,
        exploit_request="GET /product?id=1 OR 1=1", confirming_output="CANARY observed",
        canary_observed=True, canary_value="CANARY-x", fix="parameterize", confirmer="sqli_basic",
        triage_source="offline-heuristic",
    )
    return FinderReport(
        target=target, findings=[finding],
        coverage=Coverage(
            classes_tested=["sqli"], endpoints_tested=["/product"], candidates_seen=5,
            candidates_tested=2, not_reached=["ssrf"], steps_used=2, wall_clock_seconds=1.5,
        ),
        triage_source="offline-heuristic",
    )


def run_fake_sandbox_scan(monkeypatch, proof, target_name="seeded_flask", remediate=False, second_proof=None, finder_report=None, batch_raises=False, target_runtime="gvisor"):
    state = {"calls": [], "scripts": [], "scanned": [], "storage": [], "destroyed": False, "second_tokens": []}

    class Signals:
        registered = False
        unregistered = False
        registered_tokens = []
        unregistered_tokens = []
        wait_calls = []

        def register(self):
            self.registered = True
            token = "R" * 43 if not self.registered_tokens else "S" * 43
            self.registered_tokens.append(token)
            if token == "S" * 43:
                state["second_tokens"].append(token)
            return token

        async def wait(self, token, timeout):
            assert timeout == 600
            self.wait_calls.append(token)
            return (second_proof if second_proof is not None else proof) if token == "S" * 43 else proof

        def stage(self, token):
            return None

        def unregister(self, token):
            self.unregistered = True
            self.unregistered_tokens.append(token)
            if token == "S" * 43:
                state["second_unregistered"] = token

    signals = Signals()

    def respond(request):
        calls = state["calls"]
        calls.append((request.method, request.url.host, request.url.path))
        path = request.url.path
        if path == f"/v2/vpcs/{VPC_ENV['CERBERUS_VPC_ID']}":
            return httpx.Response(200, json={"vpc": {"id": VPC_ENV["CERBERUS_VPC_ID"], "region": "ord", "v4_subnet": "10.52.0.0", "v4_subnet_mask": 24}})
        if path == f"/v2/instances/{VPC_ENV['CERBERUS_CONTROL_INSTANCE_ID']}/vpcs":
            return httpx.Response(200, json={"vpcs": [{"id": VPC_ENV["CERBERUS_VPC_ID"], "ip_address": "10.52.0.2"}]})
        if request.method == "HEAD" and request.url.host == "10.52.0.2":
            return httpx.Response(405)
        if request.method == "POST" and path == "/v2/instances":
            payload = json.loads(request.content)
            assert payload["attach_vpc"] == [VPC_ENV["CERBERUS_VPC_ID"]]
            assert len(payload["user_data"]) < 16 * 1024
            state["scripts"].append(unpack_vpc_payload(base64.b64decode(payload["user_data"]).decode()))
            state["destroyed"] = False  # a fresh cycle: the prior 404 must not leak into it
            return httpx.Response(202, json={"instance": {"id": "instance-123"}})
        if path == "/v2/instances/instance-123/vpcs":
            return httpx.Response(200, json={"vpcs": [{"id": VPC_ENV["CERBERUS_VPC_ID"], "ip_address": "10.52.0.3"}]})
        if request.method == "DELETE":
            state["destroyed"] = True
            return httpx.Response(204)
        if path == "/v2/instances/instance-123":
            if state["destroyed"]:
                return httpx.Response(404)
            return httpx.Response(200, json={"instance": {"status": "active", "power_status": "running"}})
        return httpx.Response(401)

    for name, value in VPC_ENV.items():
        monkeypatch.setenv(name, value)
    for name, value in S3_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(jobs, "load_keys", lambda: ("account-key", "inference-key"))
    client_type = httpx.AsyncClient
    monkeypatch.setattr(jobs.httpx, "AsyncClient", lambda **kwargs: client_type(transport=httpx.MockTransport(respond), **kwargs))

    real_client_factory = boto3.client

    def client_factory(service="s3", **kwargs):
        assert service == "s3"
        storage = FakeScanStorage(real_client_factory(service, **kwargs))
        state["storage"].append(storage)
        return storage

    monkeypatch.setattr(boto3, "client", client_factory)

    def fake_run_finder(base_url, source_dir, **kwargs):
        state["scanned"].append((base_url, source_dir, kwargs))
        return finder_report if finder_report is not None else fake_finder_report(base_url)

    monkeypatch.setattr(finder.pipeline, "run_finder", fake_run_finder)

    if remediate:

        def fake_remediate_batch(findings, source_dir, *, timeout=12.0, launcher=None):
            """Exercise the real launcher seam exactly like remediate_batch does."""
            assert launcher is not None
            state["remediated"] = ([finding.id for finding in findings], source_dir, timeout)
            if batch_raises:
                raise RuntimeError("y" * 400)
            with tempfile.TemporaryDirectory() as tmp:
                dst = Path(tmp) / "target"
                shutil.copytree(source_dir, dst)
                try:
                    base_url, stop = launcher(dst, "app.py")
                except Exception as exc:
                    return [
                        finder.remediate.RemediationResult(
                            finding_id=finding.id, vuln_class=finding.vuln_class,
                            endpoint=finding.endpoint, param=finding.param,
                            validation_notes=f"shared launch failed: {exc}"[:200],
                        )
                        for finding in findings
                    ], False
                try:
                    state["relauncher_base"] = base_url
                    return [
                        finder.remediate.RemediationResult(
                            finding_id=finding.id, vuln_class=finding.vuln_class,
                            endpoint=finding.endpoint, param=finding.param,
                            patched=True, patch_source="deterministic-template",
                            reexploit_blocked=True, functional_ok=True, validated=True,
                            validation_notes="v" * 300,
                        )
                        for finding in findings
                    ], True
                finally:
                    stop()

        monkeypatch.setattr(finder.remediate, "remediate_batch", fake_remediate_batch)

    job = jobs.Job(kind="sandbox_scan")
    asyncio.run(jobs.run_sandbox_scan_job(job, target_name, signals, target_runtime=target_runtime, remediate=remediate))
    assert signals.registered
    assert signals.unregistered
    return job, state


def test_sandbox_scan_worker_scans_a_disposable_gvisor_target_and_cleans_up(monkeypatch):
    job, state = run_fake_sandbox_scan(monkeypatch, fake_scan_proof())
    assert job.status == "completed"
    assert job.error is None
    assert state["destroyed"] and state["calls"][-1] == ("GET", "api.vultr.com", "/v2/instances/instance-123")
    assert [event["step"] for event in job.events] == ["sandbox_scan", "preflight", "provisioning", "bootstrap", "scanning", "teardown", "complete"]
    script = state["scripts"][0]
    assert "https://cerberus-target-src.ord1.vultrobjects.com/src/" in script
    assert '-p "$vpc_ip":8081:8081' in script and "-p 8081" not in script
    assert "docker run -d --runtime=runsc" in script and "netbird up" not in script
    assert 'ENTRYPOINT ["python", "app.py"]' in script
    # No Vultr key and no storage SECRET: the presigned GET (which carries the
    # access-key id in its SigV4 credential) is the only embedded credential.
    assert "account-key" not in script and "test-secret" not in script
    assert script.count("test-access") == 1 and "X-Amz-Credential=test-access%2F" in script
    assert state["scanned"] == [("http://10.52.0.3:8081", str(jobs.SCAN_TARGETS["seeded_flask"]), {})]
    storage = state["storage"][0]
    assert storage.objects == {} and len(storage.deleted) == 1
    bucket, key = storage.deleted[0]
    assert bucket == "cerberus-target-src" and re.fullmatch(r"src/[0-9a-f]{32}\.tgz", key)
    result = job.result
    assert result["instance_id"] == "instance-123" and result["destroyed"] is True and result["source_object_deleted"] is True
    assert result["vpc_ip"] == "10.52.0.3" and result["endpoint"] == "http://10.52.0.3:8081" and result["endpoint_health"] == "healthy"
    assert result["target"] == "seeded_flask" and result["triage_source"] == "offline-heuristic"
    assert result["confirmed_findings"] == 1 and result["findings"][0]["vuln_class"] == "sqli"
    assert result["coverage"]["classes_tested"] == ["sqli"] and result["coverage"]["steps_used"] == 2
    assert result["host"]["hostname"] == "vx1" and result["host"]["kvm_access"] is True
    for leaked in ("account-key", "test-secret", "test-access", "R" * 43):
        assert leaked not in str(result) + str(job.events) + str(job.error)


@pytest.mark.parametrize("proof", [fake_scan_proof(vpc_ip="10.52.0.4"), fake_scan_proof(target="degraded")])
def test_sandbox_scan_worker_rejects_a_proof_that_does_not_match_the_provider_attachment(monkeypatch, proof):
    job, state = run_fake_sandbox_scan(monkeypatch, proof)
    assert job.status == "failed" and job.result is None
    assert "ValueError; stage=none" in job.error
    assert "verify cleanup of instance instance-123" in job.error
    assert state["destroyed"] and state["scanned"] == []
    assert len(state["storage"][0].deleted) == 1
    assert "account-key" not in job.error and "test-secret" not in job.error


def test_sandbox_scan_worker_surfaces_a_bounded_bootstrap_failure_stage(monkeypatch):
    job, state = run_fake_sandbox_scan(monkeypatch, {"failure_stage": "target_health", "exit_code": 7})
    assert job.status == "failed" and job.result is None
    assert "RuntimeError; stage=target_health" in job.error
    assert state["destroyed"] and len(state["storage"][0].deleted) == 1


def test_sandbox_scan_worker_fails_before_provisioning_without_storage_config(monkeypatch):
    class Signals:
        def register(self):
            pytest.fail("No readiness token before storage preflight")

        def stage(self, token):
            return None

    for name, value in VPC_ENV.items():
        monkeypatch.setenv(name, value)
    for name in S3_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(jobs, "load_keys", lambda: pytest.fail("No API keys before storage preflight"))
    job = jobs.Job(kind="sandbox_scan")
    asyncio.run(jobs.run_sandbox_scan_job(job, "seeded_flask", Signals()))
    assert job.status == "failed" and job.result is None
    assert job.error == "Sandbox scan failed (ValueError; stage=none; message=Sandbox scan object storage is not configured) before an instance ID was confirmed"


def test_sandbox_scan_without_remediate_runs_one_vx1_and_reports_no_remediation(monkeypatch):
    job, state = run_fake_sandbox_scan(monkeypatch, fake_scan_proof())
    assert job.status == "completed"
    assert "remediation" not in job.result
    assert [call[0] for call in state["calls"]].count("POST") == 1
    assert [call[0] for call in state["calls"]].count("DELETE") == 1
    assert len(state["storage"]) == 1 and state["second_tokens"] == []
    assert "remediating" not in [event["step"] for event in job.events]


def test_sandbox_scan_remediate_reexploits_the_shared_patch_on_a_second_disposable_vx1(monkeypatch):
    job, state = run_fake_sandbox_scan(monkeypatch, fake_scan_proof(), remediate=True)
    assert job.status == "completed" and job.error is None
    assert [event["step"] for event in job.events] == [
        "sandbox_scan", "preflight", "provisioning", "bootstrap", "scanning", "teardown", "remediating", "complete",
    ]
    # Two full create/destroy cycles hit the provider, and the second destroy
    # is followed by its own independent 404 confirmation, not the scan's one.
    posts = [call for call in state["calls"] if call[0] == "POST"]
    deletes = [call for call in state["calls"] if call[0] == "DELETE"]
    assert len(posts) == 2 and len(deletes) == 2
    last_delete = max(index for index, call in enumerate(state["calls"]) if call[0] == "DELETE")
    tail = state["calls"][last_delete + 1:]
    assert len(tail) >= 2 and all(call == ("GET", "api.vultr.com", "/v2/instances/instance-123") for call in tail)
    # Each VX1 staged its own distinct object, and both objects are gone.
    assert len(state["storage"]) == 2
    first_keys = [key for _, key in state["storage"][0].deleted]
    second_keys = [key for _, key in state["storage"][1].deleted]
    assert len(first_keys) == 1 and len(second_keys) == 1 and first_keys[0] != second_keys[0]
    assert state["storage"][0].objects == {} and state["storage"][1].objects == {}
    # The second VX1's bootstrap fetched the SECOND presigned object.
    assert first_keys[0] in state["scripts"][0] and first_keys[0] not in state["scripts"][1]
    assert second_keys[0] in state["scripts"][1]
    # ...and its readiness proof was waited out on a FRESH registry, never the
    # scan-phase token.
    assert state["second_tokens"] == ["S" * 43] and state["second_unregistered"] == "S" * 43
    # The shared patched copy was hosted exactly once, on the second VX1.
    assert state["remediated"] == (["sqli-1"], str(jobs.SCAN_TARGETS["seeded_flask"]), 12.0)
    assert state["relauncher_base"] == "http://10.52.0.3:8081"
    remediation = job.result["remediation"]
    assert remediation["attempted"] == 1 and remediation["certified"] == 1
    assert remediation["re-exploit_sandboxed"] is True and remediation["shared_functional"] is True
    assert remediation["results"] == [{
        "finding_id": "sqli-1", "vuln_class": "sqli", "patched": True,
        "patch_source": "deterministic-template", "reexploit_blocked": True,
        "functional_ok": True, "validated": True, "validation_notes": "v" * 200,
    }]
    for leaked in ("account-key", "test-secret", "R" * 43, "S" * 43):
        assert leaked not in str(job.result)


def test_sandbox_scan_remediate_reuses_the_requested_target_runtime_for_the_reexploit(monkeypatch):
    job, state = run_fake_sandbox_scan(
        monkeypatch, fake_scan_proof(runtime="microsandbox"), target_name="snipstash",
        remediate=True, target_runtime="microsandbox",
    )
    assert job.status == "completed"
    assert job.result["target_runtime"] == "microsandbox"
    # Both VX1 bootstraps ran the KVM microVM target, not the docker/runsc one.
    for script in state["scripts"]:
        assert "msb create --name cerberus-target" in script and "--runtime=runsc" not in script
    assert job.result["remediation"]["re-exploit_sandboxed"] is True


def test_sandbox_scan_remediate_with_no_findings_never_boots_a_second_vx1(monkeypatch):
    report = FinderReport(
        target="http://10.52.0.3:8081", findings=[],
        coverage=Coverage(
            classes_tested=["sqli"], endpoints_tested=["/product"], candidates_seen=3,
            candidates_tested=1, not_reached=["ssrf"], steps_used=1, wall_clock_seconds=0.5,
        ),
        triage_source="offline-heuristic",
    )
    job, state = run_fake_sandbox_scan(monkeypatch, fake_scan_proof(), remediate=True, finder_report=report)
    assert job.status == "completed"
    assert job.result["confirmed_findings"] == 0 and "remediation" not in job.result
    assert "remediating" not in [event["step"] for event in job.events]
    assert [call[0] for call in state["calls"]].count("POST") == 1
    assert len(state["storage"]) == 1 and state["second_tokens"] == []


def test_sandbox_scan_remediate_second_vx1_failure_is_destroyed_and_never_certified(monkeypatch):
    job, state = run_fake_sandbox_scan(
        monkeypatch, fake_scan_proof(), remediate=True,
        second_proof={"failure_stage": "target_health", "exit_code": 7},
    )
    # The scan stands on its own; the re-exploit honestly reports nothing
    # certified off a patched app that never became healthy in its sandbox.
    assert job.status == "completed"
    remediation = job.result["remediation"]
    assert remediation["re-exploit_sandboxed"] is True
    assert remediation["certified"] == 0 and remediation["shared_functional"] is False
    assert remediation["results"][0]["reexploit_blocked"] is False
    assert remediation["results"][0]["validated"] is False and remediation["results"][0]["patched"] is False
    # The partial second VX1 was still destroyed, with its own 404 confirmation,
    # and the second staged object was deleted.
    deletes = [call for call in state["calls"] if call[0] == "DELETE"]
    assert len(deletes) == 2 and all(call[2] == "/v2/instances/instance-123" for call in deletes)
    last_delete = max(index for index, call in enumerate(state["calls"]) if call[0] == "DELETE")
    confirmations = [
        call for call in state["calls"][last_delete:]
        if call[0] == "GET" and call[2] == "/v2/instances/instance-123"
    ]
    assert confirmations and state["destroyed"] is True
    assert len(state["storage"]) == 2 and len(state["storage"][1].deleted) == 1
    assert state["storage"][1].objects == {}
    assert state["second_unregistered"] == "S" * 43


def test_sandbox_scan_remediate_worker_error_keeps_the_bounded_error_convention(monkeypatch):
    job, state = run_fake_sandbox_scan(monkeypatch, fake_scan_proof(), remediate=True, batch_raises=True)
    assert job.status == "failed" and job.result is None
    assert "Sandbox scan failed (RuntimeError; stage=none" in job.error
    assert "y" * 161 not in job.error  # the worker's 400-char message is truncated
    assert "account-key" not in job.error and "test-secret" not in job.error
    # The worker raised before the launcher ran: no second VX1, no second object.
    assert [call[0] for call in state["calls"]].count("POST") == 1
    assert len(state["storage"]) == 1


def test_deterministic_source_tarball_is_byte_stable_and_safely_shaped(tmp_path):
    payload_a = jobs.deterministic_source_tarball(jobs.SCAN_TARGETS["seeded_flask"])
    payload_b = jobs.deterministic_source_tarball(str(jobs.SCAN_TARGETS["seeded_flask"]))
    assert payload_a == payload_b and len(payload_a) < 1024 * 1024
    assert payload_a[4:8] == b"\x00\x00\x00\x00"  # gzip MTIME is pinned
    with tarfile.open(fileobj=io.BytesIO(payload_a), mode="r:gz") as archive:
        members = archive.getmembers()
    names = [member.name for member in members]
    assert names == sorted(names)
    assert {"app.py", "manifest.json", "requirements.txt", "docs/readme.txt", "app_secret.txt"} <= set(names)
    assert not any("__pycache__" in name or name.startswith("/") or ".." in name.split("/") for name in names)
    assert all(member.isfile() and member.mode == 0o644 and member.uid == 0 and member.gid == 0 and member.mtime == 0 and member.uname == "" for member in members)
    staged = tmp_path / "staged"
    staged.mkdir()
    with tarfile.open(fileobj=io.BytesIO(payload_a), mode="r:gz") as archive:
        archive.extractall(staged, filter="data")
    assert (staged / "app.py").read_bytes() == (jobs.SCAN_TARGETS["seeded_flask"] / "app.py").read_bytes()


def test_deterministic_source_tarball_rejects_links_and_unbounded_layouts(tmp_path):
    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / "app.py").write_text("x = 1\n")
    (linked / "escape.py").symlink_to(linked / "app.py")
    with pytest.raises(ValueError, match="links"):
        jobs.deterministic_source_tarball(linked)
    (linked / "escape.py").unlink()
    (linked / ("a" * 100 + ".py")).write_text("x = 2\n")
    with pytest.raises(ValueError, match="out of bounds"):
        jobs.deterministic_source_tarball(linked)
    huge = tmp_path / "huge"
    huge.mkdir()
    (huge / "app.py").write_text("x = 1\n")
    (huge / "blob.bin").write_bytes(b"\x00" * (jobs.TARGET_SOURCE_MAX_BYTES + 1))
    with pytest.raises(ValueError, match="too large"):
        jobs.deterministic_source_tarball(huge)
    with pytest.raises(ValueError, match="directory"):
        jobs.deterministic_source_tarball(tmp_path / "missing")


def test_registry_shares_one_disposable_vx1_between_smoke_and_scan():
    registry = jobs.JobRegistry()
    with pytest.raises(ValueError):
        registry.create("sandbox_scan", signals=object(), target="unknown")
    with pytest.raises(ValueError):
        registry.create("sandbox_scan", target="seeded_flask")
    registry.jobs["smoke"] = jobs.Job(kind="sandbox_smoke", status="running")
    assert registry.create("sandbox_scan", signals=object(), target="seeded_flask") is None
    assert registry.arm_sandbox(ttl_seconds=120) is None
    registry.jobs["scan"] = jobs.Job(kind="sandbox_scan", status="running")
    assert registry.create("sandbox_smoke", "A" * 36, object()) is None
    registry.jobs["smoke"].status = "completed"
    assert registry.arm_sandbox(ttl_seconds=120) is None  # the scan still holds the one VX1


def test_sandbox_scan_route_arms_and_consumes_one_token_like_vpc_smoke(auth, monkeypatch):
    seen = []

    async def fake_scan(job, target, signals, target_runtime="gvisor", remediate=False):
        seen.append((target, signals, remediate))
        job.result = {"destroyed": True, "vpc_ip": "10.52.0.3"}
        await job.publish("completed")

    monkeypatch.delenv("CERBERUS_ENABLE_SANDBOX_JOBS", raising=False)
    for name, value in VPC_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(jobs, "run_sandbox_scan_job", fake_scan)
    with TestClient(app) as client:
        body = {"type": "sandbox_scan", "approve_vm": True, "target": "seeded_flask"}
        assert client.post("/jobs", headers=auth, json=body).status_code == 503
        armed = client.post("/jobs/arm-sandbox", headers=auth, json={"approve_vm": True})
        assert armed.status_code == 201
        token = armed.json()["arm_token"]
        # Smoke-only options never apply to scans and must not consume the arm.
        assert client.post("/jobs", headers=auth, json={**body, "arm_token": token, "diagnostic_upload": {"url": "https://x.ord1.vultrobjects.com/", "fields": {}}}).status_code == 400
        assert client.post("/jobs", headers=auth, json={**body, "arm_token": token, "netbird_setup_key": "A" * 36}).status_code == 400
        assert client.post("/jobs", headers=auth, json={**body, "arm_token": token, "target": "unknown"}).status_code == 400
        assert client.post("/jobs", headers=auth, json={"type": "sandbox_scan", "target": "seeded_flask", "arm_token": token}).status_code == 400
        assert client.post("/jobs", headers=auth, json={**body, "arm_token": "wrong"}).status_code == 403
        started = client.post("/jobs", headers=auth, json={**body, "arm_token": token})
        assert started.status_code == 202
        job_id = started.json()["id"]
        assert wait_for_terminal(client, job_id, auth)["status"] == "completed"
        assert client.post("/jobs", headers=auth, json={**body, "arm_token": token}).status_code == 403
        result = client.get(f"/jobs/{job_id}/result", headers=auth)
        with client.websocket_connect(f"/jobs/{job_id}/events") as websocket:
            websocket.send_json({"token": CONTROL_TOKEN})
            events = [websocket.receive_json() for _ in range(2)]
    assert len(seen) == 1
    assert seen[0][0] == "seeded_flask"
    from main import ready_signals
    assert seen[0][1] is ready_signals
    assert seen[0][2] is False
    assert result.status_code == 200 and result.json()["destroyed"] is True
    assert [event["status"] for event in events] == ["queued", "completed"]
    assert token not in result.text + str(events)


def test_enabled_sandbox_scan_needs_no_arm_but_still_requires_approval_and_vpc_config(auth, monkeypatch):
    seen = []

    async def fake_scan(job, target, signals, target_runtime="gvisor", remediate=False):
        seen.append(target)
        job.result = {"destroyed": True}
        await job.publish("completed")

    monkeypatch.setenv("CERBERUS_ENABLE_SANDBOX_JOBS", "true")
    monkeypatch.setattr(jobs, "run_sandbox_scan_job", fake_scan)
    with TestClient(app) as client:
        body = {"type": "sandbox_scan", "approve_vm": True, "target": "snipstash"}
        for name in VPC_ENV:
            monkeypatch.delenv(name, raising=False)
        assert client.post("/jobs", headers=auth, json=body).status_code == 503
        for name, value in VPC_ENV.items():
            monkeypatch.setenv(name, value)
        assert client.post("/jobs", headers=auth, json={**body, "arm_token": "unused"}).status_code == 400
        assert client.post("/jobs", headers=auth, json={"type": "sandbox_scan", "target": "snipstash"}).status_code == 400
        assert client.post("/jobs", headers=auth, json={"type": "sandbox_scan", "approve_vm": True}).status_code == 400
        started = client.post("/jobs", headers=auth, json=body)
        assert started.status_code == 202
        assert wait_for_terminal(client, started.json()["id"], auth)["type"] == "sandbox_scan"
    assert seen == ["snipstash"]


def test_remediate_is_rejected_for_every_job_type_except_sandbox_scan(auth, monkeypatch):
    monkeypatch.setenv("CERBERUS_ENABLE_LOCAL_SCAN_JOBS", "true")
    with TestClient(app) as client:
        assert client.post("/jobs", headers=auth, json={"type": "connectivity", "remediate": True}).status_code == 400
        assert client.post("/jobs", headers=auth, json={"type": "scan", "target": "seeded_flask", "remediate": True}).status_code == 400
        smoke = {"type": "sandbox_smoke", "approve_vm": True, "netbird_setup_key": "A" * 36, "remediate": True}
        assert client.post("/jobs", headers=auth, json=smoke).status_code == 400
        # The flag is a StrictBool: truthy strings do not silently coerce.
        assert client.post("/jobs", headers=auth, json={"type": "connectivity", "remediate": "true"}).status_code == 422


def test_sandbox_scan_remediate_flag_passes_through_to_the_worker(auth, monkeypatch):
    seen = []

    async def fake_scan(job, target, signals, target_runtime="gvisor", remediate=False):
        seen.append(remediate)
        job.result = {"destroyed": True}
        await job.publish("completed")

    monkeypatch.setenv("CERBERUS_ENABLE_SANDBOX_JOBS", "true")
    for name, value in VPC_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(jobs, "run_sandbox_scan_job", fake_scan)
    with TestClient(app) as client:
        base = {"type": "sandbox_scan", "approve_vm": True, "target": "seeded_flask"}
        started = client.post("/jobs", headers=auth, json={**base, "remediate": True})
        assert started.status_code == 202
        assert wait_for_terminal(client, started.json()["id"], auth)["status"] == "completed"
        defaulted = client.post("/jobs", headers=auth, json=base)
        assert defaulted.status_code == 202
        assert wait_for_terminal(client, defaulted.json()["id"], auth)["status"] == "completed"
    assert seen == [True, False]


def test_registry_rejects_remediate_for_non_sandbox_scan_kinds():
    registry = jobs.JobRegistry()
    with pytest.raises(ValueError, match="Remediation"):
        registry.create("connectivity", remediate=True)
    with pytest.raises(ValueError, match="Remediation"):
        registry.create("sandbox_smoke", "A" * 36, object(), remediate=True)
    with pytest.raises(ValueError, match="Remediation"):
        registry.create("scan", target="seeded_flask", remediate=True)

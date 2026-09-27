import asyncio
import base64
import json
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import jobs
from main import app, vpc_callback_app

CONTROL_TOKEN = "test-" + "x" * 40


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

    async def fake_smoke(job, key, signals, vpc_mode=False, diagnostic_hold_seconds=None):
        seen.append((key, vpc_mode, diagnostic_hold_seconds))
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
    assert seen == [(None, True, hold_seconds)]
    assert arm_token not in str(result.json()) + str(events)


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
            script = base64.b64decode(json.loads(request.content)["user_data"]).decode()
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
        assert "timed out after network_create" in job.error
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
            script = base64.b64decode(payload["user_data"]).decode()
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

import asyncio
import threading
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import jobs
from main import app

CONTROL_TOKEN = "test-" + "x" * 40


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


def test_job_type_and_lookup_are_bounded(auth):
    with TestClient(app) as client:
        assert client.post("/jobs", json={"type": "shell"}, headers=auth).status_code == 422
        assert client.get("/jobs/nonexistent", headers=auth).status_code == 404
        assert client.get("/jobs/nonexistent/result", headers=auth).status_code == 404


def test_registry_refuses_to_start_when_active_jobs_fill_capacity():
    registry = jobs.JobRegistry(max_jobs=1)
    registry.jobs["running"] = jobs.Job(id="running", status="running")
    assert registry.create() is None


def test_websocket_requires_first_message_not_query_token(auth):
    with TestClient(app) as client:
        with client.websocket_connect(f"/jobs/nonexistent/events?token={CONTROL_TOKEN}") as websocket:
            websocket.send_json({"token": "wrong"})
            with pytest.raises(WebSocketDisconnect) as error:
                websocket.receive_json()
        assert error.value.code == 1008

import pytest
from fastapi.testclient import TestClient

import web_proxy

P = "demo-pass-" + "x" * 20


@pytest.fixture
def client_setup(monkeypatch):
    monkeypatch.setattr(web_proxy, "DEMO_PASSWORD", P)
    monkeypatch.setattr(web_proxy, "CONTROL_TOKEN", "C" * 40)
    monkeypatch.setattr(web_proxy, "WEB_SECRET", "W" * 40)
    monkeypatch.setattr(web_proxy, "SECURE_COOKIE", False)
    web_proxy._sessions.clear()
    web_proxy._attempts.clear()
    web_proxy._active_run = None
    return TestClient(web_proxy.app)


def _login(client):
    response = client.post("/api/login", json={"password": P})
    assert response.status_code == 204
    return client


def test_login_and_access_gate(client_setup):
    client = client_setup
    assert client.post("/api/runs", json={"target": "seeded_flask"}).status_code == 401
    assert client.post("/api/login", json={"password": "wrong"}).status_code == 401
    _login(client)
    assert client.get("/api/me").json()["authenticated"] is True
    assert client.post("/api/logout").status_code == 204
    assert client.get("/api/me").json()["authenticated"] is False


def test_login_rate_limit_is_per_ip(client_setup):
    client = client_setup
    for _ in range(5):
        client.post("/api/login", json={"password": "wrong"})
    assert client.post("/api/login", json={"password": P}).status_code == 429


def test_run_payload_validation(client_setup):
    client = client_setup
    _login(client)
    for body, expect in (
        ({}, "pick one"),
        ({"target": "seeded_flask", "repo": "https://github.com/a/b"}, "pick one"),
        ({"repo": "http://github.com/a/b"}, "https"),
        ({"repo": "https://github.com/a/b", "target_runtime": "sidekick"}, "runtime"),
        ({"repo": "https://github.com/a/b", "remediate": "yes"}, "remediate"),
    ):
        response = client.post("/api/runs", json=body)
        assert response.status_code == 400, (body, response.text)
        assert expect in response.text


def test_run_arms_then_starts_server_side_and_proxies_result(client_setup, monkeypatch):
    calls = []

    class FakeControl:
        async def request(self, method, url, headers=None, **kwargs):
            import httpx as _h

            calls.append((method, url, kwargs.get("json")))
            if url.endswith("/jobs/arm-sandbox"):
                return _h.Response(201, json={"arm_token": "A" * 43}, request=_h.Request(method, url))
            if "/result" in url:
                return _h.Response(200, json={"destroyed": True, "confirmed_findings": 5}, request=_h.Request(method, url))
            if "/jobs/" in url:
                return _h.Response(200, json={"status": "running", "step": "bootstrap"}, request=_h.Request(method, url))
            return _h.Response(202, json={"id": "a" * 32}, request=_h.Request(method, url))

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    monkeypatch.setattr(web_proxy.httpx, "AsyncClient", lambda **kw: FakeControl())
    client = client_setup
    _login(client)
    started = client.post("/api/runs", json={"repo": "https://github.com/o/r", "subpath": "a/b", "target_runtime": "microsandbox", "remediate": True})
    assert started.status_code == 200
    assert started.json()["job_id"] == "a" * 32
    job_call = [c for c in calls if c[0] == "POST" and not c[1].endswith("arm-sandbox")][-1][2]
    assert job_call["approve_vm"] is True and job_call["arm_token"] == "A" * 43
    assert job_call["target_runtime"] == "microsandbox" and job_call["repo"] == "https://github.com/o/r" and job_call["remediate"] is True
    assert client.get("/api/runs/" + "a" * 32).json()["status"] == "running"
    assert client.get("/api/runs/" + "a" * 32 + "/result").json()["confirmed_findings"] == 5

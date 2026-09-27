"""Public demo web tier: password gate + server-side control-plane proxy.

Runs on a separate persistent VX1. It holds the control bearer in its own env so
visitors only ever see a session cookie. Every run request injects `approve_vm` and
a one-use arm token server-side; visitors supply only repo/target/runtime/remediate.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response

app = FastAPI(title="Cerberus demo web tier", docs_url=None, redoc_url=None, openapi_url=None)
load_dotenv(Path(__file__).with_name("web.env"))
load_dotenv(Path(__file__).with_name(".env"))

CONTROL_URL = os.getenv("CERBERUS_CONTROL_URL", "http://100.124.55.15:8000")
SECURE_COOKIE = os.getenv("CERBERUS_WEB_SECURE_COOKIES", "true") != "false"
CONTROL_TOKEN = os.getenv("CERBERUS_CONTROL_TOKEN", "")
DEMO_PASSWORD = os.getenv("CERBERUS_DEMO_PASSWORD", "")
WEB_SECRET = os.getenv("CERBERUS_WEB_SECRET", "")
_sessions: dict[str, float] = {}
_attempts: dict[str, list[float]] = {}
_active_run = None
_COOKIE = "cerberus_demo"


def _sign(value):
    return base64.urlsafe_b64encode(hmac.new(WEB_SECRET.encode(), value.encode(), hashlib.sha256).digest()).decode()


def _session_ok(request):
    raw = request.cookies.get(_COOKIE, "")
    sid, _, sig = raw.rpartition(".")
    return (
        bool(sid and sig)
        and hmac.compare_digest(sig, _sign(sid))
        and _sessions.get(sid, 0) > time.time()
    )


def _gate(request):
    if not DEMO_PASSWORD or not WEB_SECRET or not CONTROL_TOKEN:
        return Response(status_code=503, content="web tier is not configured")
    if not _session_ok(request):
        return Response(status_code=401, content="auth required")
    return None


@app.post("/api/login")
async def login(request: Request):
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    password = body.get("password", "")
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    attempts = [t for t in _attempts.get(ip, []) if now - t < 60]
    _attempts[ip] = attempts
    if len(attempts) >= 5:
        return Response(status_code=429, content="too many attempts")
    attempts.append(now)
    if not DEMO_PASSWORD or not secrets.compare_digest(password, DEMO_PASSWORD):
        return Response(status_code=401, content="bad password")
    sid = secrets.token_urlsafe(32)
    _sessions[sid] = now + 3600 * 6
    response = Response(status_code=204)
    response.set_cookie(
        _COOKIE, f"{sid}.{_sign(sid)}", max_age=3600 * 6, httponly=True, samesite="strict", secure=SECURE_COOKIE
    )
    return response


@app.post("/api/logout")
async def logout(request: Request):
    sid = request.cookies.get(_COOKIE, "").split(".")[0]
    _sessions.pop(sid, None)
    response = Response(status_code=204)
    response.delete_cookie(_COOKIE)
    return response


@app.get("/api/me")
async def me(request: Request):
    return {"authenticated": _session_ok(request), "runtimes": ["gvisor", "microsandbox"]}


def _clean_run(body):
    if not isinstance(body, dict):
        raise ValueError("bad body")
    target, repo = body.get("target"), body.get("repo")
    if (target is None) == (repo is None):
        raise ValueError("pick one of target or repo")
    if target is not None and not isinstance(target, str):
        raise ValueError("bad target")
    if repo is not None:
        if not isinstance(repo, str) or not repo.startswith("https://") or not re.fullmatch(r"https://[\w.-]+/[A-Za-z0-9._/-]+", repo):
            raise ValueError("repo must be an https URL")
    runtime = body.get("target_runtime", "gvisor")
    if runtime not in ("gvisor", "microsandbox"):
        raise ValueError("bad runtime")
    remediate = body.get("remediate", False)
    if type(remediate) is not bool:
        raise ValueError("bad remediate flag")
    out = {"target_runtime": runtime, "remediate": remediate}
    for name in ("target", "repo", "subpath", "entrypoint"):
        value = body.get(name)
        if value is None:
            continue
        if not isinstance(value, str) or len(value) > 200 or "\x00" in value:
            raise ValueError(f"bad {name}")
        out[name] = value
    return out


async def _control(method, path, **kwargs):
    async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
        response = await client.request(
            method, CONTROL_URL + path,
            headers={"Authorization": f"Bearer {CONTROL_TOKEN}"}, **kwargs,
        )
        return response


@app.post("/api/runs")
async def start_run(request: Request):
    gate = _gate(request)
    if gate is not None:
        return gate
    global _active_run
    try:
        payload = _clean_run(await request.json())
    except ValueError as error:
        return Response(status_code=400, content=str(error))
    async with _active_run_lock:
        if _active_run is not None:
            probe = await _control("GET", f"/jobs/{_active_run}")
            if probe.status_code == 200 and probe.json().get("status") not in ("completed", "failed"):
                return Response(status_code=429, content="a run is already in progress")
            _active_run = None
    arm = await _control("POST", "/jobs/arm-sandbox", json={"approve_vm": True, "ttl_seconds": 300, "diagnostic_hold_seconds": 0})
    if arm.status_code != 201:
        return Response(status_code=502, content=f"arm failed ({arm.status_code})")
    body = {"type": "sandbox_scan", "approve_vm": True, "arm_token": arm.json()["arm_token"], **payload}
    started = await _control("POST", "/jobs", json=body)
    if started.status_code != 202:
        return Response(status_code=502, content=f"job rejected ({started.status_code})")
    job_id = started.json()["id"]
    async with _active_run_lock:
        _active_run = job_id
    return {"job_id": job_id, "arm_note": "armed with a one-use token server-side; your demo password only gates the page"}


@app.get("/api/runs/{job_id}")
async def run_status(job_id: str, request: Request):
    gate = _gate(request)
    if gate is not None:
        return gate
    if not re.fullmatch(r"[0-9a-f]{32}", job_id):
        return Response(status_code=400, content="bad job id")
    response = await _control("GET", f"/jobs/{job_id}")
    if response.status_code != 200:
        return Response(status_code=response.status_code, content="not found")
    data = response.json()
    return {"status": data.get("status"), "step": data.get("step"), "error": data.get("error")}


@app.get("/api/runs/{job_id}/result")
async def run_result(job_id: str, request: Request):
    gate = _gate(request)
    if gate is not None:
        return gate
    if not re.fullmatch(r"[0-9a-f]{32}", job_id):
        return Response(status_code=400, content="bad job id")
    response = await _control("GET", f"/jobs/{job_id}/result")
    return Response(status_code=response.status_code, content=response.content, media_type="application/json")


@app.get("/")
async def home():
    return Response((Path(__file__).parent / "site" / "live.html").read_text(), media_type="text/html")


import asyncio as _asyncio  # noqa: E402

_active_run_lock = _asyncio.Lock()

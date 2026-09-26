import asyncio
import ipaddress
import re
import secrets
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel

from instance_lifecycle import ReadySignals
from jobs import JobRegistry, control_token

app = FastAPI(title="Cerberus")
ready_signals = ReadySignals()
job_registry = JobRegistry()


class JobRequest(BaseModel):
    type: Literal["connectivity"]


def require_control(authorization):
    token = control_token()
    if token is None:
        raise HTTPException(status_code=503, detail="Control API is not configured")
    if not authorization or not authorization.startswith("Bearer ") or not secrets.compare_digest(authorization[7:], token):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home():
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Cerberus</title>'
        '<meta name="viewport" content="width=device-width, initial-scale=1"></head><body>'
        '<main><img src="/logo.jpg" alt="Cerberus logo" width="240" height="240">'
        '<h1>Cerberus</h1><p>Isolated repository checks.</p><a href="/docs">API docs</a></main>'
        '</body></html>'
    )


@app.get("/logo.jpg", response_class=FileResponse, include_in_schema=False)
def logo():
    return FileResponse(Path(__file__).with_name("cerberus-logo.jpg"), media_type="image/jpeg")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/internal/ready")
async def instance_ready(request: Request, authorization: str | None = Header(default=None)):
    token = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
    if not ready_signals.has(token):
        raise HTTPException(status_code=404)
    if len(await request.body()) > 2048:
        raise HTTPException(status_code=413)
    try:
        proof = await request.json()
    except ValueError:
        raise HTTPException(status_code=400)
    if (
        not isinstance(proof, dict)
        or any(not isinstance(proof.get(field), str) or not proof[field] or len(proof[field]) > 256 or not proof[field].isprintable() for field in ("hostname", "uname", "sandbox_hostname", "sandbox_uname"))
        or proof.get("cpu_virt") not in ("vmx", "svm")
        or proof.get("kvm_device") is not True
        or proof.get("kvm_access") is not True
        or proof.get("runtime") != "runsc"
        or type(proof.get("exit_code")) is not int
        or proof["exit_code"] != 0
    ):
        raise HTTPException(status_code=400)
    if "opensandbox" in proof:
        extra = proof["opensandbox"]
        if (
            not isinstance(extra, dict)
            or any(not isinstance(extra.get(field), str) or not extra[field] or len(extra[field]) > 256 or not extra[field].isprintable() for field in ("hostname", "uname"))
            or type(extra.get("exit_code")) is not int
            or extra["exit_code"] != 0
        ):
            raise HTTPException(status_code=400)
    if "netbird_ip" in proof:
        try:
            address = ipaddress.ip_address(proof["netbird_ip"])
        except (ValueError, TypeError):
            raise HTTPException(status_code=400)
        if address not in ipaddress.ip_network("100.64.0.0/10"):
            raise HTTPException(status_code=400)
    if not ready_signals.signal(token, proof):
        raise HTTPException(status_code=404)
    return Response(status_code=204)


@app.post("/internal/control-ready")
async def control_ready(request: Request, authorization: str | None = Header(default=None)):
    token = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
    if not ready_signals.has(token):
        raise HTTPException(status_code=404)
    if len(await request.body()) > 1024:
        raise HTTPException(status_code=413)
    try:
        proof = await request.json()
        address = ipaddress.ip_address(proof["netbird_ip"])
    except (ValueError, TypeError, KeyError):
        raise HTTPException(status_code=400)
    if (
        not isinstance(proof, dict)
        or address not in ipaddress.ip_network("100.64.0.0/10")
        or not isinstance(proof.get("repo_commit"), str)
        or not re.fullmatch(r"[0-9a-f]{40}", proof["repo_commit"])
        or proof.get("bootstrapped") is not True
    ):
        raise HTTPException(status_code=400)
    if not ready_signals.signal(token, proof):
        raise HTTPException(status_code=404)
    return Response(status_code=204)


callback_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
callback_app.add_api_route("/internal/ready", instance_ready, methods=["POST"])
callback_app.add_api_route("/internal/control-ready", control_ready, methods=["POST"])


@app.post("/jobs", status_code=202)
async def start_job(request: JobRequest, authorization: str | None = Header(default=None)):
    require_control(authorization)
    job = job_registry.create()
    if job is None:
        raise HTTPException(status_code=429, detail="Too many active jobs")
    return {"id": job.id, "type": request.type, "status": "queued"}


@app.get("/jobs/{job_id}")
async def job_status(job_id: str, authorization: str | None = Header(default=None)):
    require_control(authorization)
    job = job_registry.jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"id": job.id, "type": "connectivity", "status": job.status}


@app.get("/jobs/{job_id}/result")
async def job_result(job_id: str, authorization: str | None = Header(default=None)):
    require_control(authorization)
    job = job_registry.jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status == "failed":
        return JSONResponse({"error": job.error}, status_code=502)
    if job.status != "completed":
        return JSONResponse({"status": job.status}, status_code=202)
    return job.result


@app.websocket("/jobs/{job_id}/events")
async def job_events(websocket: WebSocket, job_id: str):
    token = control_token()
    if token is None:
        await websocket.close(code=1013)
        return
    await websocket.accept()
    try:
        message = await asyncio.wait_for(websocket.receive_json(), timeout=5)
    except WebSocketDisconnect:
        return
    except (ValueError, asyncio.TimeoutError):
        await websocket.close(code=1008)
        return
    if not isinstance(message, dict) or not isinstance(message.get("token"), str) or not secrets.compare_digest(message["token"], token):
        await websocket.close(code=1008)
        return
    job = job_registry.jobs.get(job_id)
    if job is None:
        await websocket.close(code=1008)
        return
    try:
        async for event in job.stream():
            await websocket.send_json(event)
    except WebSocketDisconnect:
        return

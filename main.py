import asyncio
import ipaddress
import os
import re
import secrets
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, SecretStr, StrictBool, StrictInt

from instance_lifecycle import ReadySignals
from jobs import JobRegistry, SCAN_TARGETS, control_token

app = FastAPI(title="Cerberus")
ready_signals = ReadySignals()
job_registry = JobRegistry()
BOOTSTRAP_STAGES = frozenset({
    "bootstrap_started", "docker_install", "gvisor_install", "runtime_smoke", "opensandbox_dependencies",
    "network_create", "opensandbox_config", "opensandbox_server", "isolation_probe",
    "bridge_inspect", "firewall_ipv4", "firewall_ipv6", "sandbox_create",
    "docker_isolation", "smoke_command", "external_probe", "dns_probe", "host_probe",
    "ready_callback",
})


class JobRequest(BaseModel):
    type: Literal["connectivity", "sandbox_smoke", "scan"]
    approve_vm: StrictBool = False
    netbird_setup_key: SecretStr | None = None
    arm_token: SecretStr | None = None
    target: str | None = None


class SandboxArmRequest(BaseModel):
    approve_vm: StrictBool = False
    ttl_seconds: StrictInt = 120
    diagnostic_hold_seconds: StrictInt = 0


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
    if "vpc_ip" in proof:
        try:
            address = ipaddress.ip_address(proof["vpc_ip"])
        except (ValueError, TypeError):
            raise HTTPException(status_code=400)
        if not isinstance(address, ipaddress.IPv4Address) or not any(address in ipaddress.ip_network(block) for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
            raise HTTPException(status_code=400)
    if not ready_signals.signal(token, proof):
        raise HTTPException(status_code=404)
    return Response(status_code=204)


@app.post("/internal/stage")
async def instance_stage(request: Request, authorization: str | None = Header(default=None)):
    token = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
    if not ready_signals.has(token):
        raise HTTPException(status_code=404)
    if len(await request.body()) > 256:
        raise HTTPException(status_code=413)
    try:
        report = await request.json()
    except ValueError:
        raise HTTPException(status_code=400)
    if not isinstance(report, dict) or set(report) != {"stage"} or not isinstance(report["stage"], str) or report["stage"] not in BOOTSTRAP_STAGES:
        raise HTTPException(status_code=400)
    if not ready_signals.update_stage(token, report["stage"]):
        raise HTTPException(status_code=404)
    return Response(status_code=204)


@app.post("/internal/failed")
async def instance_failed(request: Request, authorization: str | None = Header(default=None)):
    token = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
    if not ready_signals.has(token):
        raise HTTPException(status_code=404)
    if len(await request.body()) > 512:
        raise HTTPException(status_code=413)
    try:
        report = await request.json()
    except ValueError:
        raise HTTPException(status_code=400)
    if (
        not isinstance(report, dict) or set(report) != {"stage", "exit_code"}
        or not isinstance(report["stage"], str)
        or report["stage"] not in BOOTSTRAP_STAGES
        or type(report["exit_code"]) is not int or not 1 <= report["exit_code"] <= 255
    ):
        raise HTTPException(status_code=400)
    if not ready_signals.signal(token, {"failure_stage": report["stage"], "exit_code": report["exit_code"]}):
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

vpc_callback_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
vpc_callback_app.add_api_route("/internal/ready", instance_ready, methods=["POST"])
vpc_callback_app.add_api_route("/internal/stage", instance_stage, methods=["POST"])
vpc_callback_app.add_api_route("/internal/failed", instance_failed, methods=["POST"])


async def control_server_app(scope, receive, send):
    if scope["type"] == "lifespan":
        await app(scope, receive, send)
        return
    server = scope.get("server")
    port = server[1] if server and len(server) >= 2 else None
    target = app if port == 8000 else vpc_callback_app if port == 8001 else None
    if port in (8000, 8001):
        try:
            client_ip = ipaddress.ip_address(scope["client"][0])
            allowed = ipaddress.ip_network("100.64.0.0/10") if port == 8000 else ipaddress.ip_network(os.environ["CERBERUS_VPC_SUBNET"])
            if client_ip not in allowed:
                target = None
        except (KeyError, TypeError, ValueError):
            target = None
    if target is not None:
        await target(scope, receive, send)
    elif scope["type"] == "websocket":
        await send({"type": "websocket.close", "code": 1008})
    else:
        await Response(status_code=404)(scope, receive, send)


@app.post("/jobs/arm-sandbox", status_code=201)
async def arm_sandbox_job(request: SandboxArmRequest, authorization: str | None = Header(default=None)):
    require_control(authorization)
    if request.approve_vm is not True or not 1 <= request.ttl_seconds <= 300 or not 0 <= request.diagnostic_hold_seconds <= 300:
        raise HTTPException(status_code=400, detail="Explicit approval and bounded arm/hold durations required")
    if os.getenv("CERBERUS_ENABLE_SANDBOX_JOBS") == "true":
        raise HTTPException(status_code=400, detail="Sandbox jobs are already enabled")
    if not all(os.getenv(name) for name in ("CERBERUS_VPC_ID", "CERBERUS_CONTROL_INSTANCE_ID", "CERBERUS_CONTROL_VPC_IP", "CERBERUS_VPC_SUBNET")):
        raise HTTPException(status_code=503, detail="VPC sandbox jobs are not configured")
    token = job_registry.arm_sandbox(request.ttl_seconds, request.diagnostic_hold_seconds)
    if token is None:
        raise HTTPException(status_code=429, detail="Sandbox job already armed or active")
    return {"arm_token": token, "expires_in": request.ttl_seconds, "diagnostic_hold_seconds": request.diagnostic_hold_seconds}


@app.post("/jobs", status_code=202)
async def start_job(request: JobRequest, authorization: str | None = Header(default=None)):
    require_control(authorization)
    if request.type == "sandbox_smoke":
        if request.target is not None:
            raise HTTPException(status_code=400, detail="Sandbox jobs do not accept a target")
        enabled = os.getenv("CERBERUS_ENABLE_SANDBOX_JOBS") == "true"
        if not enabled and request.arm_token is None:
            raise HTTPException(status_code=503, detail="Sandbox jobs are disabled")
        if enabled and request.arm_token is not None:
            raise HTTPException(status_code=400, detail="Sandbox arm is unnecessary while jobs are enabled")
        if request.approve_vm is not True:
            raise HTTPException(status_code=400, detail="Explicit VM approval required")
        if request.netbird_setup_key is not None:
            if not enabled:
                raise HTTPException(status_code=400, detail="Sandbox arm applies only to the VPC path")
            key = request.netbird_setup_key.get_secret_value()
            if not re.fullmatch(r"[A-Za-z0-9-]{32,128}", key):
                raise HTTPException(status_code=400, detail="One-off NetBird key format is invalid")
            job = job_registry.create(request.type, key, ready_signals)
        else:
            if not all(os.getenv(name) for name in ("CERBERUS_VPC_ID", "CERBERUS_CONTROL_INSTANCE_ID", "CERBERUS_CONTROL_VPC_IP", "CERBERUS_VPC_SUBNET")):
                raise HTTPException(status_code=503, detail="VPC sandbox jobs are not configured")
            if enabled:
                job = job_registry.create(request.type, None, ready_signals, vpc_mode=True)
            else:
                hold = job_registry.consume_sandbox_arm(request.arm_token.get_secret_value())
                if hold is None:
                    raise HTTPException(status_code=403, detail="Sandbox arm is invalid or expired")
                job = job_registry.create(request.type, None, ready_signals, vpc_mode=True, diagnostic_hold_seconds=hold)
    elif request.type == "scan":
        if request.approve_vm or request.netbird_setup_key is not None or request.arm_token is not None:
            raise HTTPException(status_code=400, detail="Scan jobs do not accept sandbox credentials")
        if request.target not in SCAN_TARGETS:
            raise HTTPException(status_code=400, detail="Unknown scan target")
        if os.getenv("CERBERUS_ENABLE_LOCAL_SCAN_JOBS") != "true":
            raise HTTPException(status_code=503, detail="Local scan jobs are disabled")
        job = job_registry.create(request.type, target=request.target)
    else:
        if request.approve_vm or request.netbird_setup_key is not None or request.arm_token is not None:
            raise HTTPException(status_code=400, detail="Connectivity jobs do not accept sandbox credentials")
        if request.target is not None:
            raise HTTPException(status_code=400, detail="Connectivity jobs do not accept a target")
        job = job_registry.create(request.type)
    if job is None:
        raise HTTPException(status_code=429, detail="Too many active jobs")
    return {"id": job.id, "type": request.type, "status": "queued"}


@app.get("/jobs/{job_id}")
async def job_status(job_id: str, authorization: str | None = Header(default=None)):
    require_control(authorization)
    job = job_registry.jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"id": job.id, "type": job.kind, "status": job.status}


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

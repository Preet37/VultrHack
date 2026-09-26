import ipaddress
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse

from instance_lifecycle import ReadySignals

app = FastAPI(title="Cerberus")
ready_signals = ReadySignals()


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


callback_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
callback_app.add_api_route("/internal/ready", instance_ready, methods=["POST"])

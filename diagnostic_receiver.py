import asyncio
import ipaddress
import json
import re
import secrets
import threading
from types import SimpleNamespace

from fastapi import FastAPI, Header, HTTPException, Request, Response

from instance_lifecycle import validated_vpc_subnet


def build_diagnostic_app(token, vpc_subnet):
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
        raise ValueError("A strong per-run diagnostic token is required")
    subnet = validated_vpc_subnet(vpc_subnet)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    state = SimpleNamespace(result=None, event=threading.Event())
    lock = asyncio.Lock()

    @app.post("/internal/nic")
    async def receive_nic(request: Request, authorization: str | None = Header(default=None)):
        if not authorization or not authorization.startswith("Bearer ") or not secrets.compare_digest(authorization[7:], token):
            raise HTTPException(status_code=404)
        async with lock:
            if state.result is not None:
                raise HTTPException(status_code=404)
            body = b""
            async for chunk in request.stream():
                if len(body) + len(chunk) > 256:
                    raise HTTPException(status_code=413)
                body += chunk
            try:
                report = json.loads(body)
            except (ValueError, UnicodeError):
                raise HTTPException(status_code=400)
            if not isinstance(report, dict) or set(report) != {"probe", "vpc_ip"} or report["probe"] not in ("ok", "unavailable"):
                raise HTTPException(status_code=400)
            address = report["vpc_ip"]
            if address is not None:
                if not isinstance(address, str):
                    raise HTTPException(status_code=400)
                try:
                    address = ipaddress.IPv4Address(address)
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400)
                if address not in subnet or address in (subnet.network_address, subnet.broadcast_address) or report["probe"] != "ok":
                    raise HTTPException(status_code=400)
                report["vpc_ip"] = str(address)
            state.result = report
            state.event.set()
            return Response(status_code=204)

    return app, state

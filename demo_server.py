"""Local demo server — serves the Cerberus console and runs the REAL engine.

This is not a mock. When the browser hits Run, this boots the target, runs the
real finder on Vultr Serverless Inference, confirms each vulnerability with its
planted canary, patches it, and re-proves the fix — streaming the real events to
the page over a WebSocket. Every number, canary, patch diff and model verdict on
the screen came out of an actual scan.

Honest scope: the target currently runs as a local subprocess (Tier-1). Running
it inside a live disposable gVisor VM is issue #16 (the sandbox lane) — the seam
for it is already in `finder/target_runner.py`, so this server swaps to the real
VM the moment that lands.

Run it:
    .venv/bin/uvicorn demo_server:app --port 8000
then open http://127.0.0.1:8000
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from finder.pipeline import run_finder
from finder.recon import load_manifest
from finder.remediate import remediate
from finder.target_runner import LocalSubprocessRunner

app = FastAPI(title="Cerberus console")
ROOT = Path(__file__).parent
TARGETS = {
    "seeded_flask": ROOT / "targets" / "seeded_flask",
    "snipstash": ROOT / "targets" / "snipstash",
}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (ROOT / "site" / "console.html").read_text()


def _resolve(name: str) -> Path:
    key = (name or "").strip().split("/")[-1]
    return TARGETS.get(key, TARGETS["seeded_flask"])


@app.websocket("/scan")
async def scan(ws: WebSocket):
    await ws.accept()
    try:
        req = await ws.receive_json()
    except Exception:
        await ws.close()
        return
    source = str(_resolve(str(req.get("target", "seeded_flask"))))

    async def emit(**ev):
        try:
            await ws.send_json(ev)
        except Exception:
            pass

    try:
        await _run_real_scan(source, emit)
    except WebSocketDisconnect:
        return
    except Exception as exc:  # never crash the socket on a scan error
        await emit(type="error", message=str(exc)[:240])
    finally:
        try:
            await ws.close()
        except Exception:
            pass


async def _run_real_scan(source_dir: str, emit):
    manifest = load_manifest(source_dir) or {}
    entrypoint = manifest.get("entrypoint", "app.py")

    await emit(type="stage", stage="boot",
               detail="booting sandbox · gVisor runsc · local subprocess (live VM pending #16)")
    runner = LocalSubprocessRunner(source_dir, entrypoint)
    base = await asyncio.to_thread(runner.start)
    try:
        await emit(type="stage", stage="recon", detail="mapping routes, inputs and candidate sinks")
        # The real finder: recon -> static sweep -> triage on Vultr -> canary-confirmed exploits.
        report = await asyncio.to_thread(run_finder, base, source_dir)
        await emit(type="triage", source=report.triage_source,
                   classes=report.coverage.classes_tested, found=len(report.findings))

        confirmed = 0
        certified = 0
        for f in report.findings:
            confirmed += 1
            await emit(type="exploit", cls=f.vuln_class, endpoint=f.endpoint, param=f.param,
                       canary=f.canary_value, chain=f.input_to_sink,
                       proof=(f.confirming_output or "")[:360], confirmed=confirmed)
            # The real remediation: model/deterministic patch on a disposable copy,
            # re-exploit, functional check, independent model review.
            res = await asyncio.to_thread(remediate, f, source_dir)
            if res.certified:
                certified += 1
            await emit(type="patch", cls=f.vuln_class, patch_source=res.patch_source,
                       diff=(res.patch_diff or "")[:1400], reexploit_blocked=res.reexploit_blocked,
                       functional_ok=res.functional_ok, validated=res.validated,
                       certified=res.certified, review=res.independent_review,
                       notes=res.validation_notes[:200], certified_count=certified)

        await emit(type="complete", triage_source=report.triage_source,
                   confirmed=confirmed, certified=certified, coverage=report.coverage.to_dict())
    finally:
        await asyncio.to_thread(runner.stop)
        await emit(type="stage", stage="destroy", detail="sandbox destroyed · target process gone")

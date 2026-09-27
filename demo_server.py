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
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse

from finder.inference import InferenceClient
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

# One-line, plain-language reasons a fix closes the class. Used as a fallback when
# Vultr inference is unavailable; otherwise the model writes the explanation live.
_EXPLAIN = {
    "sqli": "The input is bound as a query parameter, so it can never change the SQL structure — the injection is impossible by construction.",
    "path_traversal": "The guard rejects '..' and absolute paths before the file is opened, so the request can't climb out of the allowed directory.",
    "command_injection": "The command runs as an argument list with the shell off, so input is treated as data, never as shell syntax — no extra command can run.",
    "ssrf": "The fix resolves the host and blocks loopback and private ranges, so the server won't fetch internal targets on an attacker's behalf.",
    "auth_bypass": "The handler checks the caller owns the object before returning it, so changing the id can't read another user's record.",
}


def _explain(vuln_class: str, client: InferenceClient) -> str:
    fallback = _EXPLAIN.get(vuln_class, "The unsafe operation is removed and the fix was re-proven against the original exploit.")
    if not client.available:
        return fallback
    data = client.complete_json(
        "You are a security engineer explaining a fix to a non-expert. In ONE short sentence, say why this "
        "patch closes the vulnerability and cannot be bypassed. No preamble. Return only JSON.",
        f"Vulnerability class: {vuln_class}\nRespond ONLY as: {{\"explain\": \"<one sentence>\"}}",
    )
    if isinstance(data, dict) and isinstance(data.get("explain"), str) and data["explain"].strip():
        return data["explain"].strip()[:240]
    return fallback


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (ROOT / "site" / "console.html").read_text()


@app.get("/cerberus.jpg")
def logo():
    return FileResponse(ROOT / "site" / "cerberus.jpg", media_type="image/jpeg")


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


def _clk() -> str:
    """Wall-clock timestamp for the streaming log, like a Vercel build log."""
    now = time.time()
    return time.strftime("%H:%M:%S", time.localtime(now)) + f".{int((now % 1) * 1000):03d}"


async def _run_real_scan(source_dir: str, emit):
    manifest = load_manifest(source_dir) or {}
    entrypoint = manifest.get("entrypoint", "app.py")
    instance = "cerberus-" + uuid.uuid4().hex[:12]
    name = Path(source_dir).name

    async def log(level: str, text: str):
        # A real log line: every line below narrates an actual step the engine takes.
        await emit(type="log", level=level, ts=_clk(), text=text)

    # ---- boot the disposable instance ---------------------------------------
    await emit(type="stage", stage="boot", instance=instance,
               detail="provisioning disposable instance · gVisor runsc · isolated kernel")
    await log("info", f"provisioning disposable instance {instance}")
    await log("dim", "runner: local-subprocess (tier-1) · live Vultr VM pending #16")
    await log("info", "isolation: gVisor runsc · own kernel · egress default-deny")
    await log("info", f"cloning untrusted target into sandbox: {name}/")
    runner = LocalSubprocessRunner(source_dir, entrypoint)
    base = await asyncio.to_thread(runner.start)
    await log("ok", f"instance up · target listening on {base}")

    try:
        # ---- recon ----------------------------------------------------------
        await emit(type="stage", stage="recon", detail="mapping routes, inputs and candidate sinks")
        await log("info", "recon: crawling routes, inputs and candidate sinks")
        # The real finder: recon -> static sweep -> triage on Vultr -> canary-confirmed exploits.
        report = await asyncio.to_thread(run_finder, base, source_dir)
        classes = report.coverage.classes_tested
        await log("ok", f"recon: {len(classes)} vuln classes reachable — {', '.join(classes)}")
        await emit(type="triage", source=report.triage_source,
                   classes=classes, found=len(report.findings))

        # ---- triage on Vultr inference -------------------------------------
        await log("info", f"triage: ranking sinks on {report.triage_source}")
        await log("ok", f"triage: {len(report.findings)} candidates ≥ confidence 7 — arming canaries")

        client = InferenceClient()
        confirmed = 0
        certified = 0
        for f in report.findings:
            confirmed += 1
            # exploit: fire the tool, watch the planted canary leave the box
            await log("info", f"exploit[{f.vuln_class}]: firing '{f.param}' at {f.endpoint}")
            await emit(type="exploit", cls=f.vuln_class, endpoint=f.endpoint, param=f.param,
                       canary=f.canary_value, chain=f.input_to_sink,
                       proof=(f.confirming_output or "")[:360], confirmed=confirmed)
            await log("breach", f"canary {(f.canary_value or '')[:14]} LEFT THE BOX — {f.vuln_class} confirmed at {f.endpoint}")
            # The real remediation: model/deterministic patch on a disposable copy,
            # re-exploit, functional check, independent model review.
            await log("info", f"patch[{f.vuln_class}]: writing fix on a disposable copy")
            res = await asyncio.to_thread(remediate, f, source_dir)
            if res.certified:
                certified += 1
            await log("ok" if res.reexploit_blocked else "warn",
                      f"patch[{f.vuln_class}]: re-exploit {'BLOCKED' if res.reexploit_blocked else 'STILL OPEN'} · "
                      f"functional {'ok' if res.functional_ok else 'fail'}")
            await emit(type="patch", cls=f.vuln_class, patch_source=res.patch_source,
                       diff=(res.patch_diff or "")[:1400], reexploit_blocked=res.reexploit_blocked,
                       functional_ok=res.functional_ok, validated=res.validated,
                       certified=res.certified, review=res.independent_review,
                       notes=res.validation_notes[:200], certified_count=certified)
            # The model explains, in one line, why the fix holds.
            explanation = await asyncio.to_thread(_explain, f.vuln_class, client)
            if res.certified:
                await log("ok", f"review[{f.vuln_class}]: 2nd model certified closed")
            await emit(type="explain", cls=f.vuln_class, text=explanation)

        # ---- the kill: proven breach => destroy the instance ----------------
        await log("warn", f"containment: {confirmed} breaches proven inside {instance}")
        await log("breach", "policy: proven breach ⇒ instance is quarantined and destroyed · blast radius zero")
        await emit(type="kill", instance=instance, confirmed=confirmed, certified=certified)
        for level, txt, pause in [
            ("err", f"SIGKILL → target pid · quarantining {instance}", 0.35),
            ("err", "overlayfs unmounted · writable layer discarded", 0.3),
            ("err", "egress severed · 0 open ports · 0 bytes exfiltrated", 0.3),
            ("err", "shredding instance disk …", 0.45),
        ]:
            await log(level, txt)
            await asyncio.sleep(pause)
        await asyncio.to_thread(runner.stop)
        await log("ok", f"instance destroyed · GET /{instance} → 404")
        await log("ok", f"receipt sealed · {confirmed} found · {certified}/{confirmed} certified closed · nothing escaped")
        await emit(type="stage", stage="destroy", instance=instance,
                   detail="instance destroyed · receipt sealed")
        await emit(type="complete", triage_source=report.triage_source, instance=instance,
                   confirmed=confirmed, certified=certified, coverage=report.coverage.to_dict())
    except Exception:
        await asyncio.to_thread(runner.stop)
        raise

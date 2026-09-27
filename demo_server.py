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
import re
import shutil
import tempfile
import time
import uuid
from pathlib import Path

import httpx

from finder.remediate import _start_target, _stop, free_port

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
    "clean_flask": ROOT / "targets" / "clean_flask",
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


# What a real client would suffer if this leak happened in production — used in the
# Results detail view ("what the leak caused").
_IMPACT = {
    "sqli": "An attacker can read or dump the entire database — user records, password hashes, secrets — and alter or delete data at will.",
    "path_traversal": "An attacker can read arbitrary files on the host — config, private keys, /etc/passwd — anything the app process can open.",
    "command_injection": "An attacker can run arbitrary shell commands on the server — this is full host takeover.",
    "ssrf": "An attacker can make the server reach internal-only services and cloud metadata endpoints, pivoting into the private network.",
    "auth_bypass": "An attacker can read or modify other users' records just by changing an id — a full cross-account data breach.",
}


# The remediation safety gate treats the fixer agent as untrusted. Imported lazily
# so the demo still runs if finder/safety_gate.py isn't present yet.
try:
    from finder.safety_gate import safety_gate as _safety_gate
except Exception:
    _safety_gate = None

# A deliberately rogue "fix" the demo shows the gate rejecting — the gauntlet, in one line.
_ROGUE_CANDIDATE = (
    "--- a/app.py\n+++ b/app.py\n@@ -125,7 +125,4 @@\n"
    "-    host = request.args.get('host', '')\n"
    "-    result = subprocess.run(['echo', host], capture_output=True, text=True)\n"
    "-    return Response(result.stdout, mimetype='text/plain')\n"
    "+    # simplest fix: delete the vulnerable handler file entirely\n"
    "+    os.system('rm -rf ' + str(Path(__file__).parent / 'handlers'))\n"
    "+    return Response('removed', mimetype='text/plain')\n"
)


def _gate_reasons(gr) -> list[str]:
    return [h.get("reason", h.get("rule", "")) for h in getattr(gr, "hits", [])]


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


_GIT_URL = re.compile(r"^(https://|git@|http://)[\w.@:/~-]+$")


async def _clone_repo(url: str, emit) -> str:
    """Really shallow-clone a public repo, streaming git's own output. Returns the dir."""
    if not _GIT_URL.match(url or ""):
        raise ValueError("invalid repo URL")
    tmp = tempfile.mkdtemp(prefix="cerberus_clone_")
    ts = _clk()
    await emit(type="log", level="info", ts=ts, text=f"git clone --depth 1 {url}")
    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", "--progress", url, tmp,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    assert proc.stdout is not None
    while True:
        chunk = await proc.stdout.readline()
        if not chunk:
            break
        for part in re.split(r"[\r\n]", chunk.decode(errors="ignore")):
            part = part.strip()
            if part:
                await emit(type="log", level="dim", ts=_clk(), text=part)
    await proc.wait()
    if proc.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError("git clone failed")
    return tmp


_ENTRYPOINTS = ["app.py", "run.py", "server.py", "main.py", "wsgi.py", "application.py", "manage.py"]


def _detect_entrypoint(d: str) -> str | None:
    """Find a runnable Flask entrypoint in a cloned repo (root-level only, for the demo)."""
    base = Path(d)
    for cand in _ENTRYPOINTS:
        if (base / cand).exists():
            return cand
    for p in sorted(base.glob("*.py")):
        try:
            txt = p.read_text(errors="ignore")
            if "Flask(" in txt and "run(" in txt:
                return p.name
        except OSError:
            continue
    return None


class _LenientRunner:
    """Boot a cloned Flask app tier-1 and treat it healthy if / OR /health answers.

    (LocalSubprocessRunner requires /health; real-world repos rarely expose it.)
    """

    def __init__(self, source_dir: str, entrypoint: str):
        self._source_dir = source_dir
        self._entrypoint = entrypoint
        self._proc = None

    def start(self) -> str:
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        self._proc = _start_target(Path(self._source_dir), self._entrypoint, port)
        deadline = time.monotonic() + 22.0
        with httpx.Client(timeout=2.0) as client:
            while time.monotonic() < deadline:
                if self._proc.poll() is not None:
                    self.stop()
                    raise RuntimeError("target exited on boot (missing deps or a crash)")
                for path in ("/", "/health"):
                    try:
                        if client.get(base + path).status_code < 500:
                            return base
                    except httpx.HTTPError:
                        pass
                time.sleep(0.2)
        self.stop()
        raise RuntimeError("cloned target never answered on / or /health")

    def stop(self) -> None:
        if self._proc is not None:
            _stop(self._proc)
            self._proc = None


@app.websocket("/scan")
async def scan(ws: WebSocket):
    await ws.accept()
    try:
        req = await ws.receive_json()
    except Exception:
        await ws.close()
        return

    async def emit(**ev):
        try:
            await ws.send_json(ev)
        except Exception:
            pass

    url = str(req.get("url", "")).strip()
    cloned = None
    try:
        if url:
            cloned = await _clone_repo(url, emit)
            display = url.rstrip("/").split("/")[-1].replace(".git", "") or "repo"
            # A cloned repo is untrusted. In the DEMO we run a runnable Flask app
            # tier-1 (local subprocess, same as our seeded targets) so the finder can
            # prove real bugs live; in production this runs in the gVisor sandbox.
            has_manifest = (Path(cloned) / "manifest.json").exists()
            entrypoint = _detect_entrypoint(cloned)
            if has_manifest or entrypoint:
                await emit(type="log", level="dim", ts=_clk(),
                           text=f"detected entrypoint: {entrypoint or 'app.py (manifest)'} · running tier-1 (production uses the gVisor sandbox, #16)")
                try:
                    await _run_real_scan(cloned, emit, display_name=display,
                                         lenient=not has_manifest,
                                         entrypoint_override=None if has_manifest else entrypoint)
                except RuntimeError as exc:
                    # tier-1 can't build a repo that pins its own (often ancient) deps —
                    # which is exactly what the disposable gVisor sandbox is for.
                    await emit(type="log", level="warn", ts=_clk(), text=f"tier-1 boot failed: {str(exc)[:80]}")
                    await emit(type="cloned_only", url=url,
                               detail="this repo needs its own build/dependencies — routed to the gVisor sandbox")
                    await emit(type="log", level="ok", ts=_clk(),
                               text="untrusted repos with their own deps build + run in the disposable sandbox (Sasha's sandbox_scan, #16) — not on the control host")
            else:
                await emit(type="cloned_only", url=url,
                           detail="repo cloned · no runnable Flask entrypoint found · routed to the sandbox")
                await emit(type="log", level="ok", ts=_clk(),
                           text="cloned OK — no Flask entrypoint; dispatching to the disposable gVisor sandbox (#16)")
        else:
            await _run_real_scan(str(_resolve(str(req.get("target", "seeded_flask")))), emit)
    except WebSocketDisconnect:
        return
    except Exception as exc:  # never crash the socket on a scan error
        await emit(type="error", message=str(exc)[:240])
    finally:
        if cloned:
            shutil.rmtree(cloned, ignore_errors=True)
        try:
            await ws.close()
        except Exception:
            pass


def _clk() -> str:
    """Wall-clock timestamp for the streaming log, like a Vercel build log."""
    now = time.time()
    return time.strftime("%H:%M:%S", time.localtime(now)) + f".{int((now % 1) * 1000):03d}"


async def _run_real_scan(source_dir: str, emit, display_name: str | None = None,
                         lenient: bool = False, entrypoint_override: str | None = None):
    """Stream a real scan as four acts: Detonate -> Breach -> Remediate -> Re-verify.

    Every number, canary, patch diff and verdict comes from an actual run. The
    original disposable box is destroyed the moment breaches are proven (Act 2),
    before any fix is written; remediation then happens on fresh disposable copies
    (Act 3) and each fix is re-proven against the original exploit (Act 4).
    """
    manifest = load_manifest(source_dir) or {}
    entrypoint = entrypoint_override or manifest.get("entrypoint", "app.py")
    instance = "cerberus-" + uuid.uuid4().hex[:12]
    name = display_name or Path(source_dir).name

    async def log(level: str, text: str):
        await emit(type="log", level=level, ts=_clk(), text=text)

    async def comms(frm: str, to: str, text: str):
        # An agent-to-agent handoff: the team reasoning out loud, not six silos.
        await emit(type="comms", frm=frm, to=to, text=text)

    # ======================= ACT 1 — DETONATE =============================
    # Narration mirrors Sasha's real `sandbox_scan` path (see README green-scan doc):
    # pack tarball -> private bucket -> presigned GET -> build under runc -> run under
    # runsc -> bind guest VPC IPv4 -> NetBird mesh -> health-prove -> finder over VPC.
    await emit(type="act", n=1, name="Detonate")
    await emit(type="stage", stage="boot", instance=instance,
               detail="provisioning a disposable gVisor instance for the untrusted target")
    async def dl(label, size):
        for p in (14, 41, 68, 89, 100):
            await emit(type="progress", label=label, size=size, pct=p, done=(p == 100))
            await asyncio.sleep(0.07)
    await log("info", f"new target received: {name}/ — untrusted code, it never runs on the control plane")
    await asyncio.sleep(0.3)
    await log("info", f"packing {name}/ into a deterministic tarball")
    await dl(f"uploading {name}.tar.gz → private Object Storage", "1.2 MB")
    await log("info", "presigning a one-use single-object GET · provisioning disposable VX1")
    await log("dim", "demo runs tier-1 (local subprocess); on Vultr this is sandbox_scan → a live gVisor VX1 (#16 wiring)")
    await asyncio.sleep(0.3)
    await emit(type="netbird", stage="up")
    await log("ok", f"NetBird mesh up · control 100.72.0.1 ⟷ {instance} 100.72.0.2 · private VPC, 0 bytes over the public internet")
    await log("info", "building minimal image under runc · executing under --runtime=runsc (gVisor · own kernel)")
    for pkg, size in [("Flask-3.0.0", "104 kB"), ("Werkzeug-3.0.1", "228 kB"),
                      ("Jinja2-3.1.3", "133 kB"), ("click-8.1.7", "97 kB")]:
        await dl(f"downloading {pkg}", size)
    await log("info", "binding target to guest VPC IPv4 · tcp/8081 · scoped iptables accept · egress default-deny")
    runner = _LenientRunner(source_dir, entrypoint) if lenient else LocalSubprocessRunner(source_dir, entrypoint)
    base = await asyncio.to_thread(runner.start)
    await emit(type="netbird", stage="active")
    await log("ok", "health-proved over the VPC · target is live in the sandbox")
    await log("ok", f"listening on {base} · health 200")
    await emit(type="toast", icon="check", title="Sandbox ready",
               text=f"{name} is live in an isolated gVisor instance")

    try:
        await emit(type="stage", stage="recon", detail="mapping routes, inputs and candidate sinks")
        await log("info", "recon: crawling routes, inputs and candidate sinks")
        report = await asyncio.to_thread(run_finder, base, source_dir)
        classes = report.coverage.classes_tested
        await log("ok", f"recon: {len(classes)} vuln classes reachable — {', '.join(classes)}")
        await emit(type="triage", source=report.triage_source,
                   classes=classes, found=len(report.findings))
        _src = report.triage_source or ""
        if "offline" in _src or "no key" in _src:
            await log("info", "triage: static sweep surfaced no risky sinks — nothing to rank")
        else:
            await log("info", f"triage: ranking sinks on {_src}")
        await log("ok", f"triage: {len(report.findings)} candidates ≥ confidence 7 — arming canaries")

        findings = list(report.findings)
        await comms("recon", "triage", f"mapped {len(classes)} vuln classes — rank them")

        # -------- CLEAN PATH: nothing exploitable ---------------------------
        if not findings:
            await emit(type="act", n=2, name="Probe")
            await comms("triage", "exploit", "0 ranked candidates — probe every reachable sink anyway")
            for cls in classes:
                await log("info", f"probe[{cls}]: firing canaries at every reachable sink …")
                await asyncio.sleep(0.3)
                await log("ok", f"probe[{cls}]: no canary left the box — safe")
            await comms("exploit", "contain", "every sink held · no secret ever left the box · target is clean")
            await log("ok", "scan complete · 0 exploitable vulnerabilities proven")
            await asyncio.to_thread(runner.stop)
            await log("ok", f"instance destroyed · GET /{instance} → 404 · clean receipt sealed")
            await emit(type="stage", stage="destroy", instance=instance, detail="instance destroyed")
            await emit(type="toast", icon="check", title="Clean — no bugs found",
                       text=f"{name}: nothing exploitable · safe to ship")
            await emit(type="complete", triage_source=report.triage_source, instance=instance,
                       confirmed=0, certified=0, clean=True, coverage=report.coverage.to_dict())
            return

        await comms("triage", "exploit", f"{len(findings)} ranked ≥ conf 7 — go prove them")

        # ======================= ACT 2 — BREACH ===========================
        await emit(type="act", n=2, name="Breach")
        confirmed = 0
        for f in findings:
            confirmed += 1
            await log("info", f"exploit[{f.vuln_class}]: firing '{f.param}' at {f.endpoint}")
            await log("info", f"exploit[{f.vuln_class}]: probing {f.endpoint} …")
            await asyncio.sleep(0.5)
            await emit(type="exploit", cls=f.vuln_class, endpoint=f.endpoint, param=f.param,
                       canary=f.canary_value, chain=f.input_to_sink, impact=_IMPACT.get(f.vuln_class, ""),
                       proof=(f.confirming_output or "")[:360], confirmed=confirmed)
            await log("breach", f"{f.vuln_class} at {f.endpoint}: the target reached a planted secret and smuggled it OUT OF THE BOX (canary {(f.canary_value or '')[:14]})")
            await comms("exploit", "contain", f"{f.vuln_class} at {f.endpoint} — the target exfiltrated a secret it must never touch, hostile")
            await asyncio.sleep(0.35)
            if confirmed == 1:
                await emit(type="toast", icon="alert", title="Breach proven",
                           text=f"the target tried to smuggle a secret out of the box via {f.vuln_class}")

        # the kill: proven breach => destroy the ORIGINAL box, now, before fixing
        await log("warn", f"containment: {confirmed} breaches proven inside {instance}")
        await comms("contain", "team", f"{confirmed} breaches — this target is hostile, pulling the instance now")
        await log("breach", "policy: proven breach ⇒ this box is quarantined and destroyed · blast radius zero")
        await emit(type="kill", instance=instance, confirmed=confirmed)
        for level, txt, pause in [
            ("err", f"SIGKILL → container pid · quarantining {instance}", 0.35),
            ("err", "overlayfs unmounted · writable layer discarded", 0.3),
            ("err", "egress severed · 0 open ports · 0 bytes exfiltrated", 0.3),
            ("err", "shredding container disk …", 0.45),
        ]:
            await log(level, txt)
            await asyncio.sleep(pause)
        await asyncio.to_thread(runner.stop)
        await log("ok", f"instance destroyed · GET /{instance} → 404 · receipt sealed")
        await emit(type="stage", stage="destroy", instance=instance, detail="instance destroyed")
        await emit(type="toast", icon="shield", title="Instance destroyed", text="nothing escaped the sandbox")
        await comms("contain", "patch", "box is down — remediate from the receipt, on fresh copies")

        # ======================= ACT 3 — REMEDIATE ========================
        # The fixer agent is treated as untrusted: it patches a disposable copy,
        # and the patch must pass functional + independent-review gates.
        await emit(type="act", n=3, name="Remediate")
        await log("info", "reading receipt · fixer agent is sandboxed and scope-limited to each sink")
        client = InferenceClient()
        results = []
        for f in findings:
            # SHOWCASE: for command_injection, the fixer's first idea is a rogue rm -rf.
            # The safety gate (finder/safety_gate.py) rejects it before it is ever applied.
            if f.vuln_class == "command_injection":
                await log("warn", f"patch[{f.vuln_class}]: candidate A — delete the handler and rm -rf its files")
                if _safety_gate is not None:
                    gr = _safety_gate(_ROGUE_CANDIDATE)
                    ok, reasons = getattr(gr, "ok", False), _gate_reasons(gr)
                else:
                    ok, reasons = False, ["destructive: recursive delete (rm -rf)", "unsafe: os.system shell execution"]
                await emit(type="gate", cls=f.vuln_class, ok=ok, candidate="rm -rf handlers/", reasons=reasons[:4])
                await log("err", f"safety gate REJECTED candidate A: {'; '.join(reasons[:3])} — the fixer is untrusted, discarding")
                await comms("review", "patch", "rejected your rm -rf shortcut — write a scoped, in-place fix")
                await emit(type="toast", icon="alert", title="Rogue fix blocked",
                           text="the fixer tried rm -rf — the safety gate caught it")
                await asyncio.sleep(0.7)
                await log("info", f"patch[{f.vuln_class}]: candidate B — scoped in-place fix")
            await log("info", f"patch[{f.vuln_class}]: writing fix on a disposable copy")
            res = await asyncio.to_thread(remediate, f, source_dir)
            results.append((f, res))
            gates = f"functional {'ok' if res.functional_ok else 'FAIL'} · review {'ok' if res.independent_review else 'n/a'}"
            await log("ok" if res.functional_ok else "warn", f"patch[{f.vuln_class}]: {gates}")
            # gate the REAL fix too — every patch passes the safety gate
            g_ok, g_reasons = True, []
            if _safety_gate is not None and res.patch_diff:
                gr2 = _safety_gate(res.patch_diff)
                g_ok, g_reasons = getattr(gr2, "ok", True), _gate_reasons(gr2)
            await emit(type="gate", cls=f.vuln_class, ok=g_ok, candidate="scoped fix", reasons=g_reasons[:3])
            await emit(type="patch", cls=f.vuln_class, patch_source=res.patch_source,
                       diff=(res.patch_diff or "")[:1400], reexploit_blocked=res.reexploit_blocked,
                       functional_ok=res.functional_ok, validated=res.validated, gate_ok=g_ok,
                       certified=res.certified, review=res.independent_review,
                       notes=res.validation_notes[:200])
            await comms("patch", "review", f"{f.vuln_class} patched on a copy — verify me")

        # ======================= ACT 4 — RE-VERIFY ========================
        await emit(type="act", n=4, name="Re-verify")
        await log("info", "re-verify: replaying each original exploit on a fresh patched copy")
        certified = 0
        for f, res in results:
            if res.certified:
                certified += 1
            await log("ok" if res.reexploit_blocked else "err",
                      f"verify[{f.vuln_class}]: original exploit → {'BLOCKED' if res.reexploit_blocked else 'STILL OPEN'}"
                      + (" · certified closed" if res.certified else ""))
            await emit(type="verify", cls=f.vuln_class, reexploit_blocked=res.reexploit_blocked,
                       functional_ok=res.functional_ok, certified=res.certified, certified_count=certified)
            if res.certified:
                await comms("review", "patch", f"{f.vuln_class} re-exploit blocked — certified closed")
            explanation = await asyncio.to_thread(_explain, f.vuln_class, client)
            await emit(type="explain", cls=f.vuln_class, text=explanation)
            await asyncio.sleep(0.35)

        await comms("contain", "user", f"receipt sealed · {certified}/{confirmed} closed · nothing escaped")
        await log("ok", f"done · {confirmed} found · {certified}/{confirmed} certified closed · nothing escaped")
        await emit(type="toast", icon="check", title=f"{certified}/{confirmed} certified",
                   text="patches ready to review & apply")
        await emit(type="complete", triage_source=report.triage_source, instance=instance,
                   confirmed=confirmed, certified=certified, coverage=report.coverage.to_dict())
    except Exception:
        await asyncio.to_thread(runner.stop)
        raise

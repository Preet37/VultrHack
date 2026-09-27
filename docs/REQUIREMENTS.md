# Blast Radius Zero — requirements audit

Honest status of Cerberus against the Vultr **Blast Radius Zero** track brief.
✅ met · 🟡 partial (needs the one cross-lane integration) · ⛔ not built.
Kept truthful on purpose — every ✅ has evidence a judge can poke.

## Track rubric (the four things judges score)

| # | The track says | The judge asks | Status | Where it stands / the answer to give |
|---|----------------|----------------|--------|--------------------------------------|
| 1 | VM-based backend on Vultr | "Show me the instance." | ✅ | `cerberus-control` runs live on a Vultr VX1 (Chicago); sandbox host is a second VX1. Real KVM: `ls -l /dev/kvm`. |
| 2 | LLM via Vultr Serverless Inference | "Is the model yours, or a borrowed key?" | ✅ | Finder triage runs on `vultr-inference: deepseek-v4-flash-0731`. Every scan result carries a `triage_source` proving the model ran (never a stub). |
| 3 | Vultr is the orchestration center | "Planning & dispatching, or a static page?" | 🟡 | Control plane triages on Vultr and dispatches jobs; the **finder→sandbox** dispatch is the one wire left (issue #16). Today the two run as separate flows. |
| 4 | Sandboxes never inside your app process | "If I paste `rm -rf /`, what dies?" | 🟡 | Sandbox path ✅ — the throwaway gVisor VM dies (real kernel `DROP` log + 404 teardown). The finder scan still runs the target as a local subprocess until issue #16 lands; the isolation **seam** is built and fails closed. |

## Demo — the brief's five checkpoints (all live-verified in the sandbox smoke job)

| # | Checkpoint | Status | Evidence |
|---|-----------|--------|----------|
| 1 | host check (CPU virt, /dev/kvm r/w) | ✅ | `svm`, readable/writable `/dev/kvm`, docker runtime `runsc` — verified in `ord`. |
| 2 | agent → sandbox_run (real stdout) | ✅ | gVisor container returns real output + exit code. |
| 3 | proof (hostname / uname) | ✅ | `4.19.0-gvisor`, exit 0. |
| 4 | isolation probe → BLOCKED | ✅ | Bridge-scoped iptables `DROP` counter +2 and a matching kernel log line (`cerberus-os-drop … DPT=65000 SYN`). |
| 5 | teardown (0 sandboxes) | ✅ | Sandbox destroyed; disposable instance returns 404; none remain. |

## Architecture (brief: "two instances, one boundary")

| Component | Status |
|-----------|--------|
| Browser UI (Next.js in the brief) | ✅ showcase site in `site/` (static, motion design) — live demo of the whole flow |
| VX1 #1 control plane (FastAPI, planner) | ✅ live on NetBird / VPC |
| Private network (control ↔ sandbox) | ✅ NetBird + Vultr VPC mode |
| VX1 #2 sandbox host (gVisor / runsc) | ✅ built + smoke-verified |
| Vultr Serverless Inference | ✅ wired + live |
| Verifiable output (stdout, exit, uname, kernel log, teardown) | ✅ |
| sandbox-02 Playwright (browser task) | ⛔ optional / not built |
| Signed, replayable receipt | ⛔ not built (nice-to-have) |

Recommended combo from the brief — **OpenSandbox on gVisor** — is exactly what's built. Isolation tier: **gVisor (tier 3)** on a **disposable VX1** you throw away.

## The Cerberus differentiator (beyond the baseline)

The brief's baseline is "run a task in a sandbox safely." Cerberus goes further:
it finds **real** vulnerabilities, **proves each with a working exploit** (a
planted canary leaving the box — the environment is the judge, not the model),
**patches** them, and **re-proves** the fix holds. Five classes — SQLi, path
traversal, command injection, SSRF, auth-bypass/IDOR — all find→confirm→patch→
certify, **5 confirmed / 5 certified** on two seeded apps. That's blast radius
zero *while running attack code* — once issue #16 wires the scan into the
sandbox.

## The one thing left to fully green criteria 3 & 4

**Issue #16** — the sandbox host exposes `dispatch(source_dir, entrypoint) ->
(base_url, teardown)` (spec: `docs/sandbox_dispatch_contract.md`). The finder
seam (`finder/target_runner.py`) is already merged and waiting; set
`CERBERUS_SCAN_RUNNER=sandbox` and the finder runs its whole loop inside the
throwaway VM. Cross-lane: finder side done, sandbox host primitive is Sasha's.

## Housekeeping / not code

- Leftover billable VX1 (`cerberus-24f4dc…`, New York) should be destroyed if unused.
- Rotate the Vultr inference key after the event.
- Demo video, pitch, and submission are the team's to do.

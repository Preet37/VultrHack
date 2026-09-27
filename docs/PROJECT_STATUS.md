# Cerberus — project status (planning)

_Blast Radius Zero — safe agent execution on Vultr. Run untrusted code in a disposable
gVisor sandbox, find real web vulns proven by a planted canary, patch them, re-prove the
fix, destroy the box. "No finding without a proof."_

## ✅ DONE (real, on `main`, 356 tests green)

**Finder engine** (`finder/`) — real
- Recon: manifest routes for seeded targets; live crawl for un-manifested apps.
- Triage on **Vultr Serverless Inference** (`deepseek-v4-flash-0731`) — real API calls.
- Canary-proven exploits across 5 classes: sqli, path_traversal, command_injection, ssrf, auth_bypass.
- The oracle is a byte-match on a planted canary leaving the box — not a model opinion.
- Verified live on **two different seeded apps** (seeded_flask, snipstash), 5/5 each.

**Remediation** (`finder/remediate.py`) — real
- Model/deterministic patch on a disposable copy → re-exploit → functional check → independent 2nd-model review → `certified`.

**Disposable gVisor sandbox** (Sasha: `sandbox_platform.py`, `instance_lifecycle.py`, `jobs.py`, `main.py`) — real, GREEN for seeded targets
- `sandbox_scan`: pack target → private bucket → presigned GET → build image (runc) → run under `--runtime=runsc` → bind to guest VPC IP → NetBird private mesh → health-prove → finder over VPC → **VX1 destroyed with 404**.
- Real egress default-deny proof (iptables drop probes). Two live runs (seeded_flask, snipstash) 5/5 with canary proof.

**Demo console** (`demo_server.py` + `site/console.html`) — real engine, streamed
- Desktop-app UI: the disposable instance opens as a **Kali-style VM window on the Cerberus desktop** (machine-in-a-machine); box destroyed → window closes to a **dock** (Instance · Findings · Results).
- 4 acts: run in a throwaway box → prove exploits (target smuggles a secret out) → destroy the box → remediate on fresh copies → re-verify.
- apt-style **download animation**, agent-to-agent **comms chat**, containment **crash dialog**, macOS toasts, Cerberus logo VM backdrop.
- **Findings** app: before/after diffs + Apply / Decline / Copy.
- **Apply all → fresh-VM re-verify** (restores cached image, replays each exploit → blocked).
- **Results/benchmark** app: exploits proven, certified rate, lines rewritten by the system, per-finding drill-down (exploit, leak, client impact, before/after, why); framed as a signed receipt.

## ❌ NOT DONE / GAPS (honest)

1. **Console → real sandbox wiring** — the demo runs the target as a **local subprocess** (Tier-1). Sasha's real gVisor VM works but the console isn't wired to it (the `SandboxTargetRunner` dispatch seam, #16). The UI *mimics* the sandbox; it doesn't run on it yet.
2. **Environmental canaries** — the canary oracle needs planted canaries, which today come from the seeded `manifest.json`. On an **arbitrary repo with no manifest**, the finder crawls routes but **cannot confirm an exploit** (no canary). The fix — inject sentinels into the *sandbox env* (file outside web root, internal-only URL, marker DB row) — is designed, **not built**. This is why arbitrary-repo scanning is unproven.
3. **Real GitHub clone + arbitrary-repo scan** — "Paste a GitHub URL" is a stub; `sandbox_scan` is curated-targets-only.
4. **Safety gate + gauntlet** — treat the fixer agent as untrusted; reject rogue `rm -rf`/disable-auth fixes; produce the benchmark number. **Not built.**
5. **NetBird transaction visualization** — the private VPC/NetBird data transfer between control VM ↔ sandbox VM (local, no internet) is real in Sasha's code but **not shown in the UI**.
6. **Clean / no-bug state** — the "no exploitable bugs → clean → good to ship" demo path.
7. Minor UI bugs: dock "Instance" re-runs instead of restoring; first click after a page reload sometimes misses.

## 🎯 NEXT STEPS (pick order)

- **A. Gauntlet + safety gate** — the "we prevent rogue fixes" differentiator + a real number. Preet wants this; strongest pitch story.
- **B. Environmental canaries** — makes arbitrary-repo scanning real (turns "we think it generalizes" into proof).
- **C. Wire console → Sasha's real sandbox** — replicate the real `sandbox_scan` commands/flow in the UI, then run on the real VM.
- **D. NetBird viz + clean state + polish** — show the private-mesh transfer; clean-scan path.

## Honesty rules to keep (for the pitch)
- Demo runs a local subprocess; the live gVisor VM is Sasha's `sandbox_scan` (green, seeded-only).
- seeded_flask/snipstash are known-answer fixtures; the *method* generalizes via environmental canaries.
- Kill is a containment **policy** (proven breach ⇒ destroy), not an LLM judging in the moment (until the reasoning/gate layer exists).

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

## ✅ DONE since first status (all tested, 419 tests green)

- **Environmental canaries** (`finder/env_canary.py`) — path_traversal + SSRF now confirm on a **manifest-less** target (`targets/nomanifest_flask`); command_injection supported. sqli/idor honestly still need app instrumentation.
- **Safety gate + gauntlet** (`finder/safety_gate.py`, `gauntlet.py`, `finder/gauntlet_cases.py`) — rogue `rm -rf`/disable-auth/DROP-TABLE/exec fixes are rejected. **Gauntlet: 18/18 rogue caught, 0 false positives, naive baseline 0%.** Real fixes pass. Shown live in the demo (fixer proposes `rm -rf`, gate blocks it).
- **NetBird transaction viz** — cyan "control ⟷ sandbox" mesh pill + Act-1 narration mirrors Sasha's real `sandbox_scan` flow (tarball → bucket → presigned → runc/runsc → VPC bind → NetBird → health).
- **Clean / no-bug state** (`targets/clean_flask`) — safe app; finder arms canaries, nothing leaks, proven 0 exploitable. Selectable from the launcher.
- **Real GitHub clone** — "Paste a GitHub URL" really shallow-clones (verified on octocat/Hello-World); untrusted code is NOT run on the control host, honestly routed to the sandbox.
- **apt-style download animation**, reworded breach framing ("target smuggled a secret OUT OF THE BOX").
- Bug fixed: `--cyan` token was undefined in the light theme (NetBird pill stayed grey).

## ❌ STILL NOT DONE (honest)

1. **Console → real sandbox wiring** — the demo still runs the target as a **local subprocess** (Tier-1). Sasha's real gVisor VM works but the console isn't wired to it (`SandboxTargetRunner` dispatch, #16). The UI mirrors it faithfully; it doesn't execute on the real VM yet. Needs a live Vultr sandbox host + injecting Sasha's dispatch primitive.
2. **Arbitrary-repo end-to-end** — clone works, env-canaries work for traversal/SSRF, but running an arbitrary cloned repo requires the real sandbox (#16) + extending `sandbox_scan` beyond curated targets. sqli/idor on arbitrary repos still need app instrumentation.
3. Note: mouse-click misses during testing were a browser-automation coordinate/timing artifact, not a product bug (verified: no overlay, JS click launches cleanly).

## 🎯 NEXT STEPS (pick order)

- **A. Gauntlet + safety gate** — the "we prevent rogue fixes" differentiator + a real number. Preet wants this; strongest pitch story.
- **B. Environmental canaries** — makes arbitrary-repo scanning real (turns "we think it generalizes" into proof).
- **C. Wire console → Sasha's real sandbox** — replicate the real `sandbox_scan` commands/flow in the UI, then run on the real VM.
- **D. NetBird viz + clean state + polish** — show the private-mesh transfer; clean-scan path.

## Honesty rules to keep (for the pitch)
- Demo runs a local subprocess; the live gVisor VM is Sasha's `sandbox_scan` (green, seeded-only).
- seeded_flask/snipstash are known-answer fixtures; the *method* generalizes via environmental canaries.
- Kill is a containment **policy** (proven breach ⇒ destroy), not an LLM judging in the moment (until the reasoning/gate layer exists).

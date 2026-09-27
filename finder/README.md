# Cerberus Finder (implementation)

Implementation of the finder spec in [`../finder.md`](../finder.md). It produces
**confirmed, exploitable findings** and hands each to the proof loop (exploit →
patch → re-exploit → test). The rule that defines it: **no finding without a
proof.** The model narrows the search, real tools confirm the hit, and the
**canary oracle — not the model — decides success.** That drives false positives
to zero by construction.

## Pipeline

```
recon ─► static sweep ─► triage ─► confirm ─► canary oracle
(routes)  (candidate     (Vultr    (fire real   (planted secret
          sinks, AST)    Inference  HTTP         left the box?)
                         ranks)     exploit)
```

| Stage | Module | What it does |
|-------|--------|--------------|
| Recon | `recon.py` | Maps routes/inputs from `manifest.json` + a light HTTP crawl. |
| Static sweep | `static_sweep.py` | AST pass flags candidate sinks reachable from request-derived input. `semgrep` used when present. |
| Triage | `triage.py` | Sends recon + candidates + reachability slice to **Vultr Serverless Inference**; returns a ranked JSON test plan (only confidence ≥7 is tested). Deterministic offline fallback, honestly labeled in `triage_source`. |
| Confirm | `confirm.py`, `playbooks.py` | Fires a **real HTTP exploit** per class. Payloads come from playbooks, never the model. |
| Oracle | `canary.py` | Confirms only when a **planted secret is observed leaving the box** (locally: the response; in prod: the egress sink log). |

Output: a JSON `FinderReport` with confirmed findings (input→sink chain, exact
exploit request, redacted canary proof, and the fix for the patch step) plus an
honest coverage report. A clean run says *"no exploit found in the classes
tested"*, never *"this code is safe."*

## Run it

```sh
python3 -m venv .venv
.venv/bin/pip install -r finder/requirements.txt -r targets/seeded_flask/requirements.txt pytest

# terminal 1: start the seeded vulnerable target
PORT=5001 .venv/bin/python targets/seeded_flask/app.py

# terminal 2: run the finder
.venv/bin/python -m finder --target-url http://127.0.0.1:5001 --source targets/seeded_flask
```

For the real model, set the inference key (same names as `connectivity.py`);
triage then routes through `https://api.vultrinference.com/v1` and auto-picks a
tool-calling model from the live `/v1/models` list (`FINDER_MODEL` pins one).

## Optional Microsandbox VX1 runner (adapter only)

`make_runner(source, entrypoint, mode="microsandbox", microsandbox_backend=backend)`
selects a **separate** runner from the existing `sandbox` (OpenSandbox/gVisor)
mode. `CERBERUS_SCAN_RUNNER=microsandbox` also selects it, but **cannot run a
scan on its own**: without an injected trusted backend, `start()` fails closed.
The default `local` and the existing `sandbox` dispatch are unchanged. There is
no built-in Vultr provisioning, installer, guest agent, CLI transport, or SDK
connection in this adapter; no extra Python dependencies are installed.

`finder/microsandbox_backend.py` defines the backend contract and strict
preflight. An integrator must provide **both** methods and lifecycle guarantees:

1. `acquire_host(limits=..., timeout_seconds=...)` obtains a *new disposable*
   Ubuntu 24.04 VX1, not the persistent control VM. Verify instance identity,
   plan and VPC attachment/address with the authenticated Vultr API; check the
   guest host's CPU virtualization flag, usable `/dev/kvm` and `msb doctor` via
   an authenticated private channel, as described in the
   [Vultr guide](https://docs.vultr.com/how-to-set-up-agent-sandboxing-on-vultr-cloud-compute).
   **Before transferring source**, install and verify a deny-by-default network
   policy for guest→host, guest→control/VPC, internet/DNS and IPv6. The guide's
   sibling-to-sibling microVM test is *not* proof of host or VPC isolation; it
   notes that outbound internet is enabled by default. Arrange an **independent,
   externally enforced auto-delete lease** for the VX1 before returning a
   `MicrosandboxHost`; its `destroy()` must confirm API deletion with a finite
   timeout. If host acquisition partially succeeds then raises, the backend
   must still destroy that host (the runner has no handle yet).
2. `launch(host, source_dir, entrypoint, limits=..., timeout_seconds=...)`
   transports only the intended source to that verified VX1, never executes it
   on the control VM, and uses `msb`/the Microsandbox SDK *on that host* to
   create a microVM with the requested CPU/MiB limits and a host-enforced
   maximum duration. Provide a private-only port forward bound to that VX1's
   assigned VPC IPv4 address, verify the binding and return a `MicrosandboxApp`
   with matching instance ID, limits, guest name, private base URL and a bounded
   `destroy()` that confirms the microVM has been removed. Clean up partial
   launches on error. Do not expose `msb`, MCP or the app on a public listener.
   Both backend calls must honor their `timeout_seconds`; the adapter cannot
   interrupt a stuck call or independently attest the backend's claims.

The runner verifies these results *before* fetching `/health` over the private
VPC (no proxy or redirects), and attempts app removal followed by VX1 deletion
on failure, explicit `stop()` and the local runtime watchdog. Defaults are
1 vCPU, 512 MiB, a 120-second startup deadline and 120-second runtime, with
bounded configuration ceilings. The remote microVM lifetime and the host's
independent deletion lease are required because a local watchdog does not
survive a crashed process. If deletion cannot be confirmed, it raises; operators
must check and remove the disposable instance. Boolean preflight fields are
**claims from the injected backend**, not an attestation furnished by this
module: trusting an unverified callback would not be secure.

**Not ready for untrusted end-to-end scans:** `jobs.run_scan_job` currently calls
`make_runner` without injecting any backend, so environment-only opt-in always
fails closed. Moreover `finder.remediate.remediate()` runs a patched copy as a
*local subprocess*; the full proof loop must route **all** target execution,
including re-exploitation, through a disposable host before accepting arbitrary
repos. Wiring a real authenticated VX1/guest transport, resource enforcement,
private forwarding and policy probes is future integration work; neither
Microsandbox's sibling isolation demo nor this adapter proves those properties.

## Test

```sh
.venv/bin/python -m pytest test_finder.py test_target_runner.py -q
```

Covers acceptance criteria that don't need the sandbox host: seeded SQLi confirmed
via canary (#1), path traversal confirmed via a file-canary, clean target →
coverage with zero false positives (#2), and every finding carrying the full proof
chain (#5). `test_target_runner.py` also mocks Microsandbox preflight, limits,
startup expiry, private URL and cleanup paths. Runs offline — no key or VM.

## Status

- **Working end-to-end today:** recon, AST static sweep (plus an IDOR/auth
  heuristic), triage (Vultr Inference + offline fallback), HTTP confirmers for
  **all five classes** — SQLi, path traversal, command injection, SSRF, and
  auth-bypass/IDOR — canary oracle, coverage report, CLI, and the remediation
  proof loop that patches each and certifies it closed.
- **Next:** model-written patches for arbitrary (non-seeded) code shapes; wire in
  sqlmap/nuclei/ZAP as richer confirmers when the sandbox host has them; the
  plant-and-catch safety-net mode; the recall/false-positive benchmark vs Vulnhuntr.

## Handoff to the proof loop

Each confirmed `Finding` carries `input_to_sink`, `sink_file`/`sink_line`,
`exploit_request`, `confirming_output` (redacted canary proof), and `fix` — exactly
what patch (writes the fix), re-exploit (replays attack + mutations), and test (runs
the repo suite) need. A second model should validate the fix so the writer never
certifies its own work.

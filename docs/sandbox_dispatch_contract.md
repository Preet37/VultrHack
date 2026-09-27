# Sandbox dispatch contract (issue #16)

**For:** the sandbox-host lane (Sasha). **Depends on nothing new from the finder lane** — the seam is already merged (`finder/target_runner.py`, PR #15) and waiting.

## One sentence

The finder needs one function: *given a target app's source, run it inside a disposable gVisor sandbox and hand back a URL I can attack plus a way to destroy it.* Implement that one function and the finder runs its whole exploit→patch→re-prove loop **inside the throwaway VM** instead of on the control host.

## The function to implement

```python
def dispatch(source_dir: str, entrypoint: str) -> tuple[str, Callable[[], None]]:
    ...
```

- **`source_dir`** — a local path on the control plane holding the target app (e.g. `targets/seeded_flask`). It contains `entrypoint` (a Python file), a `requirements.txt`, and a `manifest.json`. The app reads its port from the `PORT` env var and serves `GET /health` → `200` when ready.
- **`entrypoint`** — the file to run, e.g. `"app.py"`. Start it like `python <entrypoint>` with `PORT` set.
- **Returns `(base_url, teardown)`**:
  - **`base_url`** — an `http://HOST:PORT` string the **control plane can reach over the private network** (VPC / NetBird), where the app is already answering `GET /health` with `200`. Do not return until it's healthy (mirror the local runner, which waits for health before handing back the URL).
  - **`teardown`** — a zero-arg callable that destroys the sandbox. Must be **idempotent and safe to call even if startup half-failed** (the finder calls it in a `finally`, always).

## Hard requirements

1. **The app runs inside a disposable gVisor sandbox on the sandbox host** — never on the control plane. This is the whole point (rubric criterion 4: "if I paste `rm -rf /`, what dies?" → the throwaway sandbox, nothing else).
2. **Copy the app's source + install its `requirements.txt` into the sandbox**, then run `entrypoint`. Only *execution* moves into the sandbox — static analysis and patching stay on the control plane against the local `source_dir`, so you don't need to send anything back except the reachable URL.
3. **Strip `CERBERUS_*` env vars** from the app's environment (so it plants its manifest-default canaries), and **set `PORT`**. This matches `finder/remediate.py:_start_target`.
4. **No Vultr keys, control token, or inference key** ever enter the sandbox.
5. **On any failure, raise** (don't return a dead URL). The seam treats a raise as "fail closed."
6. **`teardown` destroys the sandbox** (and confirms it — a 404 on the instance, like the smoke job already does).

## Where it plugs in (already built, don't touch)

```python
# finder/target_runner.py — already merged
SandboxTargetRunner(source_dir, entrypoint, dispatch=<your function>)
# selected at runtime by:  CERBERUS_SCAN_RUNNER=sandbox
```

`make_runner()` reads `CERBERUS_SCAN_RUNNER`; today `sandbox` mode fails closed because no `dispatch` is injected. The only wiring left is: construct `SandboxTargetRunner` with your `dispatch` where the scan job builds its runner, and pass the sandbox-mode selection through.

## Build on what you already have

Your `run_sandbox_smoke_job` (jobs.py) + VPC mode already: provision a disposable VX1, boot gVisor + OpenSandbox, run a command, prove isolation, destroy it. This contract is the same lifecycle with two changes: **(a)** the "command" becomes "install deps + run this web app", and **(b)** you expose its port as a private-network URL and keep the sandbox alive until `teardown()` instead of running one command and exiting.

## Done when (acceptance test)

With `CERBERUS_ENABLE_LOCAL_SCAN_JOBS=true` **not** required (this is the safe path), run a scan in sandbox mode:

```
CERBERUS_SCAN_RUNNER=sandbox  →  POST /jobs {"type":"scan","target":"seeded_flask"}
```

Passes when: the target app executes **inside the sandbox** (not the control host), the scan returns **5 confirmed / 5 certified**, `triage_source` is the live Vultr model, and the sandbox is **destroyed afterward** (instance 404, none remain). That closes issue #16 and rubric criterion 4 for the finder path.

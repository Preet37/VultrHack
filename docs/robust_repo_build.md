# Robust per-repo build — scanning ANY GitHub repo in the sandbox

## Why tier-1 isn't enough
The tier-1 demo runner (`_LenientRunner` + `_build_venv` in `demo_server.py`) runs a cloned
repo in a per-repo venv on the control host's Python. It works for well-formed modern repos
(e.g. our `ticketflow`), but real-world repos fail on:
- **pinned/old deps** (flask-webgoat → Flask 1.1.2, bad_python_extract → Flask 0.12) that
  won't install on the host Python;
- **no `app.run()`** (they expect `flask run` / gunicorn) or a **hardcoded port**;
- deps **not in `requirements.txt`** (imported ad-hoc).

These are environment problems, and the fix is to give each repo its **own environment** — a
container image — which is exactly what Sasha's `sandbox_scan` already does for seeded targets.

## The robust path (extend `sandbox_scan`)
Given a cloned repo directory, build and run a disposable per-repo image under gVisor:

1. **Detect the run recipe**
   - Python version: `runtime.txt` / `.python-version` / `pyproject.toml` (`requires-python`) / default `3.11`.
   - Entrypoint: `app.py` / `wsgi.py` / `run.py` / `main.py`, or a module exposing a Flask `app`.
   - Start command, in order of preference: `gunicorn <module>:app`, else `flask --app <module> run`, else `python <entrypoint>` — always bound to `0.0.0.0:$PORT`.

2. **Build the image** (in the sandbox host, under `runc`; the same build path `sandbox_scan`
   already uses):
   ```dockerfile
   FROM python:{detected}-slim
   WORKDIR /app
   COPY . /app
   RUN pip install --no-input -r requirements.txt || pip install --no-input flask requests gunicorn
   ENV PORT=8081
   CMD ["sh","-c","gunicorn -b 0.0.0.0:$PORT $MODULE:app || flask --app $MODULE run -h 0.0.0.0 -p $PORT || python $ENTRY"]
   ```
   The image **pins the repo's Python + deps**, so ancient pins and missing deps stop mattering.

3. **Run under gVisor** — `docker run --runtime=runsc` on the `cerberus-internal` VPC bridge,
   bound to the guest VPC IPv4, egress default-deny (the existing iptables drop-probe policy).

4. **Health-prove** over the VPC (`/` or `/health`), then the control VM runs the finder over
   the private network. No-manifest repos use the **environmental canaries** (`finder/env_canary.py`)
   to confirm path-traversal / SSRF / command-injection.

5. **Destroy** the container + image; the instance returns 404; the receipt is sealed.

## The seam
This slots into `finder/target_runner.py::SandboxTargetRunner` — inject a `dispatch(source_dir,
entrypoint) -> (base_url_over_vpc, teardown)` that does steps 2–5. `make_runner(mode="sandbox",
dispatch=...)` already routes to it; nothing in the find/prove/patch/certify logic changes.

## Speed — why the SCAN is quick even on a big repo
The **scan** (find → prove → fix → re-prove) is seconds because it is **dynamic**: it sends a
handful of HTTP probes at the *running* app and checks whether a canary crossed a boundary —
it does **not** statically parse the whole codebase, so a 100k-line repo scans as fast as a
100-line one. Triage is one call to Vultr's **`deepseek-v4-flash`** (~1s), and the deterministic
patches are instant. The only slow part is the **first image build** (pip install); it is cached
per repo, so re-runs are fast. For the demo, a pre-built/warm image makes the whole loop feel instant.

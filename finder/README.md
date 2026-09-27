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

## Test

```sh
.venv/bin/python -m pytest test_finder.py -q
```

Covers acceptance criteria that don't need the sandbox host: seeded SQLi confirmed
via canary (#1), path traversal confirmed via a file-canary, clean target →
coverage with zero false positives (#2), and every finding carrying the full proof
chain (#5). Runs offline — no key, no external tools.

## Status

- **Working end-to-end today:** recon, AST static sweep, triage (Vultr Inference +
  offline fallback), HTTP confirmers for **SQLi** and **path traversal**, canary
  oracle, coverage report, CLI. 5/5 tests green.
- **Next:** confirmers for command injection / SSRF / auth-bypass; wire in
  sqlmap/nuclei/ZAP as richer confirmers when the sandbox host has them; the
  plant-and-catch safety-net mode; the recall/false-positive benchmark vs Vulnhuntr.

## Handoff to the proof loop

Each confirmed `Finding` carries `input_to_sink`, `sink_file`/`sink_line`,
`exploit_request`, `confirming_output` (redacted canary proof), and `fix` — exactly
what patch (writes the fix), re-exploit (replays attack + mutations), and test (runs
the repo suite) need. A second model should validate the fix so the writer never
certifies its own work.

"""The finder pipeline: recon -> static sweep -> triage -> confirm.

Wrapped in a plan-act-observe loop with a step budget and a wall-clock cap so it
cannot run away on stage. Produces confirmed findings plus an honest coverage
report. A clean run reports coverage, never "this code is safe".
"""

from __future__ import annotations

import time

from finder import confirm as confirm_mod
from finder.inference import InferenceClient
from finder.models import Coverage, FinderReport, Finding
from finder.playbooks import confirmer_for
from finder.recon import canaries_for, recon
from finder.static_sweep import sweep
from finder.triage import CONFIDENCE_THRESHOLD, triage


def run_finder(
    base_url: str,
    source_dir: str | None = None,
    *,
    max_steps: int = 20,
    wall_clock_seconds: float = 90.0,
    client: InferenceClient | None = None,
) -> FinderReport:
    started = time.monotonic()
    client = client or InferenceClient()

    # 1) Recon.
    routes, manifest = recon(base_url, source_dir)
    canaries = canaries_for(manifest)
    route_dicts = [r.to_dict() for r in routes]

    # 2) Static sweep (needs source; without it we can only test manifest routes).
    candidates = sweep(source_dir) if source_dir else []
    by_id = {c.id: c for c in candidates}

    # 3) Triage (Vultr Serverless Inference, or offline heuristic).
    plan, triage_source = triage(candidates, route_dicts, client=client)

    # 4) Confirm loop with budgets.
    findings: list[Finding] = []
    tested_classes: set[str] = set()
    tested_endpoints: set[str] = set()
    steps = 0
    tested = 0
    for item in plan:
        if steps >= max_steps or (time.monotonic() - started) >= wall_clock_seconds:
            break
        if item.confidence < CONFIDENCE_THRESHOLD:
            continue
        candidate = by_id.get(item.candidate_id)
        if candidate is None:
            continue
        # Only count a class/endpoint as tested when a confirmer can actually
        # fire at it. Otherwise coverage would claim we tested a class we never
        # sent a single request for -- the dishonesty this report exists to avoid.
        if confirmer_for(item.vuln_class) is None:
            continue
        steps += 1
        tested += 1
        tested_classes.add(item.vuln_class)
        tested_endpoints.add(item.endpoint)
        finding = confirm_mod.confirm(item, candidate, base_url, canaries)
        if finding is not None and not any(f.id == finding.id for f in findings):
            findings.append(finding)

    coverage = Coverage(
        classes_tested=sorted(tested_classes),
        endpoints_tested=sorted(tested_endpoints),
        candidates_seen=len(candidates),
        candidates_tested=tested,
        # Every class we had a candidate for but did not actually exercise (no
        # confirmer, below the confidence threshold, or cut off by the budget).
        not_reached=sorted({c.vuln_class for c in candidates} - tested_classes),
        steps_used=steps,
        wall_clock_seconds=round(time.monotonic() - started, 2),
    )
    return FinderReport(target=base_url, findings=findings, coverage=coverage, triage_source=triage_source)

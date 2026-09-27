"""Confirm: fire the matching tool at one candidate, let the oracle judge.

No finding without a proof. This module fires the class confirmer and only
returns a Finding when the canary was observed leaving the box. A miss returns
None, and the pipeline sends the candidate back for another vector.
"""

from __future__ import annotations

from finder import canary as canary_oracle
from finder.models import Candidate, Finding, TestPlanItem
from finder.playbooks import FIXES, confirmer_for


def confirm(
    item: TestPlanItem,
    candidate: Candidate,
    base_url: str,
    canaries: list[str],
    timeout: float = 12.0,
    env_payloads: dict[str, list[str]] | None = None,
) -> Finding | None:
    confirmer = confirmer_for(item.vuln_class)
    if confirmer is None:
        return None  # class has no HTTP confirmer yet; not reported without proof
    # Environmental (sandbox-planted) payloads for a manifest-less target, keyed
    # by class. None on the seeded (manifest) path -> confirmers behave exactly
    # as before, so seeded runs are unaffected.
    extra = (env_payloads or {}).get(item.vuln_class)
    result = confirmer(base_url, item.endpoint, f"{item.param}", timeout, extra_payloads=extra)
    if not result.fired:
        return None
    # Let the oracle attribute the leak to the exact request that carried the
    # canary out, so the reported exploit is the one that actually worked -- not
    # merely the last payload fired.
    canary = win_request = win_text = None
    for request, text in result.attempts:
        canary = canary_oracle.first_match(canaries, text)
        if canary is not None:
            win_request, win_text = request, text
            break
    if canary is None:
        canary = canary_oracle.first_match(canaries, result.observable, result.response_text)
        if canary is None:
            return None
        win_request, win_text = result.exploit_request, result.response_text
    return Finding(
        id=candidate.id,
        vuln_class=item.vuln_class,
        endpoint=item.endpoint,
        param=item.param,
        input_to_sink=f"{candidate.input_source} -> {candidate.sink_symbol}() in {candidate.sink_file}:{candidate.sink_line}",
        sink_file=candidate.sink_file,
        sink_line=candidate.sink_line,
        exploit_request=win_request,
        confirming_output=canary_oracle.excerpt(canary, win_text, result.observable, result.response_text),
        canary_observed=True,
        canary_value=canary[:6] + "…",
        fix=FIXES.get(item.vuln_class, ""),
        confirmer=item.tool,
        triage_source=item.source,
    )

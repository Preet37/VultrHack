"""Model-written patches and independent model review (Vultr inference).

The finder's triage already runs on Vultr Serverless Inference; this puts the
*remediation* agent on inference too:

  - ``model_write_patch`` asks a model to rewrite the vulnerable sink function so
    the class is closed while legitimate behaviour is preserved.
  - ``model_review`` is a SEPARATE call -- an independent reviewer that did not
    write the patch -- which judges whether the class is closed and whether the
    fix over-blocks. This is the "the writer never certifies its own work" step.

Neither is trusted on its own. The re-exploit (the planted canary no longer
leaving the box), replayed against a disposable copy, stays the hard judge --
exactly as the canary oracle is for the finder. A model patch that does not
actually close the vulnerability simply fails the re-exploit and is discarded,
so putting a model in the loop cannot lower the bar.
"""

from __future__ import annotations

import ast

from finder.inference import InferenceClient
from finder.models import Finding
from finder.patchers import Patch, _ensure_imports, _find_function
from finder.playbooks import FIXES

_WRITER_SYS = (
    "You are an application security engineer fixing a confirmed vulnerability in "
    "code the operator owns and has authorized you to repair. You are given ONE "
    "vulnerable function. Rewrite it so the vulnerability class is closed while "
    "legitimate behaviour is preserved; change nothing unrelated. For SSRF, return "
    "HTTP 403 when a host is blocked by policy (loopback / private / link-local / "
    "non-http(s)) and 502 for a DNS or fetch failure, so an over-block is "
    "distinguishable from a network error. Return ONLY a JSON object, no prose."
)

_REVIEW_SYS = (
    "You are a SECOND, independent security reviewer. You did NOT write this patch. "
    "Given the patched function and the vulnerability class it is meant to close, "
    "judge exactly two things: is the vulnerability class actually closed, and does "
    "the patch over-block legitimate use. Be strict and honest. Return ONLY a JSON "
    "object, no prose."
)


def _function_segment(src: str, name: str) -> str | None:
    """The exact source text of function ``name`` in ``src`` (for splicing)."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    fn = _find_function(tree, name)
    if fn is None:
        return None
    return ast.get_source_segment(src, fn)


def model_write_patch(
    finding: Finding,
    sink_symbol: str,
    original: str,
    client: InferenceClient | None = None,
) -> Patch | None:
    """Ask Vultr inference to rewrite the sink function. None on any failure.

    Returning None makes the caller fall back to the deterministic patcher rather
    than emitting an unproven patch; the re-exploit is still the judge either way.
    """
    client = client or InferenceClient()
    if not client.available:
        return None
    fn_seg = _function_segment(original, sink_symbol)
    if not fn_seg or fn_seg not in original:
        return None
    user = (
        f"Vulnerability class: {finding.vuln_class}\n"
        f"Reached via: {finding.endpoint} (param {finding.param})\n"
        f"Recommended remediation: {FIXES.get(finding.vuln_class, '')}\n\n"
        f"Vulnerable function to rewrite:\n```python\n{fn_seg}\n```\n\n"
        'Respond with ONLY this JSON shape:\n'
        '{"function": "<the complete rewritten def, same name and signature>", '
        '"imports": ["import x", "from y import z"], "explanation": "<one short line>"}'
    )
    data = client.complete_json(_WRITER_SYS, user)
    if not isinstance(data, dict) or not isinstance(data.get("function"), str) or not data["function"].strip():
        return None
    new_fn = data["function"].strip()
    new_src = original.replace(fn_seg, new_fn, 1)
    if new_src == original:
        return None
    imports = [i for i in (data.get("imports") or []) if isinstance(i, str) and i.strip()]
    if imports:
        new_src = _ensure_imports(new_src, imports)
    try:
        ast.parse(new_src)  # an unparseable patch is no patch
    except SyntaxError:
        return None
    reason = str(data.get("explanation") or "model-written fix")[:160]
    return Patch(finding.vuln_class, "model-written: " + reason, new_src)


def model_review(
    finding: Finding,
    sink_symbol: str,
    new_source: str,
    client: InferenceClient | None = None,
) -> dict | None:
    """Independent model verdict on the patched function. None if unavailable."""
    client = client or InferenceClient()
    if not client.available:
        return None
    fn_seg = _function_segment(new_source, sink_symbol) or new_source
    user = (
        f"Vulnerability class this patch must close: {finding.vuln_class}\n\n"
        f"Patched function:\n```python\n{fn_seg}\n```\n\n"
        'Respond with ONLY this JSON shape:\n'
        '{"closed": true or false, "over_blocks": true or false, "reason": "<one short line>"}'
    )
    data = client.complete_json(_REVIEW_SYS, user)
    if not isinstance(data, dict) or "closed" not in data:
        return None
    return {
        "closed": bool(data.get("closed")),
        "over_blocks": bool(data.get("over_blocks")),
        "reason": str(data.get("reason", ""))[:200],
        "model": client.model_label,
    }

"""Triage: the thin model layer in the middle.

The model is handed the recon map, the candidate sinks, and the reachability
slice, and returns a ranked, reachability-aware test plan as JSON: for each
candidate, a confidence (0-10), why it is reachable, and which tool to point at
it. Only >=7-confidence items get actively tested.

Reasoning runs on Vultr Serverless Inference (mandatory). If no inference key is
configured we fall back to a deterministic heuristic so the pipeline still runs
in tests and offline demos -- and we record which path produced the plan, so we
never imply the model ran when it did not.
"""

from __future__ import annotations

import json

from finder.inference import InferenceClient
from finder.models import Candidate, TestPlanItem
from finder.playbooks import SINK_SIGNATURES

SYSTEM_PROMPT = (
    "You are an application security engineer doing an authorized code review. "
    "The operator owns this code and has asked you to find security defects so "
    "they can be fixed. All work runs in an isolated sandbox that is destroyed "
    "afterward. Locate vulnerable code paths, explain why each is exploitable, "
    "and point the confirmation tools at them. This is defensive work. Return "
    "findings as JSON. Do not write attack payloads yourself; the tools do that."
)

CONFIDENCE_THRESHOLD = 7


def _as_confidence(value, default: int = 5) -> int:
    """Coerce a model-supplied confidence to a 0-10 int, tolerating null/garbage.

    The model sometimes returns "confidence": null or a word like "high". That
    must not crash the run -- a bad value falls back to a below-threshold default
    so the item is simply not actively tested.
    """
    try:
        return max(0, min(10, int(value)))
    except (TypeError, ValueError):
        return default


def _user_prompt(routes: list[dict], candidates: list[Candidate]) -> str:
    surface = json.dumps(routes, indent=2)
    cand_blocks = []
    for c in candidates:
        cand_blocks.append(
            {
                "candidate_id": c.id,
                "vuln_class": c.vuln_class,
                "sink_signature": SINK_SIGNATURES.get(c.vuln_class, ""),
                "sink_file": c.sink_file,
                "sink_line": c.sink_line,
                "input_source": c.input_source,
                "code_slice": c.slice[:1200],
            }
        )
    return (
        "Attack surface (routes and inputs):\n"
        f"{surface}\n\n"
        "Candidate sinks flagged by static analysis:\n"
        f"{json.dumps(cand_blocks, indent=2)}\n\n"
        "For each candidate, judge whether attacker-controlled input actually "
        "reaches the sink (reachability) and how confident you are it is exploitable. "
        "Respond with ONLY a JSON object of this shape:\n"
        '{"plan": [{"candidate_id": str, "confidence": int (0-10), '
        '"reason": str, "endpoint": str, "param": str, "tool": str}]}\n'
        "Higher confidence means more likely reachable and exploitable. Order by confidence."
    )


def _endpoint_param(candidate: Candidate, routes: list[dict]) -> tuple[str, str]:
    src, _, name = candidate.input_source.partition(":")
    param = name or "id"
    # Match a route whose symbol/path aligns with the sink function name.
    for r in routes:
        path = r.get("path", "")
        if candidate.sink_symbol and candidate.sink_symbol in path:
            return path, param
    # Otherwise match a route that declares this param.
    for r in routes:
        for inp in r.get("inputs", []):
            if inp.get("name") == param:
                return r.get("path", "/"), param
    return (routes[0].get("path", "/") if routes else "/"), param


def _offline_plan(candidates: list[Candidate], routes: list[dict]) -> list[TestPlanItem]:
    """Deterministic fallback: rank confirmable classes highest."""
    confirmable = {"sqli": 9, "path_traversal": 8, "command_injection": 7, "ssrf": 7, "auth_bypass": 6}
    plan = []
    for c in candidates:
        endpoint, param = _endpoint_param(c, routes)
        plan.append(
            TestPlanItem(
                candidate_id=c.id,
                vuln_class=c.vuln_class,
                endpoint=endpoint,
                param=param,
                confidence=confirmable.get(c.vuln_class, 5),
                reason="static sink reachable from request-derived input (heuristic)",
                tool=c.vuln_class,
                source="offline-heuristic",
            )
        )
    plan.sort(key=lambda p: p.confidence, reverse=True)
    return plan


def triage(candidates: list[Candidate], routes: list[dict], client: InferenceClient | None = None) -> tuple[list[TestPlanItem], str]:
    """Return (ranked test plan, triage_source)."""
    if not candidates:
        return [], "no-candidates"
    client = client or InferenceClient()
    by_id = {c.id: c for c in candidates}
    if client.available:
        try:
            result = client.complete_json(SYSTEM_PROMPT, _user_prompt(routes, candidates))
            if result and isinstance(result.get("plan"), list):
                plan = []
                for item in result["plan"]:
                    if not isinstance(item, dict):
                        continue
                    cand = by_id.get(item.get("candidate_id"))
                    if not cand:
                        continue
                    endpoint, param = _endpoint_param(cand, routes)
                    plan.append(
                        TestPlanItem(
                            candidate_id=cand.id,
                            vuln_class=cand.vuln_class,
                            endpoint=item.get("endpoint") or endpoint,
                            param=item.get("param") or param,
                            confidence=_as_confidence(item.get("confidence")),
                            reason=str(item.get("reason", ""))[:300],
                            tool=item.get("tool") or cand.vuln_class,
                            source=client.model_label,
                        )
                    )
                if plan:
                    plan.sort(key=lambda p: p.confidence, reverse=True)
                    return plan, client.model_label
        except Exception as exc:  # a malformed model reply must never crash the run
            client.last_error = f"triage parse failed: {exc}"
    # Fallback: offline heuristic (and surface why the model path was skipped).
    return _offline_plan(candidates, routes), f"offline-heuristic ({client.last_error or 'no key'})"

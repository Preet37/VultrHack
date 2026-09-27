"""The canary oracle: the environment decides, never the model.

A finding is confirmed only when the exact planted canary is observed leaving
the box -- here, appearing in what the target returned to the finder. In the
full system the same check runs against the egress sink's log of every outbound
byte. Either way, a real exploit is the only thing that could have carried the
canary out, which drives false positives to zero by construction.
"""

from __future__ import annotations


def observed(canary: str, *outputs: str) -> bool:
    """True iff the canary string appears in any observable output."""
    if not canary:
        return False
    return any(canary in (text or "") for text in outputs)


def first_match(canaries: list[str], *outputs: str) -> str | None:
    """Return the first canary observed leaving the box, or None."""
    for canary in canaries:
        if canary and any(canary in (text or "") for text in outputs):
            return canary
    return None


def redact(canary: str, text: str, keep: int = 6) -> str:
    """Show that the canary fired without printing the whole secret in reports."""
    if not canary or canary not in text:
        return text
    shown = canary[:keep] + "…"
    return text.replace(canary, f"<CANARY {shown} OBSERVED>")


def excerpt(canary: str, *texts: str, window: int = 160) -> str:
    """Return a redacted snippet centered on the canary from the first text that carries it.

    The confirmer stays canary-agnostic (it just fires real payloads); the oracle
    picks the response that actually leaked the secret and produces the proof shown
    in the report.
    """
    for text in texts:
        if text and canary and canary in text:
            idx = text.index(canary)
            lo = max(0, idx - window)
            hi = min(len(text), idx + len(canary) + window)
            return redact(canary, text[lo:hi]).strip()
    # No leak: return the first non-empty observable so the report still shows what was tried.
    return next((t[:window] for t in texts if t), "")

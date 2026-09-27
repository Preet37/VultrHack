"""Structured types shared across the finder pipeline.

Everything the finder emits is JSON-serializable so a finding can be handed
straight to the proof loop (exploit -> patch -> re-exploit -> test) and pinned
into a signed receipt.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

# Vulnerability classes we support. Depth over breadth: exploitable over HTTP
# and visible in a demo. Nothing else is in scope.
SUPPORTED_CLASSES = ("sqli", "command_injection", "ssrf", "path_traversal", "auth_bypass")


@dataclass
class Route:
    """A reachable HTTP entry point discovered during recon."""

    method: str
    path: str
    inputs: list[dict] = field(default_factory=list)  # [{"name","source"}]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Candidate:
    """A candidate sink flagged by the static sweep, before confirmation."""

    id: str
    vuln_class: str
    sink_file: str
    sink_line: int
    sink_symbol: str
    snippet: str
    input_source: str  # e.g. "query:id"
    slice: str = ""  # reachability slice: input source -> sink call chain

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TestPlanItem:
    """The model's triage output for one candidate: what to test and how."""

    candidate_id: str
    vuln_class: str
    endpoint: str
    param: str
    confidence: int  # 0-10; only >=7 gets actively tested
    reason: str
    tool: str  # which confirmer to point at it
    source: str = "offline-heuristic"  # or "vultr-inference:<model>"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    """A CONFIRMED, exploitable finding. Only emitted when the canary fired."""

    id: str
    vuln_class: str
    endpoint: str
    param: str
    input_to_sink: str  # human-readable chain: input source -> sink
    sink_file: str
    sink_line: int
    exploit_request: str  # the exact request the tool fired
    confirming_output: str  # observable proof (response / tool output excerpt)
    canary_observed: bool
    canary_value: str
    fix: str
    confirmer: str
    triage_source: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Coverage:
    """Honest accounting of what ran. A clean run reports coverage, not safety."""

    classes_tested: list[str] = field(default_factory=list)
    endpoints_tested: list[str] = field(default_factory=list)
    candidates_seen: int = 0
    candidates_tested: int = 0
    not_reached: list[str] = field(default_factory=list)
    steps_used: int = 0
    wall_clock_seconds: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FinderReport:
    """The full result of a finder run."""

    target: str
    findings: list[Finding]
    coverage: Coverage
    triage_source: str

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "triage_source": self.triage_source,
            "findings": [f.to_dict() for f in self.findings],
            "coverage": self.coverage.to_dict(),
            "summary": (
                f"{len(self.findings)} confirmed finding(s) in classes tested "
                f"({', '.join(self.coverage.classes_tested) or 'none'}); "
                "no exploit found does not mean the code is safe."
            ),
        }

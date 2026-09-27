"""Gauntlet benchmark tests.

Asserts the safety gate catches 100% of the adversarial ROGUE patches and
produces ZERO false positives on the finder's real LEGIT fixes, and that the
scorecard the demo reads is internally consistent.
"""

from __future__ import annotations

import json
from pathlib import Path

from finder.gauntlet_cases import GAUNTLET_CASES, LEGIT_CASES, ROGUE_CASES
from finder.safety_gate import safety_gate
from gauntlet import RESULTS_PATH, run_gauntlet


def test_gauntlet_has_rogue_and_legit_cases():
    assert len(ROGUE_CASES) >= 12, "need ~12 adversarial rogue cases"
    assert len(LEGIT_CASES) == 5, "the 5 real seeded_flask fixes must be present"
    assert all(c["should_reject"] for c in ROGUE_CASES)
    assert all(not c["should_reject"] for c in LEGIT_CASES)


def test_every_rogue_class_is_covered():
    covered = {c["vuln_class"] for c in ROGUE_CASES}
    assert {"sqli", "command_injection", "ssrf", "path_traversal", "auth_bypass"} <= covered


def test_gauntlet_catches_all_rogue_and_no_false_positives():
    summary = run_gauntlet()
    assert summary["catch_rate"] == 1.0, ("missed rogue cases", summary["missed_rogue"])
    assert summary["rogue_caught"] == summary["rogue_total"]
    assert summary["false_positives"] == 0, ("false positives", summary["false_positive_cases"])
    assert summary["false_positive_rate"] == 0.0
    assert summary["legit_passed"] == summary["legit_total"]
    # The naive baseline (no gate) catches nothing -- the gate beats it outright.
    assert summary["naive_catch_rate"] == 0.0
    assert summary["catch_rate"] > summary["naive_catch_rate"]


def test_gauntlet_writes_results_json():
    run_gauntlet()
    assert RESULTS_PATH.exists()
    data = json.loads(Path(RESULTS_PATH).read_text())
    assert data["total"] == len(GAUNTLET_CASES)
    assert data["catch_rate"] == 1.0


def test_each_rogue_individually_rejected():
    for case in ROGUE_CASES:
        assert safety_gate(case["diff"]).ok is False, f"rogue not caught: {case['id']}"


def test_each_legit_individually_passes():
    for case in LEGIT_CASES:
        result = safety_gate(case["diff"])
        assert result.ok is True, f"legit falsely rejected: {case['id']} -> {result.hits}"

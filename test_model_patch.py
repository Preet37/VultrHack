"""Offline tests for the model-written patch + independent review (finder/model_patch.py).

These use a stub inference client so the model-patch logic (splicing, parse
rejection, review shape) is covered deterministically without a live call. The
live path is exercised separately against Vultr inference.
"""

from __future__ import annotations

import ast
from pathlib import Path

from finder.model_patch import model_review, model_write_patch
from finder.models import Finding
from finder.patchers import patch_source


class StubClient:
    def __init__(self, data, available=True):
        self._data = data
        self.available = available
        self.model_label = "stub:model"

    def complete_json(self, system, user):
        return self._data


SRC = (
    "import sqlite3\n\n"
    "def product():\n"
    '    pid = request.args.get("id")\n'
    '    q = "SELECT * FROM products WHERE id = " + pid\n'
    "    return conn.execute(q).fetchall()\n"
)

FIND = Finding(
    id="x", vuln_class="sqli", endpoint="/product", param="id",
    input_to_sink="request.args -> product()", sink_file="app.py", sink_line=1,
    exploit_request="GET /product?id=1", confirming_output="", canary_observed=True,
    canary_value="", fix="", confirmer="", triage_source="",
)

FIXED_FN = (
    "def product():\n"
    '    pid = request.args.get("id")\n'
    '    return conn.execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchall()'
)


def test_model_write_patch_splices_the_function():
    patch = model_write_patch(FIND, "product", SRC, client=StubClient(
        {"function": FIXED_FN, "imports": [], "explanation": "parameterized query"}))
    assert patch is not None
    assert "?" in patch.new_source and '+ pid' not in patch.new_source
    ast.parse(patch.new_source)  # the spliced result must parse
    assert patch.description.startswith("model-written:")


def test_model_write_patch_none_without_inference_key():
    assert model_write_patch(FIND, "product", SRC, client=StubClient({}, available=False)) is None


def test_model_write_patch_rejects_unparseable_output():
    assert model_write_patch(FIND, "product", SRC, client=StubClient(
        {"function": "def product(:\n    broken", "imports": [], "explanation": "x"})) is None


def test_model_write_patch_rejects_missing_function_field():
    assert model_write_patch(FIND, "product", SRC, client=StubClient({"explanation": "no function"})) is None


def test_model_review_returns_verdict_shape():
    r = model_review(FIND, "product", SRC, client=StubClient(
        {"closed": True, "over_blocks": False, "reason": "parameterized"}))
    assert r["closed"] is True and r["over_blocks"] is False and r["model"] == "stub:model"


def test_model_review_none_without_key():
    assert model_review(FIND, "product", SRC, client=StubClient({}, available=False)) is None


def test_ssrf_patch_uses_403_for_policy_block():
    # #13: the SSRF guard must return 403 for a policy block (distinct from a 502
    # network failure) so a functional check can detect over-blocking.
    src = (Path(__file__).parent / "targets" / "seeded_flask" / "app.py").read_text()
    patch = patch_source("ssrf", "fetch", src)
    assert patch is not None
    assert "status=403" in patch.new_source
    assert "is_private" in patch.new_source and "is_loopback" in patch.new_source

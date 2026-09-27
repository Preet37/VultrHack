"""Proof-loop acceptance tests: patch a confirmed finding and prove it is closed.

Covers the finder.md handoff: exploit -> patch -> re-exploit -> validate, plus a
generated regression test. The seeded Flask app is served on a free port so the
finder produces real confirmed findings; remediate() then patches a disposable
copy and re-exploits it.
"""

from __future__ import annotations

import importlib.util
import sys
import threading
import time
from pathlib import Path
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import pytest


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True  # so SSRF self-fetch (a nested request) is not deadlocked

ROOT = Path(__file__).parent
SEEDED = ROOT / "targets" / "seeded_flask" / "app.py"

pytest.importorskip("flask", reason="target app needs Flask installed")

from finder.models import Finding  # noqa: E402
from finder.patchers import patch_source  # noqa: E402
from finder.pipeline import run_finder  # noqa: E402
from finder.remediate import _validate, free_port, remediate  # noqa: E402


def _pt_finding() -> Finding:
    return Finding(
        id="pt", vuln_class="path_traversal", endpoint="/download", param="file",
        input_to_sink="args:file -> download() in app.py:1", sink_file="app.py", sink_line=1,
        exploit_request="GET x", confirming_output="", canary_observed=True, canary_value="",
        fix="", confirmer="", triage_source="",
    )


def _load_seeded_app():
    spec = importlib.util.spec_from_file_location("seeded_app_r", SEEDED)
    module = importlib.util.module_from_spec(spec)
    sys.modules["seeded_app_r"] = module
    spec.loader.exec_module(module)
    return module


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def findings():
    module = _load_seeded_app()
    app = module.create_app()
    port = free_port()
    server = make_server("127.0.0.1", port, app, server_class=_ThreadingWSGIServer, handler_class=_QuietHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    import httpx

    for _ in range(50):
        try:
            httpx.get(f"http://127.0.0.1:{port}/health", timeout=1.0)
            break
        except Exception:
            time.sleep(0.05)
    report = run_finder(f"http://127.0.0.1:{port}", str(SEEDED.parent), wall_clock_seconds=30)
    server.shutdown()
    return report.findings, str(SEEDED.parent)


def _one(findings, vuln_class):
    return next(f for f in findings[0] if f.vuln_class == vuln_class)


ALL_CLASSES = ["sqli", "path_traversal", "command_injection", "ssrf", "auth_bypass"]


@pytest.mark.parametrize("vuln_class", ALL_CLASSES)
def test_each_class_patch_is_certified_closed(findings, vuln_class):
    finding = _one(findings, vuln_class)
    result = remediate(finding, findings[1])
    assert result.patched is True, (vuln_class, result.validation_notes)
    assert result.reexploit_blocked is True, (vuln_class, result.reexploit_evidence)
    assert result.validated is True, (vuln_class, result.validation_notes)
    assert result.certified is True, (vuln_class, result.reexploit_evidence, result.validation_notes)
    assert result.patch_diff  # a real diff was produced


def test_regression_test_is_emitted(findings):
    finding = _one(findings, "sqli")
    result = remediate(finding, findings[1])
    assert "def test_" in result.regression_test
    assert "CANARY_MARKERS" in result.regression_test
    assert finding.endpoint in result.regression_test


def test_patch_actually_parameterizes_sql():
    # The patcher turns concatenation into a bound parameter, and the result parses.
    src = (
        "import sqlite3\n"
        "def product(product_id, conn):\n"
        '    query = "SELECT id FROM products WHERE id = " + product_id\n'
        "    return conn.execute(query).fetchall()\n"
    )
    patch = patch_source("sqli", "product", src)
    assert patch is not None
    assert "+ product_id" not in patch.new_source
    assert "(product_id,)" in patch.new_source


def test_no_patch_when_shape_unrecognized():
    # A safe, parameterized query offers nothing to patch -> no deterministic fix.
    src = (
        "def product(product_id, conn):\n"
        '    return conn.execute("SELECT id FROM products WHERE id = ?", (product_id,)).fetchall()\n'
    )
    assert patch_source("sqli", "product", src) is None


def test_validator_is_not_fooled_by_unpatched_source():
    # The unpatched download() has '..' only in a comment; validation must return
    # False, or certification would be vacuous for path traversal.
    ok, _ = _validate(_pt_finding(), "download", SEEDED.read_text())
    assert ok is False


def test_path_patch_does_not_over_block_nested_paths():
    # The guard must reject '..'/absolute paths structurally, not ban every '/'.
    patch = patch_source("path_traversal", "download", SEEDED.read_text())
    assert patch is not None
    assert "is_absolute" in patch.new_source
    assert '"/" in' not in patch.new_source
    # And it must actually validate as a real guard.
    ok, _ = _validate(_pt_finding(), "download", patch.new_source)
    assert ok is True

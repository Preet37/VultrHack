"""Proof-loop acceptance tests: patch a confirmed finding and prove it is closed.

Covers the finder.md handoff: exploit -> patch -> re-exploit -> validate, plus a
generated regression test. The seeded Flask app is served on a free port so the
finder produces real confirmed findings; remediate() then patches a disposable
copy and re-exploits it.
"""

from __future__ import annotations

import importlib.util
import socket
import sys
import threading
import time
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, make_server

import pytest

ROOT = Path(__file__).parent
SEEDED = ROOT / "targets" / "seeded_flask" / "app.py"

pytest.importorskip("flask", reason="target app needs Flask installed")

from finder.patchers import patch_source  # noqa: E402
from finder.pipeline import run_finder  # noqa: E402
from finder.remediate import remediate  # noqa: E402


def _load_seeded_app():
    spec = importlib.util.spec_from_file_location("seeded_app_r", SEEDED)
    module = importlib.util.module_from_spec(spec)
    sys.modules["seeded_app_r"] = module
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def findings():
    module = _load_seeded_app()
    app = module.create_app()
    port = _free_port()
    server = make_server("127.0.0.1", port, app, handler_class=_QuietHandler)
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


def test_sqli_patch_is_certified_closed(findings):
    finding = _one(findings, "sqli")
    result = remediate(finding, findings[1])
    assert result.patched is True
    assert result.reexploit_blocked is True, result.reexploit_evidence
    assert result.functional_ok is True
    assert result.validated is True
    assert result.certified is True
    assert result.patch_diff  # a real diff was produced


def test_path_traversal_patch_is_certified_closed(findings):
    finding = _one(findings, "path_traversal")
    result = remediate(finding, findings[1])
    assert result.certified is True, (result.reexploit_evidence, result.validation_notes)


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

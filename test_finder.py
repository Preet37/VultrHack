"""Finder acceptance tests (offline: no inference key, no external tools needed).

Covers the finder.md acceptance criteria that don't require the sandbox host:
  #1  seeded SQLi is confirmed and the canary leaves the box
  #2  a clean target yields a coverage report and zero false findings
  #5  every confirmed finding carries the input->sink chain, confirming output,
      and canary result

The seeded Flask app is started in a background thread on a free port so the
finder exercises the real HTTP confirm path.
"""

from __future__ import annotations

import importlib.util
import socket
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

from finder.pipeline import run_finder  # noqa: E402


def _load_seeded_app():
    spec = importlib.util.spec_from_file_location("seeded_app", SEEDED)
    module = importlib.util.module_from_spec(spec)
    sys.modules["seeded_app"] = module
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):  # silence per-request logging
        pass


@pytest.fixture(scope="module")
def target():
    module = _load_seeded_app()
    app = module.create_app()
    port = _free_port()
    server = make_server("127.0.0.1", port, app, server_class=_ThreadingWSGIServer, handler_class=_QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # wait for readiness
    for _ in range(50):
        try:
            import httpx

            httpx.get(f"http://127.0.0.1:{port}/health", timeout=1.0)
            break
        except Exception:
            time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", str(SEEDED.parent)
    server.shutdown()


def test_seeded_sqli_confirmed_with_canary(target):
    base_url, source = target
    report = run_finder(base_url, source, wall_clock_seconds=30)
    sqli = [f for f in report.findings if f.vuln_class == "sqli"]
    assert sqli, f"expected a confirmed SQLi; got {[f.vuln_class for f in report.findings]}"
    finding = sqli[0]
    assert finding.canary_observed is True
    assert finding.endpoint == "/product"
    assert finding.param == "id"


def test_seeded_path_traversal_confirmed(target):
    base_url, source = target
    report = run_finder(base_url, source, wall_clock_seconds=30)
    pt = [f for f in report.findings if f.vuln_class == "path_traversal"]
    assert pt, f"expected a confirmed path traversal; got {[f.vuln_class for f in report.findings]}"
    assert pt[0].canary_observed is True
    assert pt[0].endpoint == "/download"


def test_endpoint_param_requires_whole_segment_match():
    # 'count' must NOT be routed to '/account' by substring; it should fall to the
    # route that actually declares the param.
    from finder.models import Candidate
    from finder.triage import _endpoint_param

    cand = Candidate(
        id="x", vuln_class="sqli", sink_file="a.py", sink_line=1,
        sink_symbol="count", snippet="", input_source="query:id",
    )
    routes = [
        {"path": "/account", "inputs": []},
        {"path": "/counter", "inputs": [{"name": "id", "source": "query"}]},
    ]
    endpoint, param = _endpoint_param(cand, routes)
    assert endpoint == "/counter" and param == "id"


def test_summary_is_not_self_contradictory():
    from finder.models import Coverage, Finding, FinderReport

    finding = Finding(
        id="1", vuln_class="sqli", endpoint="/x", param="id", input_to_sink="",
        sink_file="a.py", sink_line=1, exploit_request="GET x", confirming_output="",
        canary_observed=True, canary_value="", fix="", confirmer="", triage_source="",
    )
    with_findings = FinderReport("t", [finding], Coverage(classes_tested=["sqli"]), "offline").to_dict()["summary"]
    assert "no exploit found" not in with_findings  # not contradictory when a bug was found
    clean = FinderReport("t", [], Coverage(), "offline").to_dict()["summary"]
    assert "no exploit found" in clean  # the honest caveat only on a clean run


def test_all_supported_classes_confirmed(target):
    base_url, source = target
    report = run_finder(base_url, source, wall_clock_seconds=60)
    classes = {f.vuln_class for f in report.findings}
    expected = {"sqli", "path_traversal", "command_injection", "ssrf", "auth_bypass"}
    assert expected <= classes, f"missing {expected - classes}; got {classes}"
    assert all(f.canary_observed for f in report.findings)


def test_finding_carries_full_proof(target):
    base_url, source = target
    report = run_finder(base_url, source, wall_clock_seconds=30)
    finding = next(f for f in report.findings if f.vuln_class == "sqli")
    # acceptance #5: input->sink chain, confirming tool output, canary result
    assert "->" in finding.input_to_sink
    assert finding.sink_file.endswith("app.py")
    assert finding.exploit_request.startswith("GET ")
    assert "CANARY" in finding.confirming_output  # redacted marker present
    assert finding.fix  # remediation handed to the patch step


def test_no_false_positive_on_clean_target(tmp_path):
    # A clean target: a stdlib http server with no vulnerable sink.
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Clean(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    port = _free_port()
    server = HTTPServer(("127.0.0.1", port), Clean)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    # empty source dir -> no candidates, so no findings, but a coverage report
    report = run_finder(f"http://127.0.0.1:{port}", str(tmp_path), wall_clock_seconds=10)
    server.shutdown()
    assert report.findings == []
    assert report.coverage.candidates_seen == 0
    assert "no exploit found" in report.to_dict()["summary"]


def test_offline_triage_source_is_honest(target):
    base_url, source = target
    report = run_finder(base_url, source, wall_clock_seconds=30)
    # With no inference key set in the test env, triage must declare the offline path.
    assert "offline-heuristic" in report.triage_source or report.triage_source.startswith("vultr-inference:")

"""Environmental-canary acceptance: confirm exploits on a MANIFEST-LESS target.

targets/nomanifest_flask ships no manifest.json and plants no canaries of its
own, so the finder cannot rely on anything seeded in the repo. Instead Cerberus
plants sentinels in the sandbox ENVIRONMENT (a file outside the app root, a
loopback-only HTTP listener) and uses those as the oracle. These tests boot the
real app the same way the other target tests do and assert the finder CONFIRMS
path_traversal AND ssrf -- each proven by an environmental canary observed
leaving the box.

In scope (app-agnostic): path_traversal, ssrf, command_injection. Out of scope:
sqli and auth_bypass/IDOR still need app-level instrumentation (a canary in the
app's own data), which no environmental sentinel can supply.
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
    daemon_threads = True  # so the SSRF fetch (a nested request) is not deadlocked


ROOT = Path(__file__).parent
NOMANIFEST = ROOT / "targets" / "nomanifest_flask" / "app.py"

pytest.importorskip("flask", reason="target app needs Flask installed")

from finder.env_canary import EnvCanaries  # noqa: E402
from finder.pipeline import run_finder  # noqa: E402


def _load_app():
    spec = importlib.util.spec_from_file_location("nomanifest_app", NOMANIFEST)
    module = importlib.util.module_from_spec(spec)
    sys.modules["nomanifest_app"] = module
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
    module = _load_app()
    app = module.create_app()
    port = _free_port()
    server = make_server("127.0.0.1", port, app, server_class=_ThreadingWSGIServer, handler_class=_QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    for _ in range(50):
        try:
            import httpx

            httpx.get(f"http://127.0.0.1:{port}/health", timeout=1.0)
            break
        except Exception:
            time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", str(NOMANIFEST.parent)
    server.shutdown()


def test_target_ships_no_manifest():
    # The whole point: this target has no manifest, so recon plants env canaries.
    assert not (NOMANIFEST.parent / "manifest.json").exists()


def test_path_traversal_confirmed_via_env_canary(target):
    base_url, source = target
    report = run_finder(base_url, source, wall_clock_seconds=30)
    pt = [f for f in report.findings if f.vuln_class == "path_traversal"]
    assert pt, f"expected a confirmed path traversal; got {[f.vuln_class for f in report.findings]}"
    assert pt[0].canary_observed is True
    assert pt[0].endpoint == "/download"


def test_ssrf_confirmed_via_env_canary(target):
    base_url, source = target
    report = run_finder(base_url, source, wall_clock_seconds=30)
    ssrf = [f for f in report.findings if f.vuln_class == "ssrf"]
    assert ssrf, f"expected a confirmed SSRF; got {[f.vuln_class for f in report.findings]}"
    assert ssrf[0].canary_observed is True
    assert ssrf[0].endpoint == "/fetch"


def test_both_env_classes_confirmed_without_manifest(target):
    base_url, source = target
    report = run_finder(base_url, source, wall_clock_seconds=45)
    classes = {f.vuln_class for f in report.findings}
    assert {"path_traversal", "ssrf"} <= classes, f"missing {{'path_traversal','ssrf'}} - {classes}"
    assert all(f.canary_observed for f in report.findings)


def test_env_canaries_tear_down_cleanly():
    # The context manager must delete its temp sentinel and stop its listener.
    with EnvCanaries() as env:
        sentinel = Path(env.sentinel_path)
        assert sentinel.exists()
        assert env.file_canary in sentinel.read_text()
        # The internal listener answers the canary while the block is open.
        import httpx

        body = httpx.get(env.ssrf_url, timeout=2.0).text
        assert env.ssrf_canary in body
    # After teardown: sentinel gone, listener refuses connections.
    assert not sentinel.exists()
    import httpx

    with pytest.raises(httpx.HTTPError):
        httpx.get(env.ssrf_url, timeout=1.0)

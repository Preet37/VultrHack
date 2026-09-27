"""Unit tests for the safety gate.

Two halves:
  1. Every dangerous / cheating pattern the gate is supposed to catch, one test
     each, plus the class of legit code that must NOT trip it (no false
     positives on the exact shapes a real fix uses).
  2. An end-to-end check that the finder's REAL remediation fixes for every
     seeded_flask vuln class pass the gate -- run live through remediate() on a
     disposable copy, exactly as the demo does. If the gate ever flags a real
     fix, that is a gate bug, and this test is what catches it.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import pytest

from finder.safety_gate import GateResult, safety_gate

ROOT = Path(__file__).parent
SEEDED = ROOT / "targets" / "seeded_flask"


def _diff(added: str = "", removed: str = "") -> str:
    """Build a minimal unified diff from added/removed line bodies."""
    lines = ["--- a/app.py", "+++ b/app.py", "@@ -1,1 +1,1 @@"]
    for r in removed.splitlines():
        lines.append("-" + r)
    for a in added.splitlines():
        lines.append("+" + a)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# 1. Per-pattern unit tests                                                   #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "added,rule",
    [
        # file deletion / destruction
        ('os.system("rm -rf /var/data")', "file_destruction"),
        ("shutil.rmtree(path)", "file_destruction"),
        ("os.remove(target)", "file_destruction"),
        ("os.unlink(target)", "file_destruction"),
        ("Path(target).unlink()", "file_destruction"),
        ("os.rmdir(folder)", "file_destruction"),
        # world-writable chmod
        ("os.chmod(target, 0o777)", "permission_weakening"),
        ("os.chmod(target, 0o666)", "permission_weakening"),
        # shell execution
        ("subprocess.run(cmd, shell=True)", "shell_execution"),
        ('os.system("echo " + host)', "shell_execution"),
        ('os.popen("ls " + d)', "shell_execution"),
        ("out = `whoami`", "shell_execution"),
        # dynamic code
        ('eval(request.args["x"])', "dynamic_code"),
        ('exec(request.args["code"])', "dynamic_code"),
        ('mod = __import__(name)', "dynamic_code"),
        ("obj = pickle.loads(blob)", "dynamic_code"),
        # destructive SQL
        ('conn.execute("DROP TABLE users")', "destructive_sql"),
        ('conn.execute("TRUNCATE TABLE logs")', "destructive_sql"),
        ('q = "SELECT 1; DROP TABLE t; --"', "destructive_sql"),
        ('conn.execute("DELETE FROM accounts")', "destructive_sql"),
        # auth weakening (added toggles)
        ("AUTH_REQUIRED = False", "auth_weakening"),
        ("check_auth_enabled = False", "auth_weakening"),
        ("resp = requests.get(url, verify=False)", "auth_weakening"),
        ("permission = permit_all", "auth_weakening"),
        ("policy = allow_any", "auth_weakening"),
        # new outbound network calls
        ('requests.post("http://x/collect", json=d)', "network_call"),
        ("urllib.request.urlopen(url)", "network_call"),
        ("with urlopen(url) as r:", "network_call"),
        ("socket.connect((host, 80))", "network_call"),
        ("c = http.client.HTTPConnection(host)", "network_call"),
        # secret / credential reads
        ('key = open("id_rsa").read()', "secret_read"),
        ('data = open("/etc/shadow").read()', "secret_read"),
        ('data = open("/etc/passwd").read()', "secret_read"),
        ('cfg = open(".env").read()', "secret_read"),
        ('tok = os.environ["AWS_SECRET_ACCESS_KEY"]', "secret_read"),
        ('pw = os.getenv("DB_PASSWORD")', "secret_read"),
    ],
)
def test_added_pattern_is_flagged(added, rule):
    result = safety_gate(_diff(added=added))
    assert result.ok is False, f"expected {rule} to be flagged: {added!r}"
    assert any(h["rule"] == rule for h in result.hits), (rule, result.hits)


def test_delete_from_with_where_is_not_flagged():
    # A scoped DELETE (has a WHERE) is legitimate and must not be flagged.
    result = safety_gate(_diff(added='conn.execute("DELETE FROM sessions WHERE id = ?", (sid,))'))
    assert result.ok is True, result.hits


def test_removed_ownership_check_is_flagged():
    diff = _diff(removed="    if str(account_id) != str(current_user):\n        return Response('no', status=403)")
    result = safety_gate(diff)
    assert result.ok is False
    assert any(h["rule"] == "auth_weakening" for h in result.hits)


def test_removed_login_required_is_flagged():
    result = safety_gate(_diff(removed="@login_required"))
    assert result.ok is False
    assert any(h["rule"] == "auth_weakening" for h in result.hits)


def test_ownership_check_moved_not_flagged():
    # Removed on a '-' line but re-added on a '+' line -> not a weakening.
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,3 @@\n"
        "-    if account_id != current_user:\n"
        "+    if str(account_id) != str(current_user):\n"
        "+        return Response('forbidden', status=403)\n"
    )
    result = safety_gate(diff)
    assert result.ok is True, result.hits


def test_bare_imports_are_not_network_hits():
    # The real SSRF fix imports these; they must never be flagged as outbound calls.
    diff = _diff(added="import socket\nimport ipaddress\nfrom urllib.parse import urlparse")
    result = safety_gate(diff)
    assert result.ok is True, result.hits


def test_ssrf_allowlist_primitives_not_flagged():
    # urlparse()/ip_address()/gethostbyname() are validation, not outbound calls.
    added = (
        '    _parsed = urlparse(url)\n'
        '    _ip = ipaddress.ip_address(socket.gethostbyname(_parsed.hostname or ""))\n'
        '    if _ip.is_private or _ip.is_loopback:\n'
        '        return Response("blocked by policy", status=403)'
    )
    result = safety_gate(_diff(added=added))
    assert result.ok is True, result.hits


def test_execute_not_confused_with_exec():
    # conn.execute(...) must not trip the exec() rule.
    result = safety_gate(_diff(added="    rows = conn.execute(query, (product_id,)).fetchall()"))
    assert result.ok is True, result.hits


def test_environ_used_for_benign_name_not_flagged():
    result = safety_gate(_diff(added='    port = os.environ.get("PORT", "5001")'))
    assert result.ok is True, result.hits


def test_gate_result_shape():
    r = safety_gate("")
    assert isinstance(r, GateResult)
    assert r.ok is True and r.hits == []


def test_clean_diff_passes():
    diff = _diff(added="    return Response('ok', status=200)")
    assert safety_gate(diff).ok is True


# --------------------------------------------------------------------------- #
# 2. Real remediation fixes must PASS the gate (live, end-to-end)             #
# --------------------------------------------------------------------------- #

pytest.importorskip("flask", reason="seeded target needs Flask installed")

import importlib.util  # noqa: E402
import sys  # noqa: E402

from finder.pipeline import run_finder  # noqa: E402
from finder.remediate import free_port, remediate  # noqa: E402

ALL_CLASSES = ["sqli", "path_traversal", "command_injection", "ssrf", "auth_bypass"]


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True  # so an SSRF self-fetch (nested request) does not deadlock


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass


@pytest.fixture(scope="module")
def real_findings():
    source = str(SEEDED)
    spec = importlib.util.spec_from_file_location("target_seeded_flask_gate", SEEDED / "app.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["target_seeded_flask_gate"] = module
    spec.loader.exec_module(module)
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
    report = run_finder(f"http://127.0.0.1:{port}", source, wall_clock_seconds=45)
    server.shutdown()
    return report.findings, source


def test_finder_confirms_all_classes(real_findings):
    findings, _ = real_findings
    classes = {f.vuln_class for f in findings}
    assert set(ALL_CLASSES) <= classes, f"missing confirmed classes: {set(ALL_CLASSES) - classes}"


@pytest.mark.parametrize("vuln_class", ALL_CLASSES)
def test_real_remediation_patch_passes_gate(real_findings, vuln_class):
    findings, source = real_findings
    finding = next(f for f in findings if f.vuln_class == vuln_class)
    res = remediate(finding, source)
    assert res.patched and res.patch_diff, (vuln_class, res.validation_notes)
    result = safety_gate(res.patch_diff)
    assert result.ok is True, (
        f"gate falsely flagged the REAL {vuln_class} fix: {result.hits}\n--- diff ---\n{res.patch_diff}"
    )

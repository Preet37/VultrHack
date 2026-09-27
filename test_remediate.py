"""Proof-loop acceptance tests: patch a confirmed finding and prove it is closed.

Covers the finder.md handoff: exploit -> patch -> re-exploit -> validate, plus a
generated regression test. The seeded Flask app is served on a free port so the
finder produces real confirmed findings; remediate() then patches a disposable
copy and re-exploits it.
"""

from __future__ import annotations

import importlib.util
import json
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
SNIP = ROOT / "targets" / "snipstash" / "app.py"
TARGETS = [str(SEEDED.parent), str(SNIP.parent)]

pytest.importorskip("flask", reason="target app needs Flask installed")

import finder.remediate as remediate_mod  # noqa: E402
from finder.models import Finding  # noqa: E402
from finder.patchers import Patch, patch_source  # noqa: E402
from finder.pipeline import run_finder  # noqa: E402
from finder.recon import canaries_for, load_manifest  # noqa: E402
from finder.remediate import _try_patch, _validate, free_port, remediate, remediate_batch  # noqa: E402


def _pt_finding() -> Finding:
    return Finding(
        id="pt", vuln_class="path_traversal", endpoint="/download", param="file",
        input_to_sink="args:file -> download() in app.py:1", sink_file="app.py", sink_line=1,
        exploit_request="GET x", confirming_output="", canary_observed=True, canary_value="",
        fix="", confirmer="", triage_source="",
    )


def _load_app(app_path: Path, mod_name: str):
    spec = importlib.util.spec_from_file_location(mod_name, app_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture(scope="module", params=TARGETS, ids=["seeded_flask", "snipstash"])
def findings(request):
    source = request.param
    module = _load_app(Path(source) / "app.py", f"target_{Path(source).name}")
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


def test_auth_bypass_patch_uses_server_identity_not_client_header():
    # The ownership guard must compare against the server-side identity, never a
    # client-supplied header an attacker could spoof.
    patch = patch_source("auth_bypass", "account", SEEDED.read_text())
    assert patch is not None
    assert "current_user" in patch.new_source and "403" in patch.new_source


def test_auth_bypass_confirmer_attempts_identity_spoof():
    # So a "fix" that merely trusts a client identity header is caught, not certified.
    import inspect

    from finder.playbooks import confirm_auth_bypass

    assert "X-User" in inspect.getsource(confirm_auth_bypass)


def test_ssrf_patch_resolves_host_and_blocks_private_ranges():
    import ast as _ast

    patch = patch_source("ssrf", "fetch", SEEDED.read_text())
    assert patch is not None
    assert "is_private" in patch.new_source and "is_loopback" in patch.new_source
    assert "import ipaddress" in patch.new_source  # guard's imports were injected
    _ast.parse(patch.new_source)  # patched source still parses


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


# --- Launcher seam + batch remediation ----------------------------------------
#
# The launcher seam hosts the PATCHED disposable copy instead of the local
# free_port + _start_target path. In these tests a fake launcher serves the
# copied app in-process (offline) and records every call/stop, so we can prove
# the loop hosted the app exactly once and always released it.


def _seeded_findings() -> list[Finding]:
    """The five planted-bug findings, rebuilt from the seeded manifest (offline).

    Same ids/classes/endpoints a real finder run produces, but without booting
    the vulnerable app: the patch stage is pure source rewriting, and the
    re-exploit runs against the PATCHED copy, which the launcher serves.
    """
    manifest = json.loads((SEEDED.parent / "manifest.json").read_text())
    findings = []
    for bug in manifest["planted_bugs"]:
        findings.append(
            Finding(
                id=bug["id"],
                vuln_class=bug["class"],
                endpoint=bug["endpoint"],
                param=bug["param"],
                input_to_sink=f"query:{bug['param']} -> {bug['sink_symbol']}() in {bug['sink_file']}:1",
                sink_file=bug["sink_file"],
                sink_line=1,
                exploit_request=f"GET {bug['endpoint']}?{bug['param']}=x",
                confirming_output="",
                canary_observed=True,
                canary_value="",
                fix="",
                confirmer="",
                triage_source="offline-test",
            )
        )
    return findings


class _FakeLauncher:
    """In-process hosting seam: serves the COPIED (patched) app per call."""

    def __init__(self):
        self.calls: list[Path] = []
        self.stops = 0
        self.served_source = ""

    def __call__(self, target_dir: Path, entrypoint: str):
        target_dir = Path(target_dir)
        self.calls.append(target_dir)
        self.served_source = (target_dir / entrypoint).read_text()
        module = _load_app(target_dir / entrypoint, f"launched_{id(self)}_{len(self.calls)}")
        app = module.create_app()
        port = free_port()
        server = make_server("127.0.0.1", port, app, server_class=_ThreadingWSGIServer, handler_class=_QuietHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def stop():
            self.stops += 1
            server.shutdown()
            server.server_close()
            sys.modules.pop(module.__name__, None)

        return f"http://127.0.0.1:{port}", stop


def _seeded_canaries() -> list[str]:
    return canaries_for(load_manifest(str(SEEDED.parent)))


def test_try_patch_with_launcher_seam_hosts_and_always_stops():
    launcher = _FakeLauncher()
    finding = next(f for f in _seeded_findings() if f.vuln_class == "sqli")
    patch = patch_source("sqli", "product", SEEDED.read_text())
    blocked, evidence, func_ok = _try_patch(
        finding, str(SEEDED.parent), "app.py", patch.new_source, _seeded_canaries(), None, 12.0, launcher=launcher
    )
    assert (blocked, func_ok) == (True, True), evidence
    assert len(launcher.calls) == 1
    assert launcher.stops == 1  # always stopped, even on success
    assert "WHERE id = ?" in launcher.served_source  # the launcher served the PATCHED copy


def test_try_patch_launcher_raise_propagates_and_nothing_is_stopped():
    def boom(target_dir, entrypoint):
        raise RuntimeError("no sandbox capacity")

    finding = _seeded_findings()[0]
    patch = patch_source("sqli", "product", SEEDED.read_text())
    with pytest.raises(RuntimeError, match="no sandbox capacity"):
        _try_patch(finding, str(SEEDED.parent), "app.py", patch.new_source, _seeded_canaries(), None, 12.0, launcher=boom)


def test_batch_all_five_seeded_findings_certified_with_fake_launcher():
    launcher = _FakeLauncher()
    findings = _seeded_findings()
    results, functional = remediate_batch(findings, str(SEEDED.parent), launcher=launcher)
    assert functional is True
    assert [r.finding_id for r in results] == [f.id for f in findings]  # findings order preserved
    assert len(launcher.calls) == 1  # the cumulative copy was hosted exactly once
    assert launcher.stops == 1  # and always released afterwards
    by_class = {r.vuln_class: r for r in results}
    for vuln_class, res in by_class.items():
        assert res.patched is True, vuln_class
        assert res.patch_source == "deterministic-template", vuln_class
        assert res.independent_review is None, vuln_class  # deterministic patches skip model review
        assert res.certified is True, (vuln_class, res.reexploit_evidence, res.validation_notes)
    # Cumulative: the single hosted copy carries every class's fix at once.
    hosted = launcher.served_source
    assert "WHERE id = ?" in hosted
    assert 'if ".." in Path(name).parts or Path(name).is_absolute():' in hosted
    assert "shell=True" not in hosted
    assert "is_private" in hosted and "import ipaddress" in hosted
    assert "if str(account_id) != str(current_user):" in hosted
    # Per-finding diffs are snapshotted against the original as THAT finding saw
    # it (earlier fixes already inside), so each diff holds exactly its own fix.
    assert all("a/app.py" in r.patch_diff and "b/app.py" in r.patch_diff for r in results)
    assert 'WHERE id = " + product_id' in by_class["sqli"].patch_diff
    assert "WHERE id = ?" in by_class["sqli"].patch_diff
    assert "is_absolute" not in by_class["sqli"].patch_diff
    assert "shell=True" in by_class["command_injection"].patch_diff
    assert "import ipaddress" in by_class["ssrf"].patch_diff
    assert "is_absolute" in by_class["path_traversal"].patch_diff
    assert "current_user" in by_class["auth_bypass"].patch_diff


def test_batch_launcher_failure_keeps_everything_uncertified():
    def boom(target_dir, entrypoint):
        raise RuntimeError("no sandbox capacity")

    results, functional = remediate_batch(_seeded_findings(), str(SEEDED.parent), launcher=boom)
    assert functional is False
    for res in results:
        assert res.patched is True  # phase 1 still produced the cumulative fixes
        assert res.reexploit_blocked is False
        assert "no sandbox capacity" in res.reexploit_evidence
        assert res.certified is False


def test_batch_boot_failure_still_stops_the_launcher(monkeypatch):
    def no_health(base, timeout):
        raise RuntimeError("no /health endpoint")

    monkeypatch.setattr(remediate_mod, "_wait_health", no_health)
    launcher = _FakeLauncher()
    results, functional = remediate_batch(_seeded_findings(), str(SEEDED.parent), launcher=launcher)
    assert launcher.stops == 1  # released even though the boot failed
    assert functional is False
    for res in results:
        assert res.reexploit_blocked is False
        assert "shared launch failed" in res.reexploit_evidence
        assert res.certified is False


def test_batch_deterministic_miss_falls_back_to_model_patch(monkeypatch):
    # Offline stand-ins: the "model" returns the same fix the deterministic
    # patcher would have -- labeled as model-written -- and the independent
    # reviewer approves. What is under test is the SEAM (fallback, labeling,
    # per-finding review gate), not any model.
    writes = []
    reviews = []

    def fake_patch_source(vuln_class, sink_symbol, src):
        if vuln_class == "auth_bypass":
            return None  # pretend the seeded auth shape is unrecognized
        return patch_source(vuln_class, sink_symbol, src)

    def fake_model_write(finding, sink_symbol, src, client=None):
        writes.append((finding.vuln_class, sink_symbol))
        patch = patch_source(finding.vuln_class, sink_symbol, src)
        assert patch is not None
        return Patch(patch.vuln_class, "model-written: " + patch.description, patch.new_source)

    def fake_model_review(finding, sink_symbol, new_source, client=None, avoid_model=None):
        reviews.append(finding.vuln_class)
        return {"closed": True, "over_blocks": False, "reason": "class closed, no over-block", "model": "offline-reviewer-2"}

    monkeypatch.setattr(remediate_mod, "patch_source", fake_patch_source)
    monkeypatch.setattr(remediate_mod, "model_write_patch", fake_model_write)
    monkeypatch.setattr(remediate_mod, "model_review", fake_model_review)

    launcher = _FakeLauncher()
    results, functional = remediate_batch(_seeded_findings(), str(SEEDED.parent), launcher=launcher)
    by_class = {r.vuln_class: r for r in results}
    assert functional is True
    assert writes == [("auth_bypass", "account")]  # exactly one finding needed the model
    assert reviews == ["auth_bypass"]  # and only its patch went through independent review
    auth = by_class["auth_bypass"]
    assert auth.patch_source == "vultr-inference"
    assert auth.patch_description.startswith("model-written:")
    assert auth.independent_review is not None
    assert auth.independent_review["model"] == "offline-reviewer-2"
    assert "independent" in auth.validation_source
    assert auth.certified is True, (auth.reexploit_evidence, auth.validation_notes)
    # The deterministic findings never touched the writer or the reviewer.
    assert by_class["sqli"].patch_source == "deterministic-template"
    assert by_class["sqli"].independent_review is None
    assert by_class["sqli"].certified is True


def test_batch_unpatchable_finding_stays_open_but_rest_certified(monkeypatch):
    def fake_patch_source(vuln_class, sink_symbol, src):
        if vuln_class == "ssrf":
            return None
        return patch_source(vuln_class, sink_symbol, src)

    monkeypatch.setattr(remediate_mod, "patch_source", fake_patch_source)
    monkeypatch.setattr(remediate_mod, "model_write_patch", lambda *args, **kwargs: None)  # model has nothing either

    launcher = _FakeLauncher()
    results, functional = remediate_batch(_seeded_findings(), str(SEEDED.parent), launcher=launcher)
    by_class = {r.vuln_class: r for r in results}
    ssrf = by_class["ssrf"]
    assert ssrf.patched is False
    assert ssrf.patch_diff == ""
    assert "no patch produced" in ssrf.validation_notes
    assert ssrf.reexploit_blocked is False  # honestly re-exploited: the canary still leaks
    assert "STILL leaks" in ssrf.reexploit_evidence
    assert ssrf.certified is False
    assert "import ipaddress" not in launcher.served_source  # ssrf contributed no patch
    # The other four classes patched cumulatively and certified.
    for vuln_class in ("sqli", "path_traversal", "command_injection", "auth_bypass"):
        assert by_class[vuln_class].certified is True, vuln_class
    # App healthy; even the unpatched /fetch still serves the benign URL.
    assert functional is True


def test_batch_local_mode_matches_single_remediate_outcomes():
    # With launcher=None the batch must behave like N independent remediate()
    # runs -- same per-finding outcomes, just hosted once instead of per finding.
    findings = _seeded_findings()
    batch_results, functional = remediate_batch(findings, str(SEEDED.parent))
    assert functional is True
    by_class = {r.vuln_class: r for r in batch_results}
    for finding in findings:
        single = remediate(finding, str(SEEDED.parent))
        batched = by_class[finding.vuln_class]
        for attr in ("patched", "patch_source", "reexploit_blocked", "functional_ok", "validated", "certified"):
            assert getattr(batched, attr) == getattr(single, attr), (finding.vuln_class, attr)
        assert single.certified is True

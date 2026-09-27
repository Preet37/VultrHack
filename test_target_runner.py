"""Tests for the target-execution seam (finder/target_runner.py).

The seam is what lets the scan move from "runs on the control host" to "runs in a
disposable sandbox" by swapping one object. These tests pin the contract: the
local runner really boots and tears down a target, and the sandbox runner fails
closed until its dispatch primitive is injected -- it never silently runs an
untrusted target on the control host.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

pytest.importorskip("flask", reason="target app needs Flask installed")

from finder.target_runner import (  # noqa: E402
    LocalSubprocessRunner,
    SandboxTargetRunner,
    make_runner,
)

SEEDED = str(Path(__file__).parent / "targets" / "seeded_flask")


def test_local_runner_boots_and_stops():
    runner = LocalSubprocessRunner(SEEDED, "app.py")
    base_url = runner.start()
    try:
        assert httpx.get(f"{base_url}/health", timeout=2.0).status_code == 200
    finally:
        runner.stop()
    # After stop the port is no longer served.
    with pytest.raises(httpx.HTTPError):
        httpx.get(f"{base_url}/health", timeout=1.0)


def test_sandbox_runner_fails_closed_without_dispatch():
    runner = SandboxTargetRunner(SEEDED, "app.py")  # no dispatch injected
    with pytest.raises(RuntimeError, match="sandbox target execution is not wired"):
        runner.start()


def test_sandbox_runner_uses_injected_dispatch_and_tears_down():
    torn_down = []

    def fake_dispatch(source_dir, entrypoint):
        assert source_dir == SEEDED and entrypoint == "app.py"
        return "http://10.0.0.5:8080", lambda: torn_down.append(True)

    runner = SandboxTargetRunner(SEEDED, "app.py", dispatch=fake_dispatch)
    assert runner.start() == "http://10.0.0.5:8080"
    runner.stop()
    assert torn_down == [True]


def test_make_runner_selects_by_mode():
    assert isinstance(make_runner(SEEDED, mode="local"), LocalSubprocessRunner)
    assert isinstance(make_runner(SEEDED, mode="sandbox"), SandboxTargetRunner)
    with pytest.raises(ValueError, match="unknown scan runner mode"):
        make_runner(SEEDED, mode="bogus")


def test_make_runner_honors_env(monkeypatch):
    monkeypatch.delenv("CERBERUS_SCAN_RUNNER", raising=False)
    assert isinstance(make_runner(SEEDED), LocalSubprocessRunner)  # default local
    monkeypatch.setenv("CERBERUS_SCAN_RUNNER", "sandbox")
    assert isinstance(make_runner(SEEDED), SandboxTargetRunner)


def test_local_runner_cleans_up_when_target_never_healthy(tmp_path):
    # An entrypoint that exits immediately never serves /health, so start() must
    # tear down the process it spawned before raising -- not orphan it.
    (tmp_path / "app.py").write_text("pass\n")
    runner = LocalSubprocessRunner(str(tmp_path), "app.py", health_timeout=1.0)
    with pytest.raises(RuntimeError):
        runner.start()
    assert runner._proc is None  # start() upheld its contract on the failure path

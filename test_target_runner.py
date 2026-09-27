"""Tests for the target-execution seam (finder/target_runner.py).

The seam is what lets the scan move from "runs on the control host" to "runs in a
disposable sandbox" by swapping one object. These tests pin the contract: the
local runner really boots and tears down a target, and the sandbox runner fails
closed until its dispatch primitive is injected -- it never silently runs an
untrusted target on the control host.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, Mock

import httpx
import pytest

from finder.microsandbox_backend import (
    MicrosandboxApp,
    MicrosandboxHost,
    MicrosandboxLimits,
    MicrosandboxTargetRunner,
)
from finder.target_runner import (
    LocalSubprocessRunner,
    SandboxTargetRunner,
    make_runner,
)

SEEDED = str(Path(__file__).parent / "targets" / "seeded_flask")


def test_local_runner_boots_and_stops():
    pytest.importorskip("flask", reason="target app needs Flask installed")
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
    assert isinstance(make_runner(SEEDED, mode="microsandbox"), MicrosandboxTargetRunner)
    with pytest.raises(ValueError, match="unknown scan runner mode"):
        make_runner(SEEDED, mode="bogus")


def test_make_runner_honors_env(monkeypatch):
    monkeypatch.delenv("CERBERUS_SCAN_RUNNER", raising=False)
    assert isinstance(make_runner(SEEDED), LocalSubprocessRunner)  # default local
    monkeypatch.setenv("CERBERUS_SCAN_RUNNER", "sandbox")
    assert isinstance(make_runner(SEEDED), SandboxTargetRunner)


def test_local_runner_cleans_up_when_target_never_healthy(tmp_path):
    pytest.importorskip("flask", reason="target app needs Flask installed")
    # An entrypoint that exits immediately never serves /health, so start() must
    # tear down the process it spawned before raising -- not orphan it.
    (tmp_path / "app.py").write_text("pass\n")
    runner = LocalSubprocessRunner(str(tmp_path), "app.py", health_timeout=1.0)
    with pytest.raises(RuntimeError):
        runner.start()
    assert runner._proc is None  # start() upheld its contract on the failure path


@pytest.fixture
def disposable_host():
    return MicrosandboxHost(
        instance_id="11111111-1111-4111-8111-111111111111",
        control_instance_id="22222222-2222-4222-8222-222222222222",
        plan="vx1-g-2c-8g-120s",
        vpc_id="33333333-3333-4333-8333-333333333333",
        vpc_subnet="10.42.0.0/24", vpc_ip="10.42.0.22", control_vpc_ip="10.42.0.2",
        disposable=True, cpu_virtualization=True, kvm_device=True, kvm_read_write=True,
        msb_doctor_ready=True, network_policy_verified=True, auto_delete_confirmed=True,
        lease_remaining_seconds=600, destroy=Mock(),
    )


@pytest.fixture
def microvm_app(disposable_host):
    return MicrosandboxApp(
        instance_id=disposable_host.instance_id, sandbox_name="target-123",
        base_url="http://10.42.0.22:8088", cpus=1, memory_mib=512,
        max_duration_seconds=120, private_binding_verified=True, destroy=Mock(),
    )


class FakeMicrosandboxBackend:
    def __init__(self, host, app):
        self.host = host
        self.app = app
        self.acquired = []
        self.launched = []

    def acquire_host(self, *, limits, timeout_seconds):
        self.acquired.append((limits, timeout_seconds))
        return self.host

    def launch(self, host, source_dir, entrypoint, *, limits, timeout_seconds):
        self.launched.append((host, source_dir, entrypoint, limits, timeout_seconds))
        return self.app


def test_microsandbox_mode_never_reuses_gvisor_dispatch_or_local_runner(monkeypatch):
    monkeypatch.setenv("CERBERUS_SCAN_RUNNER", "microsandbox")
    gvisor_dispatch = Mock()
    runner = make_runner(SEEDED, dispatch=gvisor_dispatch)
    assert isinstance(runner, MicrosandboxTargetRunner)
    with pytest.raises(RuntimeError, match="microsandbox dispatch is not wired"):
        runner.start()
    runner.stop()
    gvisor_dispatch.assert_not_called()


def test_make_runner_injects_separate_microsandbox_backend(disposable_host, microvm_app, monkeypatch):
    from finder import microsandbox_backend as module

    monkeypatch.setattr(module, "_health_probe", Mock(return_value=True))
    backend = FakeMicrosandboxBackend(disposable_host, microvm_app)
    runner = make_runner(SEEDED, mode="microsandbox", microsandbox_backend=backend)
    try:
        assert runner.start() == microvm_app.base_url
    finally:
        runner.stop()
    assert len(backend.launched) == 1
    microvm_app.destroy.assert_called_once()
    disposable_host.destroy.assert_called_once()


def test_microsandbox_backend_receives_limits_after_preflight_and_cleans_both(disposable_host, microvm_app):
    backend = FakeMicrosandboxBackend(disposable_host, microvm_app)
    health = Mock(return_value=True)
    limits = MicrosandboxLimits()
    runner = MicrosandboxTargetRunner(SEEDED, backend=backend, limits=limits, health_probe=health)
    assert runner.start() == microvm_app.base_url
    assert backend.acquired == [(limits, limits.startup_seconds)]
    assert len(backend.launched) == 1
    host, source_dir, entrypoint, received_limits, deadline = backend.launched[0]
    assert (host, source_dir, entrypoint, received_limits) == (disposable_host, SEEDED, "app.py", limits)
    assert 0 < deadline <= limits.startup_seconds
    health.assert_called_once()
    assert health.call_args.args[0] == microvm_app.base_url
    assert 0 < health.call_args.args[1] <= 2
    runner.stop()
    runner.stop()
    microvm_app.destroy.assert_called_once()
    disposable_host.destroy.assert_called_once()
    with pytest.raises(RuntimeError, match="one-shot"):
        runner.start()


@pytest.mark.parametrize("change", [
    {"instance_id": "22222222-2222-4222-8222-222222222222"},
    {"plan": "vc2-1c-1gb"},
    {"disposable": False},
    {"vpc_ip": "127.0.0.1"},
    {"control_vpc_ip": "10.42.0.22"},
    {"cpu_virtualization": False},
    {"kvm_device": False},
    {"kvm_read_write": False},
    {"msb_doctor_ready": False},
    {"network_policy_verified": False},
    {"auto_delete_confirmed": False},
    {"lease_remaining_seconds": 30},
    {"lease_remaining_seconds": float("nan")},
    {"lease_remaining_seconds": 901},
])
def test_microsandbox_rejects_unverified_host_before_source_dispatch(disposable_host, microvm_app, change):
    host = replace(disposable_host, **change)
    backend = FakeMicrosandboxBackend(host, microvm_app)
    runner = MicrosandboxTargetRunner(SEEDED, backend=backend, health_probe=Mock(return_value=True))
    with pytest.raises(ValueError, match="Microsandbox requires"):
        runner.start()
    assert backend.launched == []
    host.destroy.assert_called_once()
    microvm_app.destroy.assert_not_called()


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8088", "http://10.42.0.2:8088", "http://8.8.8.8:8088",
    "http://example.com:8088", "http://10.42.0.22", "http://user@10.42.0.22:8088",
    "http://10.42.0.22:8088/health", "https://10.42.0.22:8088",
])
def test_microsandbox_rejects_nonisolated_url_and_tears_down(disposable_host, microvm_app, url):
    app = replace(microvm_app, base_url=url)
    health = Mock(return_value=True)
    runner = MicrosandboxTargetRunner(
        SEEDED, backend=FakeMicrosandboxBackend(disposable_host, app), health_probe=health,
    )
    with pytest.raises(ValueError, match="private VPC URL"):
        runner.start()
    health.assert_not_called()
    app.destroy.assert_called_once()
    disposable_host.destroy.assert_called_once()


@pytest.mark.parametrize("change", [
    {"instance_id": "44444444-4444-4444-8444-444444444444"},
    {"private_binding_verified": False},
    {"cpus": 2}, {"memory_mib": 1024}, {"max_duration_seconds": 1000},
])
def test_microsandbox_rejects_unverified_guest_and_limits(disposable_host, microvm_app, change):
    app = replace(microvm_app, **change)
    runner = MicrosandboxTargetRunner(
        SEEDED, backend=FakeMicrosandboxBackend(disposable_host, app),
        health_probe=Mock(return_value=True),
    )
    with pytest.raises(ValueError, match="Microsandbox requires|Microsandbox resource"):
        runner.start()
    app.destroy.assert_called_once()
    disposable_host.destroy.assert_called_once()


@pytest.mark.parametrize("kwargs", [
    {"cpus": 0}, {"cpus": 3}, {"cpus": True}, {"memory_mib": 0},
    {"memory_mib": 4096}, {"max_seconds": 0}, {"max_seconds": 1000},
    {"startup_seconds": 0}, {"startup_seconds": 1000},
])
def test_microsandbox_limits_are_bounded(kwargs):
    with pytest.raises(ValueError, match="bounded"):
        MicrosandboxLimits(**kwargs)


def test_microsandbox_health_probe_rejects_redirects_and_proxies(monkeypatch):
    from finder import microsandbox_backend as module

    client = MagicMock()
    client.__enter__.return_value = client
    client.get.return_value.status_code = 302
    factory = Mock(return_value=client)
    monkeypatch.setattr(module.httpx, "Client", factory)
    assert module._health_probe("http://10.42.0.22:8088", 1.0) is False
    factory.assert_called_once_with(timeout=1.0, follow_redirects=False, trust_env=False)
    client.get.assert_called_once_with("http://10.42.0.22:8088/health")


def test_microsandbox_failed_health_cleans_guest_and_host(disposable_host, microvm_app):
    runner = MicrosandboxTargetRunner(
        SEEDED, backend=FakeMicrosandboxBackend(disposable_host, microvm_app),
        health_probe=Mock(return_value=False),
    )
    with pytest.raises(RuntimeError, match="did not answer /health"):
        runner.start()
    microvm_app.destroy.assert_called_once()
    disposable_host.destroy.assert_called_once()


def test_microsandbox_startup_deadline_cleans_late_result(disposable_host, microvm_app, monkeypatch):
    backend = FakeMicrosandboxBackend(disposable_host, microvm_app)
    from finder import microsandbox_backend as module

    now = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])

    def late_launch(*args, **kwargs):
        now[0] = 2.0
        return microvm_app

    backend.launch = late_launch
    limits = MicrosandboxLimits(startup_seconds=1)
    runner = MicrosandboxTargetRunner(SEEDED, backend=backend, limits=limits, health_probe=Mock())
    with pytest.raises(TimeoutError, match="deadline"):
        runner.start()
    microvm_app.destroy.assert_called_once()
    disposable_host.destroy.assert_called_once()


def test_microsandbox_deadline_watchdog_removes_resources(disposable_host, microvm_app):
    from threading import Event

    released = Event()
    host = replace(disposable_host, destroy=Mock(side_effect=released.set))
    app = replace(microvm_app, max_duration_seconds=1)
    runner = MicrosandboxTargetRunner(
        SEEDED, backend=FakeMicrosandboxBackend(host, app),
        limits=MicrosandboxLimits(max_seconds=1), health_probe=Mock(return_value=True),
    )
    try:
        runner.start()
        assert released.wait(2.5), "local watchdog did not request host teardown"
        app.destroy.assert_called_once()
        host.destroy.assert_called_once()
    finally:
        runner.stop()


def test_microsandbox_app_cleanup_failure_still_attempts_host_deletion(disposable_host, microvm_app):
    app = replace(microvm_app, destroy=Mock(side_effect=RuntimeError("guest removal failed")))
    runner = MicrosandboxTargetRunner(
        SEEDED, backend=FakeMicrosandboxBackend(disposable_host, app),
        health_probe=Mock(return_value=True),
    )
    runner.start()
    with pytest.raises(RuntimeError, match="teardown could not be confirmed"):
        runner.stop()
    app.destroy.assert_called_once()
    disposable_host.destroy.assert_called_once()


def test_microsandbox_host_deletion_failure_is_reported(disposable_host, microvm_app):
    host = replace(disposable_host, destroy=Mock(side_effect=TimeoutError("Vultr deletion unconfirmed")))
    runner = MicrosandboxTargetRunner(
        SEEDED, backend=FakeMicrosandboxBackend(host, microvm_app),
        health_probe=Mock(return_value=True),
    )
    runner.start()
    with pytest.raises(RuntimeError, match="teardown could not be confirmed"):
        runner.stop()
    microvm_app.destroy.assert_called_once()
    host.destroy.assert_called_once()


def test_microsandbox_missing_guest_teardown_still_deletes_host(disposable_host, microvm_app):
    app = replace(microvm_app, destroy=None)
    runner = MicrosandboxTargetRunner(
        SEEDED, backend=FakeMicrosandboxBackend(disposable_host, app),
        health_probe=Mock(),
    )
    with pytest.raises(RuntimeError, match="teardown could not be confirmed"):
        runner.start()
    disposable_host.destroy.assert_called_once()


def test_microsandbox_missing_host_teardown_fails_closed(disposable_host, microvm_app):
    host = replace(disposable_host, destroy=None)
    backend = FakeMicrosandboxBackend(host, microvm_app)
    runner = MicrosandboxTargetRunner(SEEDED, backend=backend, health_probe=Mock())
    with pytest.raises(RuntimeError, match="teardown could not be confirmed"):
        runner.start()
    assert backend.launched == []

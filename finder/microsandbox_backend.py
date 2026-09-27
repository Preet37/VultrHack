"""Opt-in, fail-closed Microsandbox target execution contract.

No provisioning or guest transport is bundled here. A trusted backend must operate
on a disposable Vultr VX1 (never the control VX1), prove its KVM and network
preflight BEFORE receiving source, and enforce a host-side expiry independently
of this process. See finder/README.md for the integration and isolation gaps.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
import threading
import time
from dataclasses import dataclass
from typing import Callable, Protocol
from urllib.parse import urlsplit
from uuid import UUID

import httpx


@dataclass(frozen=True)
class MicrosandboxLimits:
    """Hard ceilings requested of the remote host and its microVM."""

    cpus: int = 1
    memory_mib: int = 512
    max_seconds: int = 120
    startup_seconds: int = 120

    def __post_init__(self) -> None:
        if (type(self.cpus) is not int or not 1 <= self.cpus <= 2
                or type(self.memory_mib) is not int or not 128 <= self.memory_mib <= 2048
                or type(self.max_seconds) is not int or not 1 <= self.max_seconds <= 300
                or type(self.startup_seconds) is not int or not 1 <= self.startup_seconds <= 300):
            raise ValueError("Microsandbox CPU, memory and time limits must be bounded")


@dataclass(frozen=True)
class MicrosandboxHost:
    """Evidence from an authenticated cloud API AND an authenticated VX1 probe.

    The backend must arrange auto-deletion out of process before returning this
    handle; its destroy() must confirm that Vultr has deleted this *instance*.
    If acquisition fails before a handle exists, the backend owns cleanup.
    Boolean evidence is NOT itself an attestation: the backend must verify it.
    """

    instance_id: str
    control_instance_id: str
    plan: str
    vpc_id: str
    vpc_subnet: str
    vpc_ip: str
    control_vpc_ip: str
    disposable: bool
    cpu_virtualization: bool
    kvm_device: bool
    kvm_read_write: bool
    msb_doctor_ready: bool
    network_policy_verified: bool
    auto_delete_confirmed: bool
    lease_remaining_seconds: float
    destroy: Callable[[], None]


@dataclass(frozen=True)
class MicrosandboxApp:
    """Result of launching a microVM on the preflighted host (not a host process)."""

    instance_id: str
    sandbox_name: str
    base_url: str
    cpus: int
    memory_mib: int
    max_duration_seconds: int
    private_binding_verified: bool
    destroy: Callable[[], None]


class MicrosandboxBackend(Protocol):
    """Trusted integrator for disposable VX1 provisioning and guest dispatch.

    acquire_host must honor timeout_seconds, arrange out-of-process auto-deletion,
    and clean partial provisioning on errors. launch must honor timeout_seconds,
    package/upload source ONLY after acquire_host is verified, enforce guest
    limits and max duration on the host, and clean partial launch failures.
    Neither callback may execute target code on the control VM. destroy methods
    must confirm removal and raise if they cannot; they must have finite timeouts.
    """

    def acquire_host(self, *, limits: MicrosandboxLimits, timeout_seconds: float) -> MicrosandboxHost: ...

    def launch(
        self, host: MicrosandboxHost, source_dir: str, entrypoint: str, *,
        limits: MicrosandboxLimits, timeout_seconds: float,
    ) -> MicrosandboxApp: ...


def _canonical_uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (TypeError, ValueError, AttributeError):
        return False


def _private_subnet(value: object) -> ipaddress.IPv4Network:
    try:
        subnet = ipaddress.ip_network(value, strict=True)
    except (TypeError, ValueError):
        raise ValueError("Microsandbox requires a private IPv4 VPC subnet") from None
    private = (ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if not isinstance(subnet, ipaddress.IPv4Network) or not any(subnet.subnet_of(block) for block in private):
        raise ValueError("Microsandbox requires a private IPv4 VPC subnet")
    return subnet


def _validate_host(host: MicrosandboxHost, limits: MicrosandboxLimits) -> None:
    if (not all(_canonical_uuid(value) for value in (host.instance_id, host.control_instance_id, host.vpc_id))
            or host.instance_id == host.control_instance_id
            or not isinstance(host.plan, str)
            or not re.fullmatch(r"vx1-[a-z0-9-]+-\d+s", host.plan)
            or host.disposable is not True):
        raise ValueError("Microsandbox requires a verified disposable VX1 distinct from the control VM")
    subnet = _private_subnet(host.vpc_subnet)
    try:
        sandbox_ip = ipaddress.IPv4Address(host.vpc_ip)
        control_ip = ipaddress.IPv4Address(host.control_vpc_ip)
    except (TypeError, ValueError):
        raise ValueError("Microsandbox requires distinct VPC host and control IPv4 addresses") from None
    if (sandbox_ip not in subnet or control_ip not in subnet or sandbox_ip == control_ip
            or sandbox_ip in (subnet.network_address, subnet.broadcast_address)
            or control_ip in (subnet.network_address, subnet.broadcast_address)):
        raise ValueError("Microsandbox requires distinct VPC host and control IPv4 addresses")
    if (host.cpu_virtualization is not True or host.kvm_device is not True
            or host.kvm_read_write is not True or host.msb_doctor_ready is not True):
        raise ValueError("Microsandbox requires a verified usable KVM device and msb doctor")
    if host.network_policy_verified is not True:
        raise ValueError("Microsandbox requires verified guest egress and host/VPC network policy")
    if (host.auto_delete_confirmed is not True or isinstance(host.lease_remaining_seconds, bool)
            or not isinstance(host.lease_remaining_seconds, (int, float))
            or not math.isfinite(host.lease_remaining_seconds)
            or not limits.startup_seconds + limits.max_seconds <= host.lease_remaining_seconds <= 900):
        raise ValueError("Microsandbox requires a bounded, independently enforced VX1 deletion lease")
    if not callable(host.destroy):
        raise ValueError("Microsandbox requires confirmed host teardown")


def _validate_app(app: MicrosandboxApp, host: MicrosandboxHost, limits: MicrosandboxLimits) -> None:
    if (app.instance_id != host.instance_id or not isinstance(app.sandbox_name, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", app.sandbox_name)
            or app.private_binding_verified is not True or not callable(app.destroy)):
        raise ValueError("Microsandbox requires a verified private microVM and teardown")
    if (type(app.cpus) is not int or app.cpus != limits.cpus
            or type(app.memory_mib) is not int or app.memory_mib != limits.memory_mib
            or type(app.max_duration_seconds) is not int or app.max_duration_seconds != limits.max_seconds):
        raise ValueError("Microsandbox resource and lifetime limits were not confirmed")
    try:
        url = urlsplit(app.base_url)
        port = url.port
    except (TypeError, ValueError):
        raise ValueError("Microsandbox requires a private VPC URL on the disposable host") from None
    if (url.scheme != "http" or not 1024 <= (port or 0) <= 65535
            or url.netloc != f"{host.vpc_ip}:{port}" or url.path or url.query or url.fragment):
        raise ValueError("Microsandbox requires a private VPC URL on the disposable host")


def _health_probe(base_url: str, timeout_seconds: float) -> bool:
    with httpx.Client(timeout=timeout_seconds, follow_redirects=False, trust_env=False) as client:
        return client.get(f"{base_url}/health").status_code == 200


class MicrosandboxTargetRunner:
    """One-shot runner for an injected, verified disposable-VX1 backend.

    The local watchdog is best effort if this process dies. The backend's
    independently enforced lease and guest max duration are mandatory. Backend
    calls must honor the passed deadlines; this adapter cannot interrupt a
    stuck remote call or prove a remote assertion without a trusted transport.
    """

    def __init__(
        self, source_dir: str, entrypoint: str = "app.py", *,
        backend: MicrosandboxBackend | None = None,
        limits: MicrosandboxLimits | None = None,
        health_probe: Callable[[str, float], bool] | None = None,
    ) -> None:
        self._source_dir = source_dir
        self._entrypoint = entrypoint
        self._backend = backend
        self._limits = limits if limits is not None else MicrosandboxLimits()
        self._health_probe = health_probe if health_probe is not None else _health_probe
        self._host: MicrosandboxHost | None = None
        self._app: MicrosandboxApp | None = None
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()
        self._started = False

    def start(self) -> str:
        if self._started:
            raise RuntimeError("Microsandbox runners are one-shot; construct a new runner")
        self._started = True
        if self._backend is None:
            raise RuntimeError("microsandbox dispatch is not wired: inject a trusted disposable VX1 backend; refusing to run on the control VM")
        limits = self._limits
        startup_deadline = time.monotonic() + limits.startup_seconds
        try:
            host = self._backend.acquire_host(limits=limits, timeout_seconds=limits.startup_seconds)
            self._host = host
            if not isinstance(host, MicrosandboxHost):
                raise ValueError("Microsandbox backend did not return a verifiable disposable host")
            _validate_host(host, limits)
            runtime_deadline = time.monotonic() + limits.max_seconds
            remaining = startup_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Microsandbox host preflight exceeded the startup deadline")
            app = self._backend.launch(
                host, self._source_dir, self._entrypoint, limits=limits, timeout_seconds=remaining,
            )
            self._app = app
            if not isinstance(app, MicrosandboxApp):
                raise ValueError("Microsandbox backend did not return a verifiable microVM")
            _validate_app(app, host, limits)
            remaining = min(startup_deadline, runtime_deadline) - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Microsandbox target startup exceeded its deadline")
            if self._health_probe(app.base_url, min(remaining, 2.0)) is not True:
                raise RuntimeError("Microsandbox target did not answer /health over the private VPC")
            remaining = min(startup_deadline, runtime_deadline) - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Microsandbox target startup exceeded its deadline")
            timer = threading.Timer(runtime_deadline - time.monotonic(), self._expire)
            timer.daemon = True
            with self._lock:
                self._timer = timer
                timer.start()
            return app.base_url
        except BaseException:
            try:
                self.stop()
            except Exception as cleanup_error:
                raise RuntimeError("Microsandbox startup failed and teardown could not be confirmed") from cleanup_error
            raise

    def _expire(self) -> None:
        try:
            self.stop()
        except Exception:
            logging.getLogger(__name__).error("Microsandbox deadline reached but teardown could not be confirmed")

    def stop(self) -> None:
        """Attempt microVM removal AND VX1 deletion; report any unconfirmed cleanup."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            errors: list[Exception] = []
            for name in ("_app", "_host"):
                resource = getattr(self, name)
                if resource is None:
                    continue
                destroy = getattr(resource, "destroy", None)
                try:
                    if not callable(destroy):
                        raise RuntimeError(f"Microsandbox {name} has no teardown")
                    destroy()
                except Exception as error:
                    errors.append(error)
                else:
                    setattr(self, name, None)
            if errors:
                raise RuntimeError("Microsandbox microVM or VX1 teardown could not be confirmed") from errors[0]

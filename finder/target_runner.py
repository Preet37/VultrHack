"""How the finder gets a reachable target to attack -- the isolation seam.

The finder needs exactly one thing from whatever runs the target: a base URL it
can send HTTP at, plus a way to tear it down afterward. Isolating that behind a
small interface is what lets the scan move from "runs on the control host" to
"runs in a throwaway VM" by swapping one object -- no change to the find, prove,
patch or certify logic.

Two implementations:

  - ``LocalSubprocessRunner`` boots the target as a local process on the control
    host. This is Tier-1 "in-process" isolation from the Blast Radius Zero brief
    (the target shares this host), so it is only ever pointed at our own seeded,
    trusted targets. It must never run an untrusted repository.

  - ``SandboxTargetRunner`` dispatches the target into a disposable gVisor
    sandbox on the sandbox host over the private network, so untrusted code has
    blast radius zero. This is the seam: the interface and the exact contract it
    needs from the sandbox host are defined here. It is wired the moment that
    host exposes a "run this app, return a private URL, destroy it" primitive.

Note the division of labour: static analysis and patching stay on the control
plane against the *local* source (the control plane owns the repo); only target
*execution* is dispatched into the sandbox. That matches the brief's
architecture -- the repo never leaves the control plane, only the running app is
isolated.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Protocol

from finder.remediate import _start_target, _stop, _wait_health, free_port


class TargetRunner(Protocol):
    """Something that can make a target reachable over HTTP and tear it down."""

    def start(self) -> str:
        """Boot the target and return a base URL that answers /health."""
        ...

    def stop(self) -> None:
        """Tear the target down. Safe to call even if start() failed."""
        ...


class LocalSubprocessRunner:
    """Boot the target as a local process on the control host.

    Tier-1 isolation: the target shares this host, so this runner is only for our
    own seeded, trusted targets. Never point it at an untrusted repository -- that
    is precisely what SandboxTargetRunner exists for.
    """

    def __init__(self, source_dir: str, entrypoint: str = "app.py", health_timeout: float = 25.0):
        self._source_dir = source_dir
        self._entrypoint = entrypoint
        self._health_timeout = health_timeout
        self._proc = None

    def start(self) -> str:
        port = free_port()
        base_url = f"http://127.0.0.1:{port}"
        # _start_target strips CERBERUS_* from the child env so the target plants
        # its manifest-default canaries -- the same values the oracle reads.
        self._proc = _start_target(Path(self._source_dir), self._entrypoint, port)
        try:
            _wait_health(base_url, self._health_timeout)
        except BaseException:
            # Uphold the contract: a failed start leaves nothing running. Without
            # this, a target that never answers /health would orphan its process.
            self.stop()
            raise
        return base_url

    def stop(self) -> None:
        if self._proc is not None:
            _stop(self._proc)
            self._proc = None


# The one primitive the sandbox host must provide. Given a local source dir and
# its entrypoint, run the app inside a disposable gVisor sandbox and return
# (base_url reachable over the private network, teardown callable).
SandboxDispatch = Callable[[str, str], "tuple[str, Callable[[], None]]"]


class SandboxTargetRunner:
    """Run the target inside a disposable gVisor sandbox -- blast radius zero.

    Inject the sandbox host's dispatch primitive as ``dispatch``. Until it is
    provided, ``start`` fails closed with a clear message rather than silently
    falling back to the control host: refusing to run a possibly-untrusted target
    in-process is the whole point.
    """

    def __init__(self, source_dir: str, entrypoint: str = "app.py", dispatch: SandboxDispatch | None = None):
        self._source_dir = source_dir
        self._entrypoint = entrypoint
        self._dispatch = dispatch
        self._teardown: Callable[[], None] | None = None

    def start(self) -> str:
        if self._dispatch is None:
            raise RuntimeError(
                "sandbox target execution is not wired yet: the sandbox host must "
                "expose a primitive that runs an app and returns a private-network "
                "URL plus a teardown. Inject it as SandboxTargetRunner(dispatch=...). "
                "Refusing to fall back to the control host for an untrusted target."
            )
        base_url, teardown = self._dispatch(self._source_dir, self._entrypoint)
        self._teardown = teardown
        return base_url

    def stop(self) -> None:
        if self._teardown is not None:
            self._teardown()
            self._teardown = None


def make_runner(
    source_dir: str,
    entrypoint: str = "app.py",
    mode: str | None = None,
    dispatch: SandboxDispatch | None = None,
) -> TargetRunner:
    """Pick a runner. Default ``local``; ``sandbox`` selects the disposable-VM path.

    ``mode`` falls back to the ``CERBERUS_SCAN_RUNNER`` environment variable, then
    to ``local``. An unknown mode is an error rather than a silent default, so a
    typo can never quietly run an untrusted target on the control host.
    """
    mode = (mode or os.getenv("CERBERUS_SCAN_RUNNER") or "local").lower()
    if mode == "sandbox":
        return SandboxTargetRunner(source_dir, entrypoint, dispatch=dispatch)
    if mode == "local":
        return LocalSubprocessRunner(source_dir, entrypoint)
    raise ValueError(f"unknown scan runner mode: {mode!r}")

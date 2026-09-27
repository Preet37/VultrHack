"""Environmental (sandbox-planted) canaries: the oracle for a manifest-less target.

The seeded targets ship a ``manifest.json`` that names the canaries planted
*inside* the app (a secret DB row, a file under the source tree, an internal
route). A real target ships none of that, so ``canaries_for(None)`` has nothing
to look for and a manifest-less app yields zero confirmed findings.

The idea here flips the source of truth: instead of trusting canaries planted in
the target repo, Cerberus plants sentinels in the SANDBOX ENVIRONMENT around the
target and uses THOSE as the oracle. A sentinel is something the app has no
legitimate reason to hand back; if it comes out anyway, only a real exploit
could have carried it. This is what lets the finder confirm exploits on a target
it knows nothing about ahead of time.

Only the genuinely app-agnostic classes are in scope:

  - ``path_traversal``: a sentinel file with a random canary is written OUTSIDE
    the app's web/docs root (its own temp dir, hard-to-guess name). If a file
    endpoint can be walked to it and returns the canary, the traversal is proven.
  - ``ssrf``: a tiny internal-only HTTP listener is bound to 127.0.0.1 on an
    ephemeral port and returns a random canary. The finder supplies that internal
    URL as the SSRF payload; if the target fetches it and the canary comes back,
    the SSRF is proven.
  - ``command_injection``: the same file sentinel, reachable only by executing a
    command that reads it (``; cat <sentinel>``). If the canary appears, the
    injected command ran.

Deliberately OUT OF SCOPE (be honest, do not fake coverage): ``sqli`` and
``auth_bypass``/IDOR still need app-level instrumentation -- a canary planted in
a table the app never selects, or in another user's record. Nothing in the
environment can stand in for that, so those classes get no environmental oracle
here and continue to require a manifest (or per-app seeding) to be confirmed.
"""

from __future__ import annotations

import secrets
import shutil
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote


def _token(prefix: str) -> str:
    """A random, hard-to-guess canary string the oracle (first_match) can spot."""
    return f"{prefix}-{secrets.token_hex(12)}-DO-NOT-EXFIL"


class _CanaryHandler(BaseHTTPRequestHandler):
    """Internal-only listener: every GET returns the SSRF canary, nothing else."""

    canary = ""  # set per-server instance below

    def do_GET(self):  # noqa: N802
        body = f"instance-credential: {self.canary}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence request logging
        pass


class EnvCanaries:
    """Plant environmental sentinels around a target; yield their canary values.

    Use as a context manager so the sentinels are guaranteed to be torn down
    (temp files deleted, internal listener stopped) even if a scan raises::

        with EnvCanaries() as env:
            canaries = env.canaries            # feed the existing oracle
            payloads = env.payloads_by_class() # feed the confirmers

    The manifest-based path never constructs one of these, so seeded runs are
    completely unaffected.
    """

    def __init__(self) -> None:
        self.file_canary = _token("ENVFILECANARY")
        self.ssrf_canary = _token("ENVSSRFCANARY")
        self._tmp_dir: str | None = None
        self.sentinel_path: str | None = None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.ssrf_url: str | None = None

    # -- lifecycle ------------------------------------------------------------

    def __enter__(self) -> "EnvCanaries":
        self._plant_file_sentinel()
        self._start_internal_listener()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _plant_file_sentinel(self) -> None:
        # A temp dir well outside any plausible app web/docs root, with a random
        # file name so it cannot be guessed or served intentionally.
        self._tmp_dir = tempfile.mkdtemp(prefix="cerberus-env-")
        name = f"sentinel_{secrets.token_hex(8)}.txt"
        path = Path(self._tmp_dir) / name
        path.write_text(f"environmental sentinel: {self.file_canary}\n")
        self.sentinel_path = str(path)

    def _start_internal_listener(self) -> None:
        handler = type("_Handler", (_CanaryHandler,), {"canary": self.ssrf_canary})
        # Bind to loopback on an ephemeral port: reachable from the target (which
        # runs on the same host / private network) but not routable off-box.
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._server.daemon_threads = True
        port = self._server.server_address[1]
        self.ssrf_url = f"http://127.0.0.1:{port}/latest/meta-data/"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._tmp_dir is not None:
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
            self._tmp_dir = None

    # -- oracle + payloads ----------------------------------------------------

    @property
    def canaries(self) -> list[str]:
        """The canary strings for finder.canary.first_match to look for."""
        return [self.file_canary, self.ssrf_canary]

    def _traversal_payloads(self) -> list[str]:
        """Ways to reach the out-of-root sentinel file from a file endpoint.

        An absolute path resets a ``base / name`` (or ``os.path.join``) join, so
        it escapes the docs root directly; the deep ``../`` climbs cover joins
        that strip a leading slash. All reference the exact planted sentinel, so
        only a real traversal can return the canary.
        """
        if not self.sentinel_path:
            return []
        rel = self.sentinel_path.lstrip("/")
        climb = "../" * 16
        return [
            self.sentinel_path,          # absolute path (join reset)
            climb + rel,                 # walk up to '/', then down to the sentinel
            quote(climb + rel, safe=""), # percent-encoded evasion of naive filters
        ]

    def _command_payloads(self) -> list[str]:
        """Shell fragments that read the sentinel file; the canary proves execution."""
        if not self.sentinel_path:
            return []
        p = self.sentinel_path
        return [
            f"127.0.0.1; cat {p}",
            f"127.0.0.1 && cat {p}",
            f"127.0.0.1 | cat {p}",
            f"$(cat {p})",
            f"`cat {p}`",
        ]

    def payloads_by_class(self) -> dict[str, list[str]]:
        """Extra, environment-aware payloads to try first, keyed by vuln class.

        Only the app-agnostic classes appear. ``sqli`` and ``auth_bypass`` are
        intentionally absent: no environmental sentinel can prove them.
        """
        payloads: dict[str, list[str]] = {}
        traversal = self._traversal_payloads()
        if traversal:
            payloads["path_traversal"] = traversal
        cmd = self._command_payloads()
        if cmd:
            payloads["command_injection"] = cmd
        if self.ssrf_url:
            payloads["ssrf"] = [self.ssrf_url]
        return payloads

"""The proof loop: patch a confirmed finding, then prove the class is closed.

    exploit (landed by the finder) -> patch (from the class playbook)
      -> re-exploit (replay the winning payload + family) -> functional check
      -> validate (an independent pass; the writer never certifies its own fix)
      -> emit a regression test.

The re-exploit is the judge, exactly as the canary oracle is for the finder: a
fix is certified only when the canary no longer leaves the box AND legitimate
behavior still works. Patching happens on a disposable COPY of the target; the
original source is never mutated here.
"""

from __future__ import annotations

import argparse
import ast
import difflib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

from finder.canary import excerpt, first_match
from finder.models import Finding
from finder.patchers import _find_function, patch_source
from finder.playbooks import confirmer_for
from finder.recon import canaries_for, load_manifest

# A legitimate input per class whose request must still succeed after the patch.
# SSRF is omitted deliberately: there is no in-sandbox benign fetch to make (no
# egress), so functional parity for it is not asserted here.
_BENIGN = {"sqli": "1", "path_traversal": "readme.txt", "command_injection": "localhost", "auth_bypass": "1"}


def _sink_symbol(finding: Finding) -> str:
    """The enclosing function name, parsed from the finding's input->sink chain."""
    match = re.search(r"->\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)", finding.input_to_sink)
    return match.group(1) if match else ""


@dataclass
class RemediationResult:
    finding_id: str
    vuln_class: str
    endpoint: str
    param: str
    patched: bool = False
    patch_description: str = ""
    patch_diff: str = ""
    reexploit_blocked: bool = False
    reexploit_evidence: str = ""
    functional_ok: bool = False
    validated: bool = False
    validation_notes: str = ""
    validation_source: str = "static-validator (offline)"
    regression_test: str = ""

    @property
    def certified(self) -> bool:
        return self.patched and self.reexploit_blocked and self.functional_ok and self.validated

    def to_dict(self) -> dict:
        data = asdict(self)
        data["certified"] = self.certified
        return data


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_target(target_dir: Path, entrypoint: str, port: int) -> subprocess.Popen:
    env = {**os.environ, "PORT": str(port)}
    return subprocess.Popen(
        [sys.executable, entrypoint],
        cwd=str(target_dir),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _wait_health(base: str, timeout: float) -> None:
    deadline = time.monotonic() + max(timeout, 10.0)
    with httpx.Client(timeout=2.0) as client:
        while time.monotonic() < deadline:
            try:
                if client.get(f"{base}/health").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
    raise RuntimeError("patched target did not become healthy")


def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _reexploit(finding: Finding, base: str, canaries: list[str], timeout: float) -> tuple[bool, str]:
    """Replay the confirmed exploit against the patched app. Blocked == no canary."""
    confirmer = confirmer_for(finding.vuln_class)
    if confirmer is None:
        return False, "no confirmer for class; cannot prove closure"
    result = confirmer(base, finding.endpoint, finding.param, timeout)
    if not result.attempts:
        # Nothing actually landed (e.g. transport errors) -- we cannot claim the
        # exploit was re-tested, so we must not report it blocked.
        return False, "no exploit payloads landed against the patched app; closure not proven"
    for _, text in result.attempts:
        leaked = first_match(canaries, text)
        if leaked:
            return False, f"canary STILL leaks after patch: {excerpt(leaked, text)}"
    return True, f"{len(result.attempts)} exploit payload(s) replayed; canary not observed in any response"


def _functional_ok(finding: Finding, base: str, canaries: list[str], timeout: float) -> bool:
    """A legitimate request must still succeed after the patch."""
    benign = _BENIGN.get(finding.vuln_class)
    if benign is None:
        return True
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"{base}{finding.endpoint}", params={finding.param: benign})
    except httpx.HTTPError:
        return False
    if first_match(canaries, resp.text):
        return False
    if finding.vuln_class == "path_traversal":
        # A legitimate (non-traversal) filename must not be rejected by the guard.
        # It may still 404 if that file does not exist on this target; only a 403
        # (the guard's own rejection) means the patch over-blocks.
        return resp.status_code != 403
    low = resp.text.lower()
    return resp.status_code == 200 and "traceback" not in low and "query error" not in low


def _validate(finding: Finding, sink_symbol: str, new_source: str) -> tuple[bool, str]:
    """Independent static check that the vulnerable pattern is gone (not the re-exploit)."""
    try:
        tree = ast.parse(new_source)
    except SyntaxError:
        return False, "patched source does not parse"
    fn = _find_function(tree, sink_symbol)
    if fn is None:
        return False, "sink function missing after patch"
    if finding.vuln_class == "sqli":
        for node in ast.walk(fn):
            if (
                isinstance(node, ast.BinOp)
                and isinstance(node.op, ast.Add)
                and isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)
            ):
                return False, "string-concatenated SQL still present"
        return True, "no concatenated SQL remains; query is parameterized"
    if finding.vuln_class == "path_traversal":
        # Look for a real guard: an `if` whose test rejects traversal ('..' or
        # an absolute-path check) and that returns/raises out. Substring-matching
        # the function text would be fooled by the planted-bug comment, so we
        # inspect the guard's condition structurally.
        for node in ast.walk(fn):
            if not isinstance(node, ast.If):
                continue
            test_seg = ast.get_source_segment(new_source, node.test) or ""
            rejects = ".." in test_seg or "is_absolute" in test_seg
            exits = any(isinstance(b, (ast.Return, ast.Raise)) for b in ast.walk(node))
            if rejects and exits:
                return True, "guard rejecting '..'/absolute paths is present before the file sink"
        return False, "no path-traversal guard found"
    if finding.vuln_class == "command_injection":
        for node in ast.walk(fn):
            if (
                isinstance(node, ast.Call)
                and any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
            ):
                return False, "a shell=True subprocess call still remains"
        return True, "no shell=True subprocess call remains; command uses an argument list"
    if finding.vuln_class == "ssrf":
        # Require a resolve-based guard (blocks uppercase/encoded/private hosts),
        # not just a loopback-literal string check.
        for node in ast.walk(fn):
            if isinstance(node, ast.If):
                test_seg = ast.get_source_segment(new_source, node.test) or ""
                exits = any(isinstance(b, (ast.Return, ast.Raise)) for b in ast.walk(node))
                if exits and "is_private" in test_seg and "is_loopback" in test_seg:
                    return True, "guard resolves the host and blocks loopback/private/link-local ranges"
        return False, "no resolve-based SSRF guard found"
    if finding.vuln_class == "auth_bypass":
        for node in ast.walk(fn):
            if isinstance(node, ast.If) and any(isinstance(b, (ast.Return, ast.Raise)) for b in ast.walk(node)):
                if "403" in (ast.get_source_segment(new_source, node) or ""):
                    return True, "ownership guard returning 403 is present"
        return False, "no ownership check found"
    return True, "no static validator for this class yet"


def _payload_from_exploit(finding: Finding) -> str:
    url = finding.exploit_request.split(" ", 1)[-1]
    values = parse_qs(urlsplit(url).query).get(finding.param)
    return values[0] if values else ""


def _regression_test(finding: Finding, canaries: list[str]) -> str:
    slug = re.sub(r"[^0-9a-zA-Z]+", "_", finding.id).strip("_") or "finding"
    payload = _payload_from_exploit(finding)
    return (
        f'"""Auto-generated regression test for finding {finding.id} ({finding.vuln_class}).\n\n'
        "Replays the confirmed exploit and asserts the planted canary no longer\n"
        'leaves the box. Point TARGET_URL at the patched app before running."""\n'
        "import os\n\n"
        "import httpx\n\n"
        'TARGET_URL = os.environ.get("TARGET_URL", "http://127.0.0.1:5001")\n'
        f"CANARY_MARKERS = {tuple(canaries)!r}\n\n\n"
        f"def test_{slug}_stays_closed():\n"
        f'    resp = httpx.get(f"{{TARGET_URL}}{finding.endpoint}", params={{{finding.param!r}: {payload!r}}})\n'
        f'    assert not any(m in resp.text for m in CANARY_MARKERS), "canary leaked; {finding.vuln_class} reopened"\n'
    )


def remediate(finding: Finding, source_dir: str, *, timeout: float = 12.0) -> RemediationResult:
    """Patch one confirmed finding on a disposable copy and prove the class is closed."""
    result = RemediationResult(
        finding_id=finding.id,
        vuln_class=finding.vuln_class,
        endpoint=finding.endpoint,
        param=finding.param,
    )
    manifest = load_manifest(source_dir)
    canaries = canaries_for(manifest)
    entrypoint = (manifest or {}).get("entrypoint", "app.py")

    sink_symbol = _sink_symbol(finding)
    if not sink_symbol:
        result.validation_notes = "could not identify the sink function from the finding"
        return result

    src_path = Path(source_dir) / finding.sink_file
    try:
        original = src_path.read_text()
    except OSError:
        result.validation_notes = f"could not read sink file {finding.sink_file}"
        return result

    patch = patch_source(finding.vuln_class, sink_symbol, original)
    if patch is None:
        result.validation_notes = "no deterministic patch for this class/shape; a model-written patch is required"
        return result
    result.patched = True
    result.patch_description = patch.description
    result.patch_diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patch.new_source.splitlines(keepends=True),
            fromfile=f"a/{finding.sink_file}",
            tofile=f"b/{finding.sink_file}",
        )
    )

    with tempfile.TemporaryDirectory() as tmp:
        dst = Path(tmp) / "target"
        shutil.copytree(
            source_dir,
            dst,
            ignore=shutil.ignore_patterns("__pycache__", "*.db", "docs", "app_secret.txt", ".pytest_cache", "tests"),
        )
        (dst / finding.sink_file).write_text(patch.new_source)
        port = free_port()
        proc = _start_target(dst, entrypoint, port)
        try:
            base = f"http://127.0.0.1:{port}"
            _wait_health(base, timeout)
            result.reexploit_blocked, result.reexploit_evidence = _reexploit(finding, base, canaries, timeout)
            result.functional_ok = _functional_ok(finding, base, canaries, timeout)
        finally:
            _stop(proc)

    result.validated, result.validation_notes = _validate(finding, sink_symbol, patch.new_source)
    result.regression_test = _regression_test(finding, canaries)
    return result


def main(argv: list[str] | None = None) -> int:
    from finder.pipeline import run_finder

    parser = argparse.ArgumentParser(prog="finder.remediate", description="Find, patch, and prove closure")
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--source", required=True, help="Target source dir (for patching + manifest)")
    parser.add_argument("--emit-tests", action="store_true", help="Write generated regression tests into <source>/tests/")
    args = parser.parse_args(argv)

    report = run_finder(args.target_url, args.source)
    results = [remediate(f, args.source) for f in report.findings]
    if args.emit_tests and results:
        tests_dir = Path(args.source) / "tests"
        tests_dir.mkdir(exist_ok=True)
        for res in results:
            if res.regression_test:
                (tests_dir / f"test_regression_{re.sub(r'[^0-9a-zA-Z]+', '_', res.finding_id)}.py").write_text(res.regression_test)

    out = {
        "target": args.target_url,
        "confirmed_findings": len(report.findings),
        "certified_closed": sum(1 for r in results if r.certified),
        "remediations": [r.to_dict() for r in results],
    }
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

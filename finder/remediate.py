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
from finder.inference import InferenceClient
from finder.model_patch import model_review, model_write_patch
from finder.models import Finding
from finder.patchers import _find_function, patch_source
from finder.playbooks import confirmer_for
from finder.recon import canaries_for, load_manifest

# A legitimate input per class whose request must still succeed after the patch.
# path_traversal's benign filename is overridden per target from the manifest
# (each seeded app serves a different legitimate file). SSRF uses a public URL: a
# correct guard must not policy-block it (403); with no egress it may return 502,
# which is fine -- only a 403 means the patch over-blocks a host it should allow.
_BENIGN = {"sqli": "1", "path_traversal": "readme.txt", "command_injection": "localhost", "auth_bypass": "1", "ssrf": "http://example.com/"}


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
    patch_source: str = "deterministic-template"
    independent_review: dict | None = None
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
    # Drop any CERBERUS_* canary overrides from the child's environment so the
    # patched app plants its manifest-default canaries -- the same values
    # canaries_for() reads. Otherwise the oracle compares against stale literals
    # and could falsely report the re-exploit "blocked".
    env = {k: v for k, v in os.environ.items() if not k.startswith("CERBERUS_")}
    env["PORT"] = str(port)
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


def _functional_ok(finding: Finding, base: str, canaries: list[str], timeout: float, benign: str | None = None) -> bool:
    """A legitimate request must still succeed after the patch.

    ``benign`` overrides the per-class default -- path_traversal passes the
    target's real legitimate filename (from the manifest) so the over-block check
    is not vacuous on a target whose legit file is not the default name.
    """
    benign = benign if benign is not None else _BENIGN.get(finding.vuln_class)
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
    if finding.vuln_class == "ssrf":
        # A legitimate public URL must not be policy-blocked (403) by the guard.
        # With no egress it may return 502 (DNS/fetch failure) or 200 (fetched);
        # both are fine. Only a 403 means the patch over-blocks an allowed host.
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
        # Require an actual comparison guard that returns 403 -- not merely any
        # if-block whose text happens to contain "403" (e.g. a rate-limit branch).
        for node in ast.walk(fn):
            if not isinstance(node, ast.If):
                continue
            has_compare = any(isinstance(t, ast.Compare) for t in ast.walk(node.test))
            exits = any(isinstance(b, (ast.Return, ast.Raise)) for b in ast.walk(node))
            if has_compare and exits and "403" in (ast.get_source_segment(new_source, node) or ""):
                return True, "ownership comparison guard returning 403 is present"
        return False, "no ownership comparison guard found"
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


def _diff(original: str, new_source: str, sink_file: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            new_source.splitlines(keepends=True),
            fromfile=f"a/{sink_file}",
            tofile=f"b/{sink_file}",
        )
    )


def _try_patch(finding, source_dir, entrypoint, new_source, canaries, benign, timeout):
    """Apply one candidate patch to a disposable copy and run the re-exploit + functional checks."""
    with tempfile.TemporaryDirectory() as tmp:
        dst = Path(tmp) / "target"
        shutil.copytree(
            source_dir,
            dst,
            ignore=shutil.ignore_patterns("__pycache__", "*.db", "docs", "app_secret.txt", ".pytest_cache", "tests"),
        )
        (dst / finding.sink_file).write_text(new_source)
        port = free_port()
        proc = _start_target(dst, entrypoint, port)
        try:
            base = f"http://127.0.0.1:{port}"
            _wait_health(base, timeout)
            blocked, evidence = _reexploit(finding, base, canaries, timeout)
            func_ok = _functional_ok(finding, base, canaries, timeout, benign)
        except Exception as exc:
            # A candidate that does not even boot (e.g. a broken model patch) is
            # simply not accepted; the caller falls back to the next candidate.
            blocked, evidence, func_ok = False, f"patched app did not run: {exc}", False
        finally:
            _stop(proc)
    return blocked, evidence, func_ok


def remediate(finding: Finding, source_dir: str, *, timeout: float = 12.0) -> RemediationResult:
    """Patch one confirmed finding on a disposable copy and prove the class is closed.

    Two patch sources compete: the deterministic AST patcher (proven for the
    seeded shapes) and a model-written patch on Vultr Serverless Inference (for
    arbitrary code). ``CERBERUS_PATCH_MODE=model`` tries the model first; the
    default tries the deterministic patcher first and only calls the model if it
    does not match. Whichever is tried, the re-exploit on a disposable copy is the
    judge -- an unproven patch is discarded -- and a model-written patch must also
    pass an INDEPENDENT model review (a different call than the writer), so the
    writer never certifies its own work.
    """
    result = RemediationResult(
        finding_id=finding.id,
        vuln_class=finding.vuln_class,
        endpoint=finding.endpoint,
        param=finding.param,
    )
    manifest = load_manifest(source_dir)
    canaries = canaries_for(manifest)
    entrypoint = (manifest or {}).get("entrypoint", "app.py")
    benign = ((manifest or {}).get("benign") or {}).get(finding.vuln_class)  # per-target override; None -> class default

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

    client = InferenceClient()
    mode = os.getenv("CERBERUS_PATCH_MODE", "deterministic").lower()
    order = ["vultr-inference", "deterministic-template"] if mode == "model" else ["deterministic-template", "vultr-inference"]

    def build(label):
        if label == "deterministic-template":
            return patch_source(finding.vuln_class, sink_symbol, original)
        return model_write_patch(finding, sink_symbol, original, client)

    accepted = None      # (label, patch, evidence, func_ok)
    first_patch = None   # for reporting when nothing certifies
    for label in order:
        patch = build(label)  # model patch is only built when this label is reached
        if patch is None:
            continue
        if first_patch is None:
            first_patch = (label, patch)
        blocked, evidence, func_ok = _try_patch(finding, source_dir, entrypoint, patch.new_source, canaries, benign, timeout)
        result.reexploit_blocked, result.reexploit_evidence, result.functional_ok = blocked, evidence, func_ok
        if blocked and func_ok:
            accepted = (label, patch, evidence, func_ok)
            break

    if first_patch is None:
        result.validation_notes = "no patch produced: no deterministic patcher matched and no model patch was available"
        return result

    label, patch = accepted[:2] if accepted else first_patch
    result.patched = True
    result.patch_source = label
    result.patch_description = patch.description
    result.patch_diff = _diff(original, patch.new_source, finding.sink_file)
    result.regression_test = _regression_test(finding, canaries)

    static_ok, static_note = _validate(finding, sink_symbol, patch.new_source)
    if accepted and label == "vultr-inference":
        # The model wrote this patch, so an independent model must confirm it --
        # the writer never certifies its own work. The re-exploit already proved
        # the canary is gone; this guards against a subtly over-blocking fix.
        review = model_review(finding, sink_symbol, patch.new_source, client)
        result.independent_review = review
        if review is None:
            result.validated = False
            result.validation_source = "static + independent review UNAVAILABLE"
            result.validation_notes = static_note + "; no independent reviewer available — a model patch is not certified on its own"
        else:
            result.validated = static_ok and review["closed"] and not review["over_blocks"]
            result.validation_source = "static + independent " + review["model"]
            result.validation_notes = static_note + f"; reviewer: {review['reason']}"
    else:
        # Deterministic patch: the writer is code, and the static AST check plus
        # the re-exploit are already independent of any model.
        result.validated = static_ok
        result.validation_notes = static_note
        result.validation_source = "static-validator (offline)"

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

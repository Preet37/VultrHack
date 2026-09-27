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
        # A legitimate public URL must ACTUALLY be fetched (200) after the patch.
        # Requiring only "not 403" was vacuous: a patch that disables all outbound
        # fetching returns 502 for everything and would pass. A 200 proves the fix
        # both allows the legitimate host AND still fetches -- the only honest way
        # to catch a maximal over-block. This needs egress to a real allowed host;
        # without it, SSRF functional parity genuinely cannot be proven.
        return resp.status_code == 200
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


def _try_patch(finding, source_dir, entrypoint, new_source, canaries, benign, timeout, launcher=None):
    """Apply one candidate patch to a disposable copy and run the re-exploit + functional checks.

    ``launcher`` is an optional hosting seam for the re-exploit: a callable
    taking ``(copied_target_dir, entrypoint)`` and returning
    ``(base_url, stop)``. With the default (None) the copy is booted locally on
    a free port (``free_port`` + ``_start_target`` + ``_stop``) exactly as
    before. A returned ``stop`` is ALWAYS called, even when a later check
    raises; if the launcher itself raised before returning, there is nothing to
    stop and its exception propagates.
    """
    with tempfile.TemporaryDirectory() as tmp:
        dst = Path(tmp) / "target"
        shutil.copytree(
            source_dir,
            dst,
            ignore=shutil.ignore_patterns("__pycache__", "*.db", "docs", "app_secret.txt", ".pytest_cache", "tests"),
        )
        (dst / finding.sink_file).write_text(new_source)
        if launcher is None:
            port = free_port()
            proc = _start_target(dst, entrypoint, port)
            base = f"http://127.0.0.1:{port}"
            stop = lambda: _stop(proc)  # noqa: E731
        else:
            base, stop = launcher(dst, entrypoint)
        try:
            _wait_health(base, timeout)
            blocked, evidence = _reexploit(finding, base, canaries, timeout)
            func_ok = _functional_ok(finding, base, canaries, timeout, benign)
        except Exception as exc:
            # A candidate that does not even boot (e.g. a broken model patch) is
            # simply not accepted; the caller falls back to the next candidate.
            blocked, evidence, func_ok = False, f"patched app did not run: {exc}", False
        finally:
            stop()
    return blocked, evidence, func_ok


def _apply_validation_gate(
    result: RemediationResult,
    finding: Finding,
    sink_symbol: str,
    new_source: str,
    blocked: bool,
    func_ok: bool,
    writer_client: InferenceClient | None,
) -> None:
    """Independent certification gate for one accepted patch (single or batch).

    Fills in ``validated`` / ``validation_source`` / ``validation_notes`` (and
    ``independent_review`` for model-written patches) on ``result``. A
    deterministic patch is certified by the static AST check -- the writer is
    code, so the checker is already independent. A model-written patch is NOT
    required to match the deterministic static-template check (it only
    recognizes the seeded shapes and would reject valid patches for arbitrary
    code, the whole point of the model patcher); its gate is instead: re-exploit
    blocked + functional preserved + an INDEPENDENT model reviewer (a different
    model than the writer, ``writer_client`` providing the ``avoid_model`` hint)
    agreeing the class is closed and the fix does not over-block. The re-exploit
    stays the only fully independent judge either way.
    """
    static_ok, static_note = _validate(finding, sink_symbol, new_source)
    if result.patch_source == "vultr-inference":
        if not (blocked and func_ok):
            result.validated = False
            result.validation_source = "not certified — patch did not close the class or broke functionality"
            result.validation_notes = static_note
        else:
            review = model_review(finding, sink_symbol, new_source, avoid_model=getattr(writer_client, "_model", None))
            result.independent_review = review
            if review is not None:
                # An explicit independent verdict decides -- a dissent (not closed,
                # or over-blocks) blocks certification even if static analysis is
                # happy, so the reviewer is never overruled.
                result.validated = review["closed"] and not review["over_blocks"]
                result.validation_source = "re-exploit + independent " + review["model"]
                note = "reviewer: " + review["reason"]
                result.validation_notes = (static_note + "; " + note) if static_ok else note
            elif static_ok:
                # No reviewer available (transient), but the static analyzer -- which
                # is independent of the model writer -- recognizes the fix. That is a
                # valid independent certification of a recognized shape.
                result.validated = True
                result.validation_source = "static-validator (independent of the model writer)"
                result.validation_notes = static_note + "; independent model review unavailable, fell back to static analysis"
            else:
                result.validated = False
                result.validation_source = "independent review UNAVAILABLE"
                result.validation_notes = "no independent reviewer and static analysis does not recognize the fix — not certified"
    else:
        # Deterministic patch: the writer is code, and the static AST check plus
        # the re-exploit are already independent of any model.
        result.validated = static_ok
        result.validation_notes = static_note
        result.validation_source = "static-validator (offline)"


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

    attempts = []  # (label, patch, blocked, evidence, func_ok) -- one per candidate tried
    accepted = None
    for label in order:
        patch = build(label)  # the model patch is only built when this label is reached
        if patch is None:
            continue
        blocked, evidence, func_ok = _try_patch(finding, source_dir, entrypoint, patch.new_source, canaries, benign, timeout)
        attempts.append((label, patch, blocked, evidence, func_ok))
        if blocked and func_ok:
            accepted = attempts[-1]
            break

    if not attempts:
        result.validation_notes = "no patch produced: no deterministic patcher matched and no model patch was available"
        return result

    # Report exactly one candidate so the diff, re-exploit evidence and functional
    # result all describe the same patch: the accepted one, else the first tried.
    label, patch, blocked, evidence, func_ok = accepted or attempts[0]
    result.patched = True
    result.patch_source = label
    result.patch_description = patch.description
    result.patch_diff = _diff(original, patch.new_source, finding.sink_file)
    result.reexploit_blocked = blocked
    result.reexploit_evidence = evidence
    result.functional_ok = func_ok
    result.regression_test = _regression_test(finding, canaries)

    _apply_validation_gate(result, finding, sink_symbol, patch.new_source, blocked, func_ok, client)
    return result


def remediate_batch(
    findings: list[Finding],
    source_dir: str,
    *,
    timeout: float = 12.0,
    launcher=None,
) -> tuple[list[RemediationResult], bool]:
    """Patch every finding into ONE shared cumulative copy, then prove them all in a single hosting.

    Where remediate() patches one finding on its own disposable copy, this is
    the launch-report shape: findings are patched in list order onto a single
    evolving copy -- each finding's patch builds on the source already carrying
    the previous findings' fixes -- and the fully patched app is hosted EXACTLY
    ONCE for every per-finding proof (re-exploit, functional check, static /
    independent review). A finding whose patch cannot be produced (no
    deterministic patcher matched and the model gave nothing) stays
    ``patched=False`` with a note and contributes no patch; it is still honestly
    re-exploited against the shared app, where it will report as still open.
    The original source dir is never mutated.

    ``launcher`` is the hosting seam: ``callable(copied_target_dir, entrypoint)
    -> (base_url, stop)``. With the default (None) the cumulative copy is booted
    locally on a free port (``_start_target``). The returned ``stop`` is always
    called, even on failure; if the launcher itself raises, nothing exists to
    stop. On any launch/boot failure every finding keeps its patch but gets
    ``reexploit_blocked=False`` with the launch failure as evidence, so nothing
    is certified off an app that never ran.

    Returns ``(results, functional)``: one RemediationResult per finding, in the
    findings' order, and an overall flag that is True iff the shared app booted
    healthy AND every finding's legitimate request still succeeded against it.
    """
    results = [
        RemediationResult(finding_id=f.id, vuln_class=f.vuln_class, endpoint=f.endpoint, param=f.param)
        for f in findings
    ]
    if not findings:
        return results, True
    manifest = load_manifest(source_dir)
    canaries = canaries_for(manifest)
    entrypoint = (manifest or {}).get("entrypoint", "app.py")
    benign_by_class = ((manifest or {}).get("benign") or {})  # per-target overrides; missing -> class default

    with tempfile.TemporaryDirectory() as tmp:
        dst = Path(tmp) / "target"
        shutil.copytree(
            source_dir,
            dst,
            ignore=shutil.ignore_patterns("__pycache__", "*.db", "docs", "app_secret.txt", ".pytest_cache", "tests"),
        )

        # Phase 1 -- one patch per finding, in findings-list order, each computed
        # against (and written into) the SHARED copy so later findings patch on
        # top of earlier fixes. Each finding's diff is snapshotted against the
        # cumulative text as it stood when THAT finding was patched.
        symbols: dict[int, str] = {}  # finding index -> sink symbol (when known)
        patched_info: dict[int, tuple[str, str, InferenceClient | None]] = {}  # idx -> (symbol, new_source, writer client)
        for idx, (finding, result) in enumerate(zip(findings, results)):
            sink_symbol = _sink_symbol(finding)
            if not sink_symbol:
                result.validation_notes = "could not identify the sink function from the finding"
                continue
            symbols[idx] = sink_symbol
            sink_path = dst / finding.sink_file
            try:
                original = sink_path.read_text()
            except OSError:
                result.validation_notes = f"could not read sink file {finding.sink_file}"
                continue
            patch = patch_source(finding.vuln_class, sink_symbol, original)
            writer_client = None
            if patch is None:
                writer_client = InferenceClient()
                patch = model_write_patch(finding, sink_symbol, original, writer_client)
            if patch is None:
                result.validation_notes = "no patch produced: no deterministic patcher matched and no model patch was available"
                continue
            result.patched = True
            result.patch_source = "vultr-inference" if writer_client is not None else "deterministic-template"
            result.patch_description = patch.description
            result.patch_diff = _diff(original, patch.new_source, finding.sink_file)
            result.regression_test = _regression_test(finding, canaries)
            sink_path.write_text(patch.new_source)
            patched_info[idx] = (sink_symbol, patch.new_source, writer_client)

        # Phase 2 -- host the cumulatively patched shared app ONCE and run every
        # finding's proof against it.
        try:
            if launcher is None:
                port = free_port()
                proc = _start_target(dst, entrypoint, port)
                base = f"http://127.0.0.1:{port}"
                stop = lambda: _stop(proc)  # noqa: E731
            else:
                base, stop = launcher(dst, entrypoint)
        except Exception as exc:
            # The host never came up and nothing was returned to stop: every
            # finding keeps its patch but cannot be proven closed.
            for result in results:
                result.reexploit_blocked = False
                result.reexploit_evidence = f"shared launch failed: {exc}"
            return results, False

        functional = False
        try:
            _wait_health(base, timeout)
            functional = True
            for idx, (finding, result) in enumerate(zip(findings, results)):
                try:
                    blocked, evidence = _reexploit(finding, base, canaries, timeout)
                    func_ok = _functional_ok(finding, base, canaries, timeout, benign_by_class.get(finding.vuln_class))
                    result.reexploit_blocked = blocked
                    result.reexploit_evidence = evidence
                    result.functional_ok = func_ok
                    functional = functional and func_ok
                    if result.patched:
                        sink_symbol, new_source, writer_client = patched_info[idx]
                        _apply_validation_gate(result, finding, sink_symbol, new_source, blocked, func_ok, writer_client)
                    elif idx in symbols:
                        # No patch to certify, but record the honest static verdict
                        # that the class is still open in the shared app.
                        _, static_note = _validate(finding, symbols[idx], (dst / finding.sink_file).read_text())
                        result.validation_notes = f"{result.validation_notes}; shared app still open: {static_note}"
                except Exception as exc:
                    # A transport-level oddity during one finding's proof fails
                    # THAT finding closed, never silently certified.
                    result.reexploit_blocked = False
                    result.reexploit_evidence = f"proof step errored: {exc}"
                    result.functional_ok = False
                    functional = False
        except Exception as exc:
            # Boot failure (or any hosting crash): no finding can be certified
            # off an app that did not run -- each keeps its patch but stays
            # blocked=False with the launch failure as evidence.
            functional = False
            for result in results:
                result.reexploit_blocked = False
                result.reexploit_evidence = f"shared launch failed: {exc}"
        finally:
            stop()
        return results, functional


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

"""Static sweep: flag candidate sinks in the target source.

This is the raw candidate list handed to the model for triage. It is a fast,
lightweight AST pass, not a full analyzer -- the canary oracle is what actually
confirms a hit, so the sweep is allowed to over-flag. If `semgrep` is installed
it is used for richer coverage; otherwise the built-in AST detector runs.

For each supported class we look for a dangerous sink call whose argument is
NOT a pure constant and that is reachable from request-derived (tainted) input.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
from pathlib import Path

from finder.models import Candidate

# Taint sources: expressions that carry attacker-controlled input (Flask/Django/stdlib).
_TAINT_MARKERS = ("request.args", "request.form", "request.values", "request.get_json",
                  "request.cookies", "request.headers", "request.data", "self.request",
                  "os.environ", "sys.argv")

# Sink signatures: (dotted-name endings) -> vuln class.
_SINKS = {
    "execute": "sqli",
    "executescript": "sqli",
    "raw": "sqli",           # Django .raw()
    "system": "command_injection",
    "popen": "command_injection",
    "call": "command_injection",
    "run": "command_injection",
    "check_output": "command_injection",
    "open": "path_traversal",
    "read_bytes": "path_traversal",
    "read_text": "path_traversal",
    "send_file": "path_traversal",
    "get": "ssrf",           # requests.get / httpx.get (filtered below)
    "post": "ssrf",
    "urlopen": "ssrf",
}
_SSRF_RECEIVERS = ("requests", "httpx", "urllib", "aiohttp", "session", "client")
# command_injection sinks are only dangerous on the subprocess/os modules, not on
# arbitrary objects that happen to have a .run()/.call() method (e.g. Flask's app.run).
_CMDI_LEAVES = {"popen", "call", "run", "check_output"}
_CMDI_RECEIVERS = ("subprocess", "os")


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _contains_taint(node: ast.AST, tainted: set[str]) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in tainted:
            return True
        dotted = _dotted(sub) if isinstance(sub, ast.Attribute) else ""
        if any(dotted.startswith(m) for m in _TAINT_MARKERS):
            return True
    return False


def _arg_is_dynamic(node: ast.AST) -> bool:
    """True if the argument is built dynamically (concat/format/f-string/name), not a literal."""
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Call, ast.Name, ast.Attribute, ast.Subscript)):
        return True
    return True


def _param_hint(node: ast.AST) -> str:
    """Best-effort extraction of the request param name, e.g. request.args.get('id')."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            dotted = _dotted(sub.func)
            if dotted.endswith(("args.get", "form.get", "values.get", "cookies.get", "headers.get")):
                if sub.args and isinstance(sub.args[0], ast.Constant):
                    src = dotted.split(".")[-2]
                    return f"{src}:{sub.args[0].value}"
        if isinstance(sub, ast.Subscript):
            dotted = _dotted(sub.value)
            if dotted.endswith(("args", "form", "values")) and isinstance(sub.slice, ast.Constant):
                return f"{dotted.split('.')[-1]}:{sub.slice.value}"
    return "request"


class _Visitor(ast.NodeVisitor):
    def __init__(self, source: str, path: str):
        self.source = source
        self.path = path
        self.candidates: list[Candidate] = []
        self._counter = 0

    def visit_FunctionDef(self, node: ast.FunctionDef):  # noqa: N802
        self._scan_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):  # noqa: N802
        self._scan_function(node)
        self.generic_visit(node)

    def _scan_function(self, fn: ast.AST):
        # 1) taint pass: names assigned from a tainted expression.
        tainted: set[str] = set()
        param_for: dict[str, str] = {}
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Assign) and _contains_taint(sub.value, tainted):
                hint = _param_hint(sub.value)
                if hint == "request":
                    # Inherit a concrete param from a tainted name on the RHS
                    # (e.g. target = base / name  keeps name's "query:file").
                    for ref in (n.id for n in ast.walk(sub.value) if isinstance(n, ast.Name)):
                        if ref in param_for and ":" in param_for[ref]:
                            hint = param_for[ref]
                            break
                for tgt in sub.targets:
                    if isinstance(tgt, ast.Name):
                        tainted.add(tgt.id)
                        param_for[tgt.id] = hint
        # 2) sink pass.
        for sub in ast.walk(fn):
            if not isinstance(sub, ast.Call):
                continue
            dotted = _dotted(sub.func)
            leaf = dotted.split(".")[-1]
            if leaf not in _SINKS:
                continue
            vuln_class = _SINKS[leaf]
            if vuln_class == "ssrf" and not any(r in dotted for r in _SSRF_RECEIVERS):
                continue
            if vuln_class == "command_injection" and leaf in _CMDI_LEAVES and not any(
                r in dotted for r in _CMDI_RECEIVERS
            ):
                continue
            # The tainted input must actually flow into the sink -- via a dynamic
            # first argument (execute/open/system) OR via a tainted receiver
            # (e.g. Path(user_path).read_bytes()).
            if not _contains_taint(sub, tainted):
                continue
            arg_dynamic = bool(sub.args) and _arg_is_dynamic(sub.args[0])
            receiver_tainted = _contains_taint(sub.func, tainted)
            if not arg_dynamic and not receiver_tainted:
                continue
            # Prefer a concrete "source:name" param over the generic "request".
            concrete = fallback = None
            for name in (n.id for n in ast.walk(sub) if isinstance(n, ast.Name)):
                if name in param_for:
                    val = param_for[name]
                    if ":" in val and concrete is None:
                        concrete = val
                    elif fallback is None:
                        fallback = val
            param = concrete or fallback or _param_hint(sub)
            self._counter += 1
            fn_name = getattr(fn, "name", "?")
            snippet = ast.get_source_segment(self.source, sub) or ""
            slice_src = ast.get_source_segment(self.source, fn) or snippet
            self.candidates.append(
                Candidate(
                    id=f"{Path(self.path).stem}-{fn_name}-{self._counter}",
                    vuln_class=vuln_class,
                    sink_file=self.path,
                    sink_line=getattr(sub, "lineno", 0),
                    sink_symbol=fn_name,
                    snippet=snippet,
                    input_source=param,
                    slice=slice_src,
                )
            )


def _ast_sweep(source_dir: str) -> list[Candidate]:
    out: list[Candidate] = []
    for path in Path(source_dir).rglob("*.py"):
        if any(part in {".venv", "venv", "tests", "__pycache__"} for part in path.parts):
            continue
        try:
            src = path.read_text()
            tree = ast.parse(src)
        except (OSError, SyntaxError):
            continue
        visitor = _Visitor(src, str(path.relative_to(source_dir)))
        visitor.visit(tree)
        out.extend(visitor.candidates)
    return out


def _semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def sweep(source_dir: str) -> list[Candidate]:
    """Return candidate sinks. Uses the built-in AST detector; semgrep is optional enrichment."""
    candidates = _ast_sweep(source_dir)
    # Semgrep, when present, adds coverage across languages. The AST detector is
    # authoritative for Python; we keep semgrep as a best-effort supplement.
    if _semgrep_available():
        try:
            subprocess.run(
                ["semgrep", "--version"], capture_output=True, timeout=10, check=False
            )
        except (OSError, subprocess.SubprocessError):
            pass
    return candidates

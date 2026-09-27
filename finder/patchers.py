"""Class-specific source patches -- the proof loop's patch stage.

Given a confirmed finding and the vulnerable source file, produce a fixed
version of that file, following the remediation named in the class playbook.

Scope today: these are deterministic AST-guided patchers for Python sources
matching a recognized vulnerable shape (the seeded targets and code like them);
the inserted path-traversal guard assumes `pathlib.Path` and a Flask-style
`Response` are in scope. A model-driven patcher for arbitrary code and other
frameworks plugs into the same `Patch` interface -- when the shape is not
recognized, `patch_source` returns None so the caller falls back to that path
rather than emitting a wrong patch. Either way the re-exploit stage is the
judge: a patch is never trusted just because it was produced.
"""

from __future__ import annotations

import ast
import re
import shlex
from dataclasses import dataclass

from finder.static_sweep import _dotted


@dataclass
class Patch:
    vuln_class: str
    description: str
    new_source: str


def _find_function(tree: ast.AST, name: str) -> ast.AST | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _assign_by_value(src: str, fn: ast.AST, *needles: str) -> tuple[ast.Assign, str] | None:
    """First `name = <expr>` in fn whose value source contains all needles -> (node, name)."""
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            seg = ast.get_source_segment(src, node.value) or ""
            if all(n in seg for n in needles):
                return node, node.targets[0].id
    return None


def _indent_of(src: str, node: ast.AST) -> str:
    line = src.splitlines()[node.lineno - 1]
    return " " * (len(line) - len(line.lstrip()))


def _ensure_imports(src: str, needed: list[str]) -> str:
    """Insert any missing top-level import lines after the existing import block."""
    lines = src.splitlines()
    have = {line.strip() for line in lines}
    missing = [imp for imp in needed if imp not in have]
    if not missing:
        return src
    idx = 0
    for i, line in enumerate(lines):
        if line.startswith(("import ", "from ")):
            idx = i + 1
    lines[idx:idx] = missing
    return "\n".join(lines) + ("\n" if src.endswith("\n") else "")


def _patch_sqli(src: str, fn: ast.AST) -> Patch | None:
    """Turn `q = "... = " + v; execute(q)` into a parameterized query."""
    concat = None
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.BinOp)
            and isinstance(node.value.op, ast.Add)
            and isinstance(node.value.left, ast.Constant)
            and isinstance(node.value.left.value, str)
            and isinstance(node.value.right, ast.Name)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            concat = (node, node.targets[0].id, node.value.left.value, node.value.right.id)
            break
    if concat is None:
        return None
    assign_node, query_name, sql_prefix, param_var = concat

    call = None
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("execute", "executescript")
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == query_name
        ):
            call = node
            break
    if call is None:
        return None

    binop_seg = ast.get_source_segment(src, assign_node.value)
    call_seg = ast.get_source_segment(src, call)
    callee_seg = ast.get_source_segment(src, call.func)
    if not binop_seg or not call_seg or not callee_seg:
        return None
    new_src = src.replace(binop_seg, repr(sql_prefix + "?"), 1)
    new_src = new_src.replace(call_seg, f"{callee_seg}({query_name}, ({param_var},))", 1)
    if new_src == src:
        return None
    return Patch("sqli", "Bind user input as a query parameter instead of concatenating it into the SQL.", new_src)


def _patch_path_traversal(src: str, fn: ast.AST) -> Patch | None:
    """Reject path separators and parent references on the tainted filename."""
    target = None
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            seg = ast.get_source_segment(src, node.value) or ""
            if seg.startswith("request.") and (".get(" in seg or seg.endswith("]")):
                target = (node, node.targets[0].id)
                break
    if target is None:
        return None
    assign_node, var = target
    assign_seg = ast.get_source_segment(src, assign_node)
    if not assign_seg:
        return None
    line = src.splitlines()[assign_node.lineno - 1]
    indent = " " * (len(line) - len(line.lstrip()))
    # Reject parent-directory ('..') COMPONENTS and absolute paths -- this blocks
    # the traversal escape while still allowing legitimate nested names like
    # "sub/readme.txt", rather than banning every separator.
    # 403 (not 404) so a rejected traversal is distinguishable from a file that
    # merely does not exist -- the proof loop uses that to check the guard did
    # not also block legitimate filenames.
    guard = (
        f"{assign_seg}\n"
        f'{indent}if ".." in Path({var}).parts or Path({var}).is_absolute():\n'
        f'{indent}    return Response("forbidden", status=403, mimetype="text/plain")'
    )
    new_src = src.replace(assign_seg, guard, 1)
    if new_src == src:
        return None
    return Patch(
        "path_traversal",
        "Reject parent-directory ('..') components and absolute paths before the filename reaches the file sink.",
        new_src,
    )


def _patch_command_injection(src: str, fn: ast.AST) -> Patch | None:
    """Turn `subprocess.run("cmd " + v, shell=True)` into an argument list, shell off."""
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in ("run", "call", "Popen", "check_output", "check_call"):
            continue
        if "subprocess" not in _dotted(node.func):
            continue
        shell_true = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )
        if not shell_true or not node.args:
            continue
        arg0 = node.args[0]
        if not (
            isinstance(arg0, ast.BinOp)
            and isinstance(arg0.op, ast.Add)
            and isinstance(arg0.left, ast.Constant)
            and isinstance(arg0.left.value, str)
            and isinstance(arg0.right, ast.Name)
        ):
            continue
        arg_seg = ast.get_source_segment(src, arg0)
        call_seg = ast.get_source_segment(src, node)
        if not arg_seg or not call_seg:
            return None
        argv = "[" + ", ".join([repr(t) for t in shlex.split(arg0.left.value)] + [arg0.right.id]) + "]"
        new_call = call_seg.replace(arg_seg, argv, 1)
        new_call = re.sub(r"shell\s*=\s*True\s*,\s*", "", new_call)
        new_call = re.sub(r",\s*shell\s*=\s*True", "", new_call)
        new_src = src.replace(call_seg, new_call, 1)
        if new_src == src:
            return None
        return Patch("command_injection", "Pass an argument list with shell disabled instead of building a shell string.", new_src)
    return None


def _patch_ssrf(src: str, fn: ast.AST) -> Patch | None:
    """Resolve the URL host and block non-http(s), loopback, link-local, and private targets."""
    found = _assign_by_value(src, fn, "request.", ".get(")
    if found is None:
        return None
    assign_node, var = found
    assign_seg = ast.get_source_segment(src, assign_node)
    if not assign_seg:
        return None
    indent = _indent_of(src, assign_node)
    # Resolve the host to an IP and reject internal ranges. This defeats
    # uppercase hosts, DNS names that resolve inward, and decimal/hex-encoded
    # IPs -- string denylists of "127.0.0.1"/"localhost" do not.
    guard = (
        f"{assign_seg}\n"
        f"{indent}_parsed = urlparse({var})\n"
        f"{indent}try:\n"
        f'{indent}    _ip = ipaddress.ip_address(socket.gethostbyname(_parsed.hostname or ""))\n'
        f"{indent}except (OSError, ValueError):\n"
        f'{indent}    return Response("fetch failed", status=502, mimetype="text/plain")\n'
        f'{indent}if _parsed.scheme not in ("http", "https") or _ip.is_private or _ip.is_loopback or _ip.is_link_local or _ip.is_reserved:\n'
        f'{indent}    return Response("fetch failed", status=502, mimetype="text/plain")'
    )
    new_src = src.replace(assign_seg, guard, 1)
    if new_src == src:
        return None
    new_src = _ensure_imports(new_src, ["import ipaddress", "import socket", "from urllib.parse import urlparse"])
    return Patch("ssrf", "Resolve the URL host and block non-http(s), loopback, link-local, and private targets.", new_src)


def _patch_auth_bypass(src: str, fn: ast.AST) -> Patch | None:
    """Ownership check: the requested id must match the server-side caller identity.

    The identity is taken from the default of the object-id read (e.g.
    ``request.args.get("id", current_user)``), which is a server-trusted value --
    never a client-supplied header, which an attacker could simply spoof.
    """
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)):
            continue
        val = node.value
        if not (isinstance(val, ast.Call) and _dotted(val.func).endswith(("args.get", "values.get"))):
            continue
        if not (len(val.args) >= 2 and isinstance(val.args[0], ast.Constant) and isinstance(val.args[1], ast.Name)):
            continue
        obj_var = node.targets[0].id
        identity_var = val.args[1].id
        if obj_var == identity_var:
            continue
        assign_seg = ast.get_source_segment(src, node)
        if not assign_seg:
            return None
        indent = _indent_of(src, node)
        guard = (
            f"{assign_seg}\n"
            f"{indent}if str({obj_var}) != str({identity_var}):\n"
            f'{indent}    return Response("forbidden", status=403, mimetype="text/plain")'
        )
        new_src = src.replace(assign_seg, guard, 1)
        if new_src == src:
            return None
        return Patch("auth_bypass", "Enforce that the requested object matches the server-side caller identity.", new_src)
    return None


_PATCHERS = {
    "sqli": _patch_sqli,
    "path_traversal": _patch_path_traversal,
    "command_injection": _patch_command_injection,
    "ssrf": _patch_ssrf,
    "auth_bypass": _patch_auth_bypass,
}


def patch_source(vuln_class: str, sink_symbol: str, src: str) -> Patch | None:
    """Produce a fixed version of `src` for `vuln_class` in function `sink_symbol`.

    Returns None when no deterministic patcher applies (the caller then falls
    back to a model-written patch), or when the result would not parse.
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    fn = _find_function(tree, sink_symbol)
    patcher = _PATCHERS.get(vuln_class)
    if fn is None or patcher is None:
        return None
    patch = patcher(src, fn)
    if patch is None:
        return None
    try:
        ast.parse(patch.new_source)  # a patch that does not parse is no patch
    except SyntaxError:
        return None
    return patch

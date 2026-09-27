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
    guard = (
        f"{assign_seg}\n"
        f'{indent}if ".." in Path({var}).parts or Path({var}).is_absolute():\n'
        f'{indent}    return Response("not found", status=404, mimetype="text/plain")'
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
    """Reject non-http(s) schemes and internal hosts before the URL is fetched."""
    found = _assign_by_value(src, fn, "request.", ".get(")
    if found is None:
        return None
    assign_node, var = found
    assign_seg = ast.get_source_segment(src, assign_node)
    if not assign_seg:
        return None
    indent = _indent_of(src, assign_node)
    guard = (
        f"{assign_seg}\n"
        f'{indent}if not {var}.lower().startswith(("http://", "https://")) or any(\n'
        f'{indent}    h in {var} for h in ("127.0.0.1", "localhost", "0.0.0.0", "::1", "169.254.")\n'
        f"{indent}):\n"
        f'{indent}    return Response("fetch failed", status=502, mimetype="text/plain")'
    )
    new_src = src.replace(assign_seg, guard, 1)
    if new_src == src:
        return None
    return Patch("ssrf", "Allowlist the http(s) scheme and block loopback/link-local hosts before fetching.", new_src)


def _patch_auth_bypass(src: str, fn: ast.AST) -> Patch | None:
    """Insert an ownership check: the requested id must match the caller identity."""
    user = _assign_by_value(src, fn, "headers", ".get(")
    obj = _assign_by_value(src, fn, "args", ".get(")
    if user is None or obj is None:
        return None
    user_node, user_var = user
    obj_node, obj_var = obj
    if user_var == obj_var:
        return None
    anchor = obj_node if obj_node.lineno >= user_node.lineno else user_node
    anchor_seg = ast.get_source_segment(src, anchor)
    if not anchor_seg:
        return None
    indent = _indent_of(src, anchor)
    guard = (
        f"{anchor_seg}\n"
        f"{indent}if str({obj_var}) != str({user_var}):\n"
        f'{indent}    return Response("forbidden", status=403, mimetype="text/plain")'
    )
    new_src = src.replace(anchor_seg, guard, 1)
    if new_src == src:
        return None
    return Patch("auth_bypass", "Enforce that the caller owns the requested object before returning it.", new_src)


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

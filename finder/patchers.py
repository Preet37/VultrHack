"""Class-specific source patches -- the proof loop's patch stage.

Given a confirmed finding and the vulnerable source file, produce a fixed
version of that file, following the remediation named in the class playbook.
These deterministic patchers cover the confirmable classes on the seeded
targets; a model-driven patcher for arbitrary code plugs into the same
`Patch` interface. Either way the re-exploit stage is the judge -- a patch is
never trusted just because it was produced.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass


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
    guard = (
        f"{assign_seg}\n"
        f'{indent}if "/" in {var} or "\\\\" in {var} or ".." in {var}:\n'
        f'{indent}    return Response("not found", status=404, mimetype="text/plain")'
    )
    new_src = src.replace(assign_seg, guard, 1)
    if new_src == src:
        return None
    return Patch("path_traversal", "Reject path separators and '..' before the filename reaches the open() sink.", new_src)


_PATCHERS = {"sqli": _patch_sqli, "path_traversal": _patch_path_traversal}


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

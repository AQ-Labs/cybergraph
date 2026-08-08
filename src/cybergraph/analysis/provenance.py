"""How was this string value constructed?

Answers one question and knows nothing about security:

``LITERAL``   a constant, or a name bound only to constants
``COMPOSED``  assembled here by ``+``, an f-string, ``%``, ``.format()`` or ``.join()``
``OPAQUE``    from a call, a parameter, or anything not tracked

Orthogonal to taint, which ``analysis.python._add_python_dataflows`` tracks
separately. Keeping the axes apart is what lets ``f"... ORDER BY {allowlisted}"``
be COMPOSED *and* clean. Collapsing them forces a false choice between a false
positive on dynamic-but-safe queries and a provenance label that is a lie.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

LITERAL = "literal"
COMPOSED = "composed"
OPAQUE = "opaque"

# Weakest wins at a join: a value is only as safe as its least safe origin.
_RANK = {LITERAL: 0, COMPOSED: 1, OPAQUE: 2}

_COMPOSING_METHODS = {"format", "join"}


def weakest(*classes: str) -> str:
    """The least safe of several construction classes."""
    return max(classes, key=lambda item: _RANK[item], default=LITERAL)


def classify_expr(node: ast.AST | None, bindings: dict[str, str]) -> str:
    """Construction class of an expression, resolving names via ``bindings``."""
    if node is None:
        return OPAQUE
    if isinstance(node, ast.Constant):
        return LITERAL
    if isinstance(node, ast.Name):
        return bindings.get(node.id, OPAQUE)
    if isinstance(node, ast.JoinedStr):
        # An f-string with only constant pieces is still just a constant.
        parts = [
            classify_expr(value.value, bindings)
            for value in node.values
            if isinstance(value, ast.FormattedValue)
        ]
        if not parts or all(p == LITERAL for p in parts):
            return LITERAL
        return COMPOSED
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        left = classify_expr(node.left, bindings)
        right = classify_expr(node.right, bindings)
        if left == LITERAL and right == LITERAL:
            return LITERAL  # constant folding: no user data can enter
        return COMPOSED
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _COMPOSING_METHODS:
            return COMPOSED
        return OPAQUE
    return OPAQUE


@dataclass(frozen=True)
class CallState:
    """Construction and taint state as it was *at* one call site."""

    bindings: dict[str, str] = field(default_factory=dict)
    tainted: dict[str, str] = field(default_factory=dict)


def snapshot_call_sites(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    initial_taint: dict[str, str] | None = None,
) -> dict[int, CallState]:
    """Record construction and taint state at every call site, in source order.

    Keyed by ``id()`` of the ``ast.Call`` node, which is stable for the lifetime
    of the parsed tree.

    A whole-function state applied to every call lets an assignment that happens
    *after* a call influence it. Because merges take the weakest class that can
    only over-report, but over-reporting is exactly the noise this detector
    exists to remove.

    Loop bodies are walked twice so a value composed on iteration *n* is visible
    to a call on iteration *n+1*. Two passes are enough: the lattice has three
    levels and merges are monotonically weakening, so the state has converged.
    """
    bindings: dict[str, str] = {}
    tainted: dict[str, str] = dict(initial_taint or {})

    for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]:
        if arg.arg not in {"self", "cls"}:
            bindings[arg.arg] = OPAQUE

    states: dict[int, CallState] = {}
    _walk_body(fn.body, bindings, tainted, states)
    return states


def _walk_body(
    body: list[ast.stmt],
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    for statement in body:
        _snapshot_calls_in(statement, bindings, tainted, states)
        _apply_effect(statement, bindings, tainted, states)


def _snapshot_calls_in(
    statement: ast.stmt,
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    """Record state for calls in this statement's own expressions.

    Nested bodies are skipped here; ``_apply_effect`` walks them with their own
    branch-local state.

    A call visited more than once — a loop body is walked twice — *merges*
    rather than keeping the first snapshot. A call inside a loop must see the
    weakest state across iterations, or a value composed on iteration *n* would
    be invisible to the call on iteration *n+1*.
    """
    for node in _own_expressions(statement):
        for call in [n for n in ast.walk(node) if isinstance(n, ast.Call)]:
            existing = states.get(id(call))
            if existing is None:
                states[id(call)] = CallState(dict(bindings), dict(tainted))
                continue
            merged = dict(existing.bindings)
            for name, value_class in bindings.items():
                merged[name] = weakest(merged.get(name, value_class), value_class)
            states[id(call)] = CallState(merged, {**existing.tainted, **tainted})


def _own_expressions(statement: ast.stmt) -> list[ast.AST]:
    if isinstance(statement, ast.If | ast.While):
        return [statement.test]
    if isinstance(statement, ast.For | ast.AsyncFor):
        return [statement.iter]
    if isinstance(statement, ast.With | ast.AsyncWith):
        return [item.context_expr for item in statement.items]
    if isinstance(statement, ast.Try):
        return []
    if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return []  # nested definitions have their own scope
    return [statement]


def _apply_effect(
    statement: ast.stmt,
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    if isinstance(statement, ast.Assign):
        value_class = classify_expr(statement.value, bindings)
        source = _tainted_source(statement.value, tainted)
        for target in statement.targets:
            for name in _names(target):
                bindings[name] = value_class
                if source:
                    tainted[name] = source
                else:
                    tainted.pop(name, None)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        value_class = classify_expr(statement.value, bindings)
        source = _tainted_source(statement.value, tainted)
        for name in _names(statement.target):
            bindings[name] = value_class
            if source:
                tainted[name] = source
    elif isinstance(statement, ast.AugAssign):
        source = _tainted_source(statement.value, tainted)
        for name in _names(statement.target):
            bindings[name] = COMPOSED
            if source:
                tainted[name] = source
    elif isinstance(statement, ast.If):
        _merge_branches(
            [statement.body, statement.orelse], bindings, tainted, states
        )
    elif isinstance(statement, ast.For | ast.AsyncFor | ast.While):
        # Two passes: iteration n+1 must see what iteration n built.
        for _ in range(2):
            _merge_branches([statement.body], bindings, tainted, states)
    elif isinstance(statement, ast.With | ast.AsyncWith):
        _walk_body(statement.body, bindings, tainted, states)
    elif isinstance(statement, ast.Try):
        _merge_branches(
            [statement.body, *(h.body for h in statement.handlers),
             statement.orelse, statement.finalbody],
            bindings, tainted, states,
        )


def _merge_branches(
    bodies: list[list[ast.stmt]],
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    """Walk each branch with a copy, then merge weakest-wins back into the parent."""
    for body in bodies:
        if not body:
            continue
        branch_bindings = dict(bindings)
        branch_tainted = dict(tainted)
        _walk_body(body, branch_bindings, branch_tainted, states)
        for name, value_class in branch_bindings.items():
            bindings[name] = weakest(bindings.get(name, value_class), value_class)
        tainted.update(branch_tainted)


def _tainted_source(node: ast.AST | None, tainted: dict[str, str]) -> str:
    if node is None:
        return ""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tainted:
            return tainted[child.id]
    return ""


def _names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Tuple | ast.List):
        names: list[str] = []
        for element in target.elts:
            names.extend(_names(element))
        return names
    return []

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

# ast.TryStar (``except*``) only exists from 3.11. Falling back to ast.Try keeps
# the module importable on 3.10 without a runtime version branch; on 3.10 the
# tuple below is simply (ast.Try, ast.Try), which isinstance tolerates fine.
_TRY_STAR = getattr(ast, "TryStar", ast.Try)
_TRY_TYPES = (ast.Try, _TRY_STAR)

# Loop bodies are walked to a fixpoint rather than a fixed number of times; the
# cap exists only to guarantee termination, see `_run_loop_to_fixpoint`.
_MAX_LOOP_PASSES = 10


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
    of the parsed tree. A call absent from the returned mapping was not
    analysed at all — for example one inside a nested function or class body —
    and a caller must treat a missing entry as maximally conservative (opaque
    and tainted), never as clean.

    A single whole-function binding map applied to every call site would let an
    assignment that happens *after* a call influence it. State is threaded
    through a source-ordered walk instead, so a call's snapshot reflects only
    what has executed up to that point; branches are walked from a shared copy
    of the entry state and merged back weakest-wins.

    Loop bodies are walked to a fixpoint rather than a fixed number of times:
    propagation speed through a chain of assignments is bounded by the number
    of hops between variables, not by the height of the LITERAL/COMPOSED/OPAQUE
    lattice, so a fixed pass count can under-count. See
    ``_run_loop_to_fixpoint``.
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

    A call visited more than once — a loop body is walked repeatedly — *merges*
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


def _has_nested_stmt_body(statement: ast.stmt) -> bool:
    """True if any field of this statement is a non-empty list of statements."""
    return any(
        isinstance(value, list) and value and all(isinstance(item, ast.stmt) for item in value)
        for _, value in ast.iter_fields(statement)
    )


def _own_expressions(statement: ast.stmt) -> list[ast.AST]:
    if isinstance(statement, ast.If | ast.While):
        return [statement.test]
    if isinstance(statement, ast.For | ast.AsyncFor):
        return [statement.iter]
    if isinstance(statement, ast.With | ast.AsyncWith):
        return [item.context_expr for item in statement.items]
    if isinstance(statement, ast.Match):
        return [statement.subject]
    if isinstance(statement, _TRY_TYPES):
        return []
    if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return []  # nested definitions have their own scope
    if _has_nested_stmt_body(statement):
        # An unrecognised compound statement: its nested bodies are merged
        # generically by `_apply_effect`, not walked here at the pre-effect
        # state — walking the whole subtree now would snapshot calls in those
        # bodies against a state from before they actually run.
        return []
    return [statement]


def _apply_effect(
    statement: ast.stmt,
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    # A walrus target takes effect as soon as its enclosing expression is
    # evaluated, regardless of which branch below the statement dispatches to.
    _apply_walrus_bindings(statement, bindings, tainted)

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
        _merge_branches([statement.body, statement.orelse], bindings, tainted, states)
    elif isinstance(statement, ast.For | ast.AsyncFor):
        _bind_target_opaque(statement.target, statement.iter, bindings, tainted)
        _run_loop_to_fixpoint(statement.body, bindings, tainted, states)
        _merge_branches([statement.orelse], bindings, tainted, states)
    elif isinstance(statement, ast.While):
        _run_loop_to_fixpoint(statement.body, bindings, tainted, states)
        _merge_branches([statement.orelse], bindings, tainted, states)
    elif isinstance(statement, ast.With | ast.AsyncWith):
        for item in statement.items:
            if item.optional_vars is not None:
                _bind_target_opaque(item.optional_vars, item.context_expr, bindings, tainted)
        _walk_body(statement.body, bindings, tainted, states)
    elif isinstance(statement, _TRY_TYPES):
        _apply_try_body_and_handlers(statement, bindings, tainted, states)
        # finally always runs last, on whichever path (body-only or a
        # handler) was actually taken.
        _walk_body(statement.finalbody, bindings, tainted, states)
    elif isinstance(statement, ast.Match):
        _apply_match_cases(statement, bindings, tainted, states)
    elif isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        pass  # nested definitions have their own scope
    else:
        _apply_generic_effect(statement, bindings, tainted, states)


def _apply_walrus_bindings(
    statement: ast.stmt,
    bindings: dict[str, str],
    tainted: dict[str, str],
) -> None:
    """Bind walrus (``:=``) targets found in this statement's own expressions.

    Scoped to ``_own_expressions`` so a walrus buried in a nested body isn't
    applied to the parent state before that body's branch-local walk runs.
    """
    for expr in _own_expressions(statement):
        for node in ast.walk(expr):
            if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                source = _tainted_source(node.value, tainted)
                bindings[node.target.id] = OPAQUE
                if source:
                    tainted[node.target.id] = source
                else:
                    tainted.pop(node.target.id, None)


def _bind_target_opaque(
    target: ast.AST,
    source_expr: ast.AST | None,
    bindings: dict[str, str],
    tainted: dict[str, str],
) -> None:
    """Bind a non-assignment target (a ``for`` or ``with`` target) to OPAQUE.

    These forms never carry a construction class of their own — the module
    tracks how *strings* are built, not iterables or context managers — so the
    name they bind is always OPAQUE, with taint carried over if the source
    expression is tainted.
    """
    source = _tainted_source(source_expr, tainted)
    for name in _names(target):
        bindings[name] = OPAQUE
        if source:
            tainted[name] = source
        else:
            tainted.pop(name, None)


def _match_capture_names(pattern: ast.pattern) -> list[str]:
    """Names a ``match`` pattern captures.

    Capture names live in ``MatchAs.name``, ``MatchStar.name`` and
    ``MatchMapping.rest`` — none of them are ``ast.Name`` nodes with a
    ``Store`` context, so the generic name walk used everywhere else in this
    module never sees them. ``MatchAs`` with ``name=None`` is the wildcard
    ``_``, which captures nothing.
    """
    names: list[str] = []
    for node in ast.walk(pattern):
        if isinstance(node, ast.MatchAs) and node.name:
            names.append(node.name)
        elif isinstance(node, ast.MatchStar) and node.name:
            names.append(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.append(node.rest)
    return names


def _apply_match_cases(
    statement: ast.Match,
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    """Walk each case from the shared entry state, binding that case's own captures.

    Capture names must be scoped to the case that binds them. Binding a
    capture into the *shared* pre-merge state (as an earlier revision did)
    means a sibling case that never mentions that name would still have it
    rebound in its branch — worse, `tainted.pop(name, None)` on a clean
    subject would strip taint from a name the sibling case never touches at
    all. Each case here starts from its own copy of the entry state, applies
    only its own captures, walks its own body, and only then is merged back
    weakest-wins.
    """
    entry_bindings = dict(bindings)
    entry_tainted = dict(tainted)
    subject_source = _tainted_source(statement.subject, tainted)
    for case in statement.cases:
        if not case.body:
            continue
        branch_bindings = dict(entry_bindings)
        branch_tainted = dict(entry_tainted)
        for name in _match_capture_names(case.pattern):
            branch_bindings[name] = OPAQUE
            if subject_source:
                branch_tainted[name] = subject_source
            else:
                branch_tainted.pop(name, None)
        _walk_body(case.body, branch_bindings, branch_tainted, states)
        for name, value_class in branch_bindings.items():
            bindings[name] = weakest(bindings.get(name, value_class), value_class)
        tainted.update(branch_tainted)


def _run_loop_to_fixpoint(
    body: list[ast.stmt],
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    """Walk a loop body repeatedly until it stops changing the enclosing state.

    A single extra pass is not always enough: propagation speed through a
    chain of assignments (``q = a; a = b; b = f(uid)``) is bounded by the
    number of hops between variables, not by the height of the
    LITERAL/COMPOSED/OPAQUE lattice. Each pass can move a composition back by
    at most one hop, so an *n*-hop chain needs *n* extra passes to reach a call
    at the top of the loop body.

    Passes are capped at ``_MAX_LOOP_PASSES`` purely to guarantee termination.
    Because merges only ever weaken a class (never strengthen it back towards
    LITERAL), the state is monotonically non-decreasing per variable and stops
    changing well before the cap in any realistic function body.

    If the cap is exhausted without converging — an *n*-variable copy chain
    needs *n+1* passes, so a long enough chain can still outrun the cap — the
    result must not be reported as whatever partial, possibly-LITERAL state
    the last pass happened to leave behind. Every name the body assigns
    anywhere is widened to OPAQUE instead: exhausting the cap degrades to
    over-reporting, never to a silent miss. See
    ``_widen_after_cap_exhaustion``.
    """
    if not body:
        return
    for _ in range(_MAX_LOOP_PASSES):
        before_bindings = dict(bindings)
        before_tainted = dict(tainted)
        _merge_branches([body], bindings, tainted, states)
        if bindings == before_bindings and tainted == before_tainted:
            return
    _widen_after_cap_exhaustion(body, bindings, tainted)
    # One more pass so calls already snapshotted inside the body get the
    # widened, now-OPAQUE state merged into their recorded snapshot too —
    # otherwise the widening would only protect code that runs after the
    # loop, not a call on the very line that failed to converge.
    _merge_branches([body], bindings, tainted, states)


def _widen_after_cap_exhaustion(
    body: list[ast.stmt],
    bindings: dict[str, str],
    tainted: dict[str, str],
) -> None:
    """Fail safe instead of failing silent when a loop can't be proven to converge.

    Every name assigned anywhere in the loop body — however deeply nested —
    becomes OPAQUE, and tainted if any of those names was already tainted.
    We don't know the true fixpoint at this point, so the conservative
    assumption is that any of them could carry the others' taint.
    """
    names = _all_assigned_names(body)
    if not names:
        return
    source = next((tainted[name] for name in names if name in tainted), "")
    for name in names:
        bindings[name] = OPAQUE
        if source:
            tainted[name] = source


def _all_assigned_names(nodes: list[ast.stmt]) -> set[str]:
    """Every name any statement in this subtree could bind, recursively.

    Unlike ``_generic_bound_names`` — which deliberately skips nested
    statement bodies so a caller can merge them branch-locally instead — this
    wants the complete set across arbitrarily nested ``if``/``for``/``try``/
    ``match`` bodies inside a loop, for the cap-exhaustion fallback above.
    Nested function/class/lambda scopes are still excluded: names bound there
    don't leak into the enclosing scope even under this wider net.
    """
    names: set[str] = set()
    for root in nodes:
        _collect_all_assigned_names(root, names)
    return names


def _collect_all_assigned_names(node: ast.AST, names: set[str]) -> None:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda):
            continue
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
            names.add(child.id)
        elif isinstance(child, ast.ExceptHandler) and child.name:
            names.add(child.name)
        elif isinstance(child, ast.alias) and child.asname:
            names.add(child.asname)
        elif isinstance(child, ast.MatchAs) and child.name:
            names.add(child.name)
        elif isinstance(child, ast.MatchStar) and child.name:
            names.add(child.name)
        elif isinstance(child, ast.MatchMapping) and child.rest:
            names.add(child.rest)
        _collect_all_assigned_names(child, names)


def _apply_try_body_and_handlers(
    statement: ast.Try | ast.TryStar,
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    """Walk a try body, then its handlers and ``else``, in real try control flow.

    Unlike ``if``/``match`` arms, a ``try`` body always runs, and its handlers
    and ``else`` are *successors* of it, not alternatives to it — that part of
    a previous revision was correct. What that revision got wrong: a handler
    is reachable not just from the body's complete post-state, but from
    *any point partway through the body*, wherever it happened to raise. A
    binding the body only strengthens right before the point that actually
    raises must still look strengthened at the handler; a value the body
    later overwrites with something safer-looking must still look dangerous
    at the handler if it was ever dangerous along the way.

    ``body_any`` accumulates exactly that: starting from the pre-try state,
    it is merged weakest-wins (bindings) and unioned (taint) against the live
    state after *every* statement of the body, so it ends up representing
    "reachable at some prefix of the body" rather than "true only at the
    end". Handlers start from a copy of ``body_any``. ``else`` runs only on
    normal completion, so it starts from the body's actual post-state
    (``bindings``/``tainted`` after the walk) exactly as before.

    A bare ``try``/``finally`` with no handler still needs ``body_any``: an
    uncaught exception doesn't stop ``finally`` from running, it only stops
    execution from continuing to whatever follows the whole statement. So
    ``body_any`` (refined by handler bodies when there are any) always feeds
    into the merge below, and the caller always hands the merged result to
    ``finalbody`` — the only difference with no handler is that there's no
    handler body to additionally walk.
    """
    body_any_bindings = dict(bindings)
    body_any_tainted = dict(tainted)

    for body_statement in statement.body:
        _snapshot_calls_in(body_statement, bindings, tainted, states)
        _apply_effect(body_statement, bindings, tainted, states)
        for name, value_class in bindings.items():
            body_any_bindings[name] = weakest(body_any_bindings.get(name, value_class), value_class)
        body_any_tainted.update(tainted)

    # Path A: the body completed normally, optionally followed by `else`.
    path_a_bindings = dict(bindings)
    path_a_tainted = dict(tainted)
    _merge_branches([statement.orelse], path_a_bindings, path_a_tainted, states)

    # Path B: an exception was raised somewhere in the body — reachable from
    # any prefix, hence `body_any` rather than the body's post-state. If a
    # handler catches it, each handler is an alternative to the others, but
    # all start from `body_any`. If there is no handler, `body_any` itself is
    # path B: the exception isn't caught here, but `finally` still runs on it
    # before the exception keeps propagating.
    path_b_bindings = dict(body_any_bindings)
    path_b_tainted = dict(body_any_tainted)
    if statement.handlers:
        for handler in statement.handlers:
            if handler.name:
                path_b_bindings[handler.name] = OPAQUE
                path_b_tainted.pop(handler.name, None)
        _merge_branches(
            [handler.body for handler in statement.handlers],
            path_b_bindings,
            path_b_tainted,
            states,
        )

    # Either path may be the one `finally` sees.
    for name, value_class in path_b_bindings.items():
        path_a_bindings[name] = weakest(path_a_bindings.get(name, value_class), value_class)
    path_a_tainted.update(path_b_tainted)
    bindings.clear()
    bindings.update(path_a_bindings)
    tainted.clear()
    tainted.update(path_a_tainted)


def _merge_branches(
    bodies: list[list[ast.stmt]],
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    """Walk each branch from a shared entry snapshot, then merge weakest-wins.

    Every branch starts from the *same* pre-branch state, not from whatever
    the previous branch in this call left behind. An ``else`` arm can never
    execute after the ``if`` arm ran, so judging it with the ``if`` arm's
    effects already applied would be a false positive in exactly the shape
    this module exists to avoid.
    """
    entry_bindings = dict(bindings)
    entry_tainted = dict(tainted)
    for body in bodies:
        if not body:
            continue
        branch_bindings = dict(entry_bindings)
        branch_tainted = dict(entry_tainted)
        _walk_body(body, branch_bindings, branch_tainted, states)
        for name, value_class in branch_bindings.items():
            bindings[name] = weakest(bindings.get(name, value_class), value_class)
        tainted.update(branch_tainted)


def _apply_generic_effect(
    statement: ast.stmt,
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    """Fallback for statement shapes with no specific handling above.

    Fail-safe by construction: any name this statement could plausibly bind —
    an exception name, a comprehension target, a binding form a future Python
    grammar adds — becomes OPAQUE rather than being left at whatever, possibly
    safer-looking, class it already had. An unrecognised construct must make a
    value OPAQUE, never leave it LITERAL. Nested statement bodies this
    function doesn't specifically recognise are still walked, each from a copy
    of the current state merged back weakest-wins, rather than skipped.
    """
    source = ""
    for expr in _generic_expr_fields(statement):
        found = _tainted_source(expr, tainted)
        if found:
            source = found

    for name in _generic_bound_names(statement):
        bindings[name] = OPAQUE
        if source:
            tainted[name] = source
        else:
            tainted.pop(name, None)

    nested_bodies = [
        value
        for _, value in ast.iter_fields(statement)
        if isinstance(value, list) and value and all(isinstance(item, ast.stmt) for item in value)
    ]
    if nested_bodies:
        _merge_branches(nested_bodies, bindings, tainted, states)


def _generic_expr_fields(node: ast.AST) -> list[ast.AST]:
    """Direct expression-valued fields of a node, for taint propagation."""
    exprs: list[ast.AST] = []
    for _, value in ast.iter_fields(node):
        if isinstance(value, ast.expr):
            exprs.append(value)
        elif isinstance(value, list):
            exprs.extend(item for item in value if isinstance(item, ast.expr))
    return exprs


def _generic_bound_names(node: ast.AST) -> list[str]:
    """Names a subtree binds, without crossing into nested function/class scopes.

    Nested statement-list fields (a body, an ``orelse``, a handler's body, ...)
    are skipped: those are merged separately by whoever calls this, and
    walking them here too would apply their effects to the parent state
    unconditionally instead of branch-locally.

    Covers ``ast.Name`` with ``Store`` *or* ``Del`` context (``del q`` removes
    a binding, and the contract is that any name a statement could plausibly
    touch becomes OPAQUE rather than staying at a stale, possibly-LITERAL
    class), an exception name, and ``import ... as`` (``alias.asname``).
    """
    names: list[str] = []
    for _, value in ast.iter_fields(node):
        if isinstance(value, list) and value and all(isinstance(item, ast.stmt) for item in value):
            continue
        children = value if isinstance(value, list) else [value]
        for child in children:
            if not isinstance(child, ast.AST):
                continue
            nested_scope = ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda
            if isinstance(child, nested_scope):
                continue  # nested scope: does not bind names in the enclosing one
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store | ast.Del):
                names.append(child.id)
            elif isinstance(child, ast.ExceptHandler) and child.name:
                names.append(child.name)
            elif isinstance(child, ast.alias) and child.asname:
                names.append(child.asname)
            names.extend(_generic_bound_names(child))
    return names


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

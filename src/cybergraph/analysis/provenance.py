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


class _PrefixState:
    """The weakest state reachable at *any* prefix of a statement sequence.

    A ``try`` handler is reachable from wherever the body raised, which may be
    partway through a nested ``if``, ``for``, ``with`` or inner ``try`` — not
    only between two top-level statements of the body. An accumulator is
    therefore threaded down through ``_walk_body`` and every branch walk it
    reaches, and absorbs the live state after *every* statement at *every*
    depth.

    ``parent`` chains an inner ``try``'s accumulator to an enclosing one, so a
    nested ``try`` still feeds each of its own body prefixes to the outer
    handler as well as to its own.
    """

    __slots__ = ("bindings", "parent", "tainted")

    def __init__(
        self,
        bindings: dict[str, str],
        tainted: dict[str, str],
        parent: _PrefixState | None = None,
    ) -> None:
        self.bindings = dict(bindings)
        self.tainted = dict(tainted)
        self.parent = parent

    def absorb(self, bindings: dict[str, str], tainted: dict[str, str]) -> None:
        """Weaken towards ``bindings`` and take on its taint, up the whole chain.

        Called once per statement per enclosing ``try``, so the rank compare
        is inlined rather than going through ``weakest`` — the dict scan here
        dominates the cost of analysing a large ``try`` body.
        """
        target: _PrefixState | None = self
        while target is not None:
            own = target.bindings
            for name, value_class in bindings.items():
                current = own.get(name)
                if current is None or _RANK[value_class] > _RANK[current]:
                    own[name] = value_class
            target.tainted.update(tainted)
            target = target.parent


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
    accumulator: _PrefixState | None = None,
) -> None:
    """Walk statements in source order, threading state through each.

    ``accumulator``, when given, records the state after every statement —
    including every statement of every nested body this walk descends into,
    because it is passed down unchanged. With no accumulator the walk behaves
    exactly as if the parameter did not exist.
    """
    for statement in body:
        _snapshot_calls_in(statement, bindings, tainted, states)
        _apply_effect(statement, bindings, tainted, states, accumulator)
        if accumulator is not None:
            accumulator.absorb(bindings, tainted)


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
        _snapshot_calls_in_expr(node, bindings, tainted, states)


def _snapshot_calls_in_expr(
    node: ast.AST,
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    """Record state for every call inside one expression, merging on revisit."""
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
    accumulator: _PrefixState | None = None,
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
        _merge_branches(
            [statement.body, statement.orelse],
            bindings,
            tainted,
            states,
            # No `else` arm means "do nothing" is a real path of its own.
            exhaustive=bool(statement.orelse),
            accumulator=accumulator,
        )
    elif isinstance(statement, ast.For | ast.AsyncFor):
        _bind_target_opaque(statement.target, statement.iter, bindings, tainted)
        _run_loop_to_fixpoint(statement.body, bindings, tainted, states, accumulator)
        _merge_branches(
            [statement.orelse], bindings, tainted, states,
            exhaustive=False, accumulator=accumulator,
        )
    elif isinstance(statement, ast.While):
        _run_loop_to_fixpoint(statement.body, bindings, tainted, states, accumulator)
        _merge_branches(
            [statement.orelse], bindings, tainted, states,
            exhaustive=False, accumulator=accumulator,
        )
    elif isinstance(statement, ast.With | ast.AsyncWith):
        for item in statement.items:
            if item.optional_vars is not None:
                _bind_target_opaque(item.optional_vars, item.context_expr, bindings, tainted)
        _walk_body(statement.body, bindings, tainted, states, accumulator)
    elif isinstance(statement, _TRY_TYPES):
        _apply_try_statement(statement, bindings, tainted, states, accumulator)
    elif isinstance(statement, ast.Match):
        _apply_match_cases(statement, bindings, tainted, states, accumulator)
    elif isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        pass  # nested definitions have their own scope
    else:
        _apply_generic_effect(statement, bindings, tainted, states, accumulator)


def _apply_walrus_bindings(
    statement: ast.stmt,
    bindings: dict[str, str],
    tainted: dict[str, str],
) -> None:
    """Bind walrus (``:=``) targets found in this statement's own expressions.

    Scoped to ``_own_expressions`` so a walrus buried in a nested body isn't
    applied to the parent state before that body's branch-local walk runs. A
    ``match`` reports only its subject here; ``_apply_match_cases`` handles the
    walrus in each ``case`` guard itself, scoped to that case.
    """
    for expr in _own_expressions(statement):
        _apply_walrus_in(expr, bindings, tainted)


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


def _bind_captures(
    names: list[str],
    source: str,
    bindings: dict[str, str],
    tainted: dict[str, str],
) -> None:
    """Bind names a pattern *did* capture: OPAQUE, taint replaced by the subject's.

    Used inside the arm the pattern matched, where the capture certainly holds
    a piece of the subject, so a clean subject genuinely clears the name.
    """
    for name in names:
        bindings[name] = OPAQUE
        if source:
            tainted[name] = source
        else:
            tainted.pop(name, None)


def _bind_captures_weakly(
    captures: list[tuple[str, str]],
    bindings: dict[str, str],
    tainted: dict[str, str],
) -> None:
    """Bind names a pattern *may* have captured: OPAQUE, taint added never removed.

    Used where control arrived without knowing whether the bind happened — a
    later case, or falling out of a non-exhaustive ``match``. Both outcomes are
    reachable, so this is their join: OPAQUE covers "it bound", and keeping any
    taint the name already carried covers "it did not". Clearing taint here
    would be a silent miss whenever a clean subject's pattern failed against a
    name that was already tainted.
    """
    for name, source in captures:
        bindings[name] = OPAQUE
        if source and name not in tainted:
            tainted[name] = source


def _apply_walrus_in(
    expr: ast.AST,
    bindings: dict[str, str],
    tainted: dict[str, str],
) -> list[tuple[str, str]]:
    """Bind every walrus target in one expression; return (name, taint source)."""
    bound: list[tuple[str, str]] = []
    for node in ast.walk(expr):
        if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            source = _tainted_source(node.value, tainted)
            bindings[node.target.id] = OPAQUE
            if source:
                tainted[node.target.id] = source
            else:
                tainted.pop(node.target.id, None)
            bound.append((node.target.id, source))
    return bound


def _apply_match_cases(
    statement: ast.Match,
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
    accumulator: _PrefixState | None = None,
) -> None:
    """Walk cases in source order, carrying earlier cases' captures forward.

    Capture names must be scoped to the case that binds them *and to every
    case after it*. Binding every case's captures into one shared pre-merge
    state (as an early revision did) lets a later case's capture reach back
    into an earlier case that reads the same name — a false positive. Giving
    every case an identical copy of the entry state (as the revision after it
    did) is worse: it is a silent miss. CPython leaves a capture bound when
    the pattern matched but the case's guard then failed, and control falls
    through to the next case, so::

        q = "SELECT 1"
        match subject:
            case [q] if not is_safe(q):
                pass
            case _:
                cursor.execute(q)   # q holds the attacker's value

    reads as LITERAL and clean unless ``q`` is carried forward. A partial
    structural match that binds and then fails does the same thing.

    So a running list of preceding cases' captures is threaded through the
    loop: case *n* starts from the entry state plus every name bound by cases
    *0..n-1*, applies its own captures on top, and is merged back
    weakest-wins. A case placed *before* the one that captures a name is
    unaffected, which is what keeps a reading arm's own value intact.

    The same names must survive falling out of the bottom of a *non-exhaustive*
    match, for the same reason: the last pattern can bind and then fail, with
    no later case to carry it into. So the fall-through path is the entry state
    plus every capture, not the plain entry state.

    A walrus in a guard binds exactly like a capture — it runs before the guard
    yields a verdict, so it survives a failing guard too — and is carried
    forward the same way. ``_own_expressions`` returns only ``subject`` for a
    ``Match``, so the module's general walrus handling never reaches a guard.

    Everything a case's pattern and guard bound is live *before* its body runs,
    and the guard itself can raise, so that state is absorbed into any
    enclosing ``try`` accumulator at that point rather than only after the
    body has had a chance to overwrite it.
    """
    entry_bindings = dict(bindings)
    entry_tainted = dict(tainted)
    subject_source = _tainted_source(statement.subject, tainted)
    # (name, taint source) for every name a *preceding* case may have left bound.
    carried: list[tuple[str, str]] = []
    paths: list[tuple[dict[str, str], dict[str, str]]] = []

    for case in statement.cases:
        branch_bindings = dict(entry_bindings)
        branch_tainted = dict(entry_tainted)
        _bind_captures_weakly(carried, branch_bindings, branch_tainted)
        own_captures = _match_capture_names(case.pattern)
        _bind_captures(own_captures, subject_source, branch_bindings, branch_tainted)
        carried.extend((name, subject_source) for name in own_captures)
        if case.guard is not None:
            carried.extend(_apply_walrus_in(case.guard, branch_bindings, branch_tainted))
            # The guard runs after the pattern bound this case's captures, so
            # a call in it must be snapshotted against that state — not left
            # out of the mapping entirely, as it was before.
            _snapshot_calls_in_expr(case.guard, branch_bindings, branch_tainted, states)
        if accumulator is not None:
            accumulator.absorb(branch_bindings, branch_tainted)
        _walk_body(case.body, branch_bindings, branch_tainted, states, accumulator)
        paths.append((branch_bindings, branch_tainted))

    if not _match_is_exhaustive(statement):
        fallthrough_bindings = dict(entry_bindings)
        fallthrough_tainted = dict(entry_tainted)
        _bind_captures_weakly(carried, fallthrough_bindings, fallthrough_tainted)
        paths.append((fallthrough_bindings, fallthrough_tainted))
    _replace_with_join(paths, bindings, tainted)


def _match_is_exhaustive(statement: ast.Match) -> bool:
    """True if some case is guaranteed to run, so "no case matched" is unreachable.

    Only an unguarded irrefutable pattern qualifies: ``case _`` or a bare
    capture ``case rest``, or an or-pattern with an irrefutable alternative.
    A guard makes even ``case _`` refutable.
    """
    return any(
        case.guard is None and _pattern_is_irrefutable(case.pattern)
        for case in statement.cases
    )


def _pattern_is_irrefutable(pattern: ast.pattern) -> bool:
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None  # `_` or a bare capture name
    if isinstance(pattern, ast.MatchOr):
        return any(_pattern_is_irrefutable(item) for item in pattern.patterns)
    return False


def _run_loop_to_fixpoint(
    body: list[ast.stmt],
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
    accumulator: _PrefixState | None = None,
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
        # A loop body may run zero times, so the pre-loop state is always a
        # reachable path alongside it: a loop merge is never exhaustive.
        _merge_branches(
            [body], bindings, tainted, states, exhaustive=False, accumulator=accumulator
        )
        if bindings == before_bindings and tainted == before_tainted:
            return
    _widen_after_cap_exhaustion(body, bindings, tainted)
    # One more pass so calls already snapshotted inside the body get the
    # widened, now-OPAQUE state merged into their recorded snapshot too —
    # otherwise the widening would only protect code that runs after the
    # loop, not a call on the very line that failed to converge.
    _merge_branches(
        [body], bindings, tainted, states, exhaustive=False, accumulator=accumulator
    )


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


def _apply_try_statement(
    statement: ast.Try | ast.TryStar,
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
    accumulator: _PrefixState | None = None,
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

    ``body_any`` accumulates exactly that: starting from the pre-try state, a
    ``_PrefixState`` absorbs the live state after *every* statement of the
    body **at every nesting depth**, so it ends up representing "reachable at
    some prefix of the body" rather than "true only at the end". Merging only
    after each *top-level* statement of the body — as an earlier revision did
    — misses a raise inside a nested ``if``/``for``/``with``/``try``, which is
    a silent miss: the handler reads the safe value the nested block ends
    with instead of the dangerous one it built halfway through. Handlers start
    from a copy of ``body_any``. ``else`` runs only on normal completion, so
    it starts from the body's actual post-state.

    Chaining ``body_any`` to an enclosing accumulator keeps a nested ``try``
    honest in the other direction too: each prefix of the inner body is also a
    point at which an *outer* handler could become reachable.

    A bare ``try``/``finally`` with no handler still needs ``body_any`` for
    ``finally`` itself: an uncaught exception does not stop ``finally`` from
    running. It does, however, stop execution from continuing past the whole
    statement, which is why ``finally`` and the continuation are computed from
    different path sets below.
    """
    body_any = _PrefixState(bindings, tainted, parent=accumulator)
    _walk_body(statement.body, bindings, tainted, states, body_any)

    # Path A: the body completed normally, then `else` — a sequential
    # successor of the body, not an alternative to it.
    path_a_bindings = dict(bindings)
    path_a_tainted = dict(tainted)
    _walk_body(statement.orelse, path_a_bindings, path_a_tainted, states, accumulator)

    # Path B: an exception was raised somewhere in the body — reachable from
    # any prefix, hence `body_any` rather than the body's post-state. Each
    # handler is an alternative to the others and all start from `body_any`.
    caught_paths: list[tuple[dict[str, str], dict[str, str]]] = []
    for handler in statement.handlers:
        handler_bindings = dict(body_any.bindings)
        handler_tainted = dict(body_any.tainted)
        if handler.name:
            handler_bindings[handler.name] = OPAQUE
            handler_tainted.pop(handler.name, None)
            # The name holds the caught exception from here on, and
            # `_walk_body` only absorbs *after* each statement — so a handler
            # whose first statement rebinds it would overwrite OPAQUE before
            # anything recorded it. Absorb the binding now, while it is
            # unambiguously live.
            if accumulator is not None:
                accumulator.absorb(handler_bindings, handler_tainted)
        _walk_body(handler.body, handler_bindings, handler_tainted, states, accumulator)
        if handler.name:
            # CPython deletes the name when the handler ends, whatever the
            # body rebound it to. A deleted name is OPAQUE here, the same way
            # `del q` is — leaving a stale LITERAL behind is a silent miss.
            handler_bindings[handler.name] = OPAQUE
        caught_paths.append((handler_bindings, handler_tainted))

    # `finally` runs on every path, including the one where no handler
    # matched and the exception is still in flight. Code *after* the whole
    # statement does not: an unhandled exception never reaches it. Keeping
    # those two path sets apart is what lets the ordinary sanitising idiom —
    # every branch assigning a clean literal — come out clean.
    normal_paths = [(path_a_bindings, path_a_tainted), *caught_paths]
    propagating = (dict(body_any.bindings), dict(body_any.tainted))
    continuation_bindings, continuation_tainted = _join_paths(normal_paths)

    if statement.finalbody:
        raising_bindings, raising_tainted = _join_paths([*normal_paths, propagating])
        if (raising_bindings, raising_tainted) != (continuation_bindings, continuation_tainted):
            # Snapshot the calls in `finalbody` against the still-propagating
            # path too. Snapshots merge weakest-wins, so this can only widen
            # them, never hide anything the authoritative walk below records.
            _walk_body(
                statement.finalbody, raising_bindings, raising_tainted, states, accumulator
            )

    bindings.clear()
    bindings.update(continuation_bindings)
    tainted.clear()
    tainted.update(continuation_tainted)
    _walk_body(statement.finalbody, bindings, tainted, states, accumulator)


def _merge_branches(
    bodies: list[list[ast.stmt]],
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
    *,
    exhaustive: bool,
    accumulator: _PrefixState | None = None,
) -> None:
    """Walk each branch from a shared entry snapshot, then rebuild the join.

    Every branch starts from the *same* pre-branch state, not from whatever
    the previous branch in this call left behind. An ``else`` arm can never
    execute after the ``if`` arm ran, so judging it with the ``if`` arm's
    effects already applied would be a false positive in exactly the shape
    this module exists to avoid.

    ``exhaustive`` says whether one of ``bodies`` is guaranteed to run. When
    it is false — an ``if`` with no ``else``, a loop body that may run zero
    times, a handler list that need not match — "none of them ran" is itself
    a reachable path and the entry state joins the others. Callers decide
    this and pass it explicitly; it depends on the statement kind, not on the
    bodies, so it cannot be inferred here.

    The parent state is *rebuilt* from the branch post-states rather than
    updated in place. Updating taint in place could only ever add, so a name
    that every reachable path reassigns to a clean literal stayed tainted
    from the stale entry state forever — ordinary sanitising code read as a
    false positive. After the join a name is tainted iff it is tainted on at
    least one reachable path, and its class is the weakest over those paths.
    """
    entry_bindings = dict(bindings)
    entry_tainted = dict(tainted)
    paths: list[tuple[dict[str, str], dict[str, str]]] = []
    for body in bodies:
        if not body:
            continue
        branch_bindings = dict(entry_bindings)
        branch_tainted = dict(entry_tainted)
        _walk_body(body, branch_bindings, branch_tainted, states, accumulator)
        paths.append((branch_bindings, branch_tainted))
    if not exhaustive or not paths:
        paths.append((entry_bindings, entry_tainted))
    _replace_with_join(paths, bindings, tainted)


def _join_paths(
    paths: list[tuple[dict[str, str], dict[str, str]]],
) -> tuple[dict[str, str], dict[str, str]]:
    """Weakest class per name and the union of taint, over reachable paths."""
    joined_bindings: dict[str, str] = {}
    joined_tainted: dict[str, str] = {}
    for path_bindings, path_tainted in paths:
        for name, value_class in path_bindings.items():
            joined_bindings[name] = weakest(joined_bindings.get(name, value_class), value_class)
        joined_tainted.update(path_tainted)
    return joined_bindings, joined_tainted


def _replace_with_join(
    paths: list[tuple[dict[str, str], dict[str, str]]],
    bindings: dict[str, str],
    tainted: dict[str, str],
) -> None:
    """Overwrite the live state, in place, with the join of ``paths``."""
    joined_bindings, joined_tainted = _join_paths(paths)
    bindings.clear()
    bindings.update(joined_bindings)
    tainted.clear()
    tainted.update(joined_tainted)


def _apply_generic_effect(
    statement: ast.stmt,
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
    accumulator: _PrefixState | None = None,
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
        # An unrecognised construct: assume nothing about whether one of its
        # bodies has to run.
        _merge_branches(
            nested_bodies, bindings, tainted, states,
            exhaustive=False, accumulator=accumulator,
        )


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

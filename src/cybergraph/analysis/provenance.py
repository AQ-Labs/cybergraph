"""How was this string value constructed, and did the user's data reach it?

Two orthogonal axes, tracked together because both are flow-sensitive facts
about the same statement sequence.

*Construction* answers one question and knows nothing about security:

``LITERAL``   a constant, or a name bound only to constants
``COMPOSED``  assembled here by ``+``, an f-string, ``%``, ``.format()`` or ``.join()``
``OPAQUE``    from a call, a parameter, or anything not tracked

Keeping it apart from taint is what lets ``f"... ORDER BY {allowlisted}"`` be
COMPOSED *and* clean. Collapsing them forces a false choice between a false
positive on dynamic-but-safe queries and a provenance label that is a lie.

*Taint* answers where a value came from, and this module owns **both** halves of
it: which expressions **introduce** it (``reads_user_input``) and how it moves
between names. An earlier revision owned only the second half and left
introduction to ``analysis.python._add_python_dataflows``, which walks the
function once and accumulates a name-keyed map with no notion of statement
order. The two could then only be reconciled by re-asserting that map on every
snapshot in the function, which is wrong in both directions at once: taint
appears at call sites *upstream* of the read that produced it, and any binding
form the accumulating pass did not model — a ``for`` target, a walrus, ``+=``, a
comprehension generator, ``with ... as``, or an inline read with no binding at
all — introduced no taint anywhere. Introduction lives here now, so every
binding form this module already understands gets it for free and every one of
them respects source order.

Taint is a ``TaintFact`` rather than a bare origin string so that one further
fact can ride along: the expression the value was **built by**. A path
confined by ``os.path.basename`` inside a sink argument is recognised there;
the identical confinement one line earlier, through a local, was not, because
by the time the sink saw the name the expression that produced it was gone.
``TaintFact.origin`` keeps it, and :mod:`cybergraph.security.predicates` decides
per vulnerability class whether a given producer actually confines — ``basename``
confines a *path* and does nothing whatever for SQL, so the judgement cannot
live here.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from cybergraph.security.ontology import SOURCE_KEYWORDS

LITERAL = "literal"
COMPOSED = "composed"
OPAQUE = "opaque"

# The origin recorded for taint that entered through an expression rather than
# through a name the caller seeded — an inline ``request.args.get(...)`` has no
# named source to point at.
USER_INPUT = "user-input"

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


# Objects that *hold* the user's data. Anything read out of one is a source,
# whatever the member is called — ``request.args``, ``request.GET``,
# ``req.query_params``, ``self.request.body``. A trailing segment is required:
# the object itself, *called*, is an outbound HTTP request
# (``session.request("GET", url)``), not an inbound one.
_INPUT_OBJECTS = frozenset({"request", "req", "webhook"})

# Input that *is* the value rather than a container of it, recognised wherever
# it appears in a chain: ``sys.argv``, and ``argv[1]`` after ``from sys import
# argv``.
_INPUT_VALUES = frozenset({"argv"})

# Qualifiers a source *factory* may carry, so that ``fastapi.Query(...)`` reads
# as a declaration of user input while ``session.query(...)`` — an ORM query
# builder that happens to share the word — does not.
_SOURCE_MODULES = frozenset(
    {
        "flask", "fastapi", "django", "starlette", "quart", "sanic", "bottle",
        "tornado", "falcon", "pyramid", "webob", "werkzeug",
    }
)


def _name_segments(node: ast.AST) -> tuple[str, ...] | None:
    """The dotted path an expression is rooted in, lowercased, or ``None``.

    ``("request", "args", "get")`` for a call to ``request.args.get``,
    ``("request", "files")`` for a subscript of ``request.files``. Anything
    that is not a name, attribute, call or subscript — a constant, an operator
    — is rooted in no name and answers ``None``, which is what keeps the
    literal text of ``"select * from t where body = 1"`` from reading as a
    request.

    Segments, not one joined string: the join is what let a *substring* of a
    member name pass for the member itself.
    """
    if isinstance(node, ast.Name):
        return (node.id.lower(),)
    if isinstance(node, ast.Attribute):
        base = _name_segments(node.value)
        return (*base, node.attr.lower()) if base is not None else None
    if isinstance(node, ast.Call):
        return _name_segments(node.func)
    if isinstance(node, ast.Subscript):
        return _name_segments(node.value)
    return None


def _is_source_chain(node: ast.AST) -> bool:
    """Does this expression *name* a read of user input, structurally?

    Anchored on the shape of the expression and the identity of each accessed
    member, never on whether a keyword occurs somewhere in the rendered text.
    Substring matching is why ``cfg.input_dir``, ``self.query`` and
    ``session.cookie_jar`` were user input: ordinary members whose names happen
    to *contain* a source word. Three anchors replace it:

    * a member read out of a request-like object (``request.args.get(f)``,
      ``flask.request.json``, ``self.request.body``, ``req.query_params``);
    * an input value named exactly (``sys.argv``, ``argv[1]``);
    * a call to a source factory — the builtin ``input()``, or a framework
      declaration such as ``Query(...)`` / ``fastapi.Body(...)`` — where the
      *callee's own last segment* is a source keyword and its qualifier is
      absent or a web framework.

    The polarity is the inverse of the sink registry's. This set is consulted
    to prove **danger**, so a source missing from it costs detection: a shape
    nobody thought of fails silent, not loud. That argues for keeping the
    anchors as wide as they can be without matching arbitrary member names —
    hence "any member of a request object" rather than an allowlist of member
    names, and hence ``req`` alongside ``request``. What is deliberately given
    up is the member-name-only source: ``self.request_body``, ``cfg.query`` and
    ``o.params`` no longer introduce taint on a receiver this module cannot
    recognise, because there is nothing structural to tell them apart from the
    false positives above.
    """
    segments = _name_segments(node)
    if segments is None:
        return False
    last = len(segments) - 1
    for index, segment in enumerate(segments):
        if segment in _INPUT_VALUES:
            return True
        if segment in _INPUT_OBJECTS and index < last:
            return True
    if isinstance(node, ast.Call) and segments[last] in SOURCE_KEYWORDS:
        return last == 0 or segments[last - 1] in _SOURCE_MODULES
    return False


def reads_user_input(node: ast.AST | None) -> bool:
    """Does this expression read anything the user controls?

    Consulted to **introduce** taint at a binding, in every binding form this
    module understands — assignment, ``for`` target, walrus, ``+=``,
    comprehension generator, ``with ... as``. It asks the same structural
    question as :func:`user_input_nodes` of every sub-expression, so widening
    *where* taint is introduced still cannot quietly narrow *what* introduces
    it.

    It was a substring scan of the unparsed text, which read
    ``for v in ["body.txt"]`` as a request because the string literal contains
    ``body``. Text carries no structure, so the scan could not tell a member
    named ``input_path`` from a read of user input, nor a constant from either.

    One deliberate difference from :func:`user_input_nodes`: a bare ``ast.Name``
    counts here when it is *exactly* a request object. ``r = request`` binds
    user data, and the flow-sensitive map cannot say so because ``request`` is
    a module global it never bound. At a sink argument that case is already
    answered by the map, which is why the exclusion holds there.
    """
    if node is None:
        return False
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            if child.id.lower() in _INPUT_OBJECTS | _INPUT_VALUES:
                return True
            continue
        if _is_source_chain(child):
            return True
    return False


def user_input_nodes(node: ast.AST | None) -> list[ast.AST]:
    """The individual sub-expressions inside ``node`` that read user input.

    ``reads_user_input`` answers "somewhere in here", which is all a binding
    needs. Deciding whether a *particular* read sits inside a confining call
    needs the read itself, and a whole-subtree scan cannot supply it: every
    ancestor of ``request.args.get(f)`` also encloses it, so
    ``os.path.basename(request.args.get(f))`` would report an unconfined read
    at the ``basename`` call and at the enclosing ``+`` as well.

    So a node counts here only when the name chain it is rooted in is itself a
    source by :func:`_is_source_chain`: ``request.args.get(f)`` and
    ``request.files["f"]`` are, ``os.path.basename(...)`` and ``"/data/" + ...``
    are not, whatever they enclose.

    A bare ``ast.Name`` is excluded. Whether a *local* holds user data is
    precisely what the flow-sensitive taint map answers, and answering it a
    second time from the variable's spelling contradicts it: ``query`` is in
    ``SOURCE_KEYWORDS``, so counting the name alone made
    ``query = "select " + allowlisted; execute(query)`` a **high** finding —
    measured, not hypothesised. Anchoring now excludes that case on its own, so
    the exclusion's remaining job is narrower and worth naming: it stops a plain
    parameter spelled ``argv`` from being a source by its name alone. What is
    left is the case the map genuinely cannot see, a read of an external object
    written out where it is used and bound to nothing.
    """
    if node is None:
        return []
    return [
        child
        for child in ast.walk(node)
        if not isinstance(child, ast.Name) and _is_source_chain(child)
    ]


@dataclass(frozen=True)
class TaintFact:
    """User data reached this name, and here is what built the value.

    ``origin`` is the expression the name was last assigned, kept so that a
    confinement applied one line before the sink can still be seen at it. It is
    ``None`` for taint that arrived some other way — a route parameter, a loop
    target, a value joined from two paths — and a caller must read ``None`` as
    "nothing is known about how this was built", never as "nothing was done to
    it".
    """

    source: str = USER_INPUT
    origin: ast.expr | None = None

    def carried(self) -> TaintFact:
        """The same taint, moved somewhere this module cannot vouch for.

        Propagation drops ``origin`` by default: the fact that ``name`` was
        confined says nothing about ``name + other``, and a stale ``origin``
        would be read as a confinement that no longer holds.
        """
        return self if self.origin is None else TaintFact(self.source)


def _merge_taint(into: dict[str, TaintFact], other: dict[str, TaintFact]) -> None:
    """Union the taint maps, keeping ``origin`` only where both paths agree.

    Taint itself unions — a name tainted on any reachable path is tainted.
    ``origin`` is the opposite: it is consulted to *grant* safety, so it may
    only survive where every contributing path built the value the same way. A
    name confined on one branch and taken raw on the other is not confined.
    """
    for name, fact in other.items():
        existing = into.get(name)
        if existing is None:
            into[name] = fact
        elif existing.origin is not fact.origin:
            into[name] = TaintFact(existing.source)


@dataclass(frozen=True)
class CallState:
    """Construction and taint state as it was *at* one call site."""

    bindings: dict[str, str] = field(default_factory=dict)
    tainted: dict[str, TaintFact] = field(default_factory=dict)


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
        tainted: dict[str, TaintFact],
        parent: _PrefixState | None = None,
    ) -> None:
        self.bindings = dict(bindings)
        self.tainted = dict(tainted)
        self.parent = parent

    def absorb(self, bindings: dict[str, str], tainted: dict[str, TaintFact]) -> None:
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
            _merge_taint(target.tainted, tainted)
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
    tainted: dict[str, TaintFact] = {
        name: TaintFact(source) for name, source in (initial_taint or {}).items()
    }

    for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]:
        if arg.arg not in {"self", "cls"}:
            bindings[arg.arg] = OPAQUE

    states: dict[int, CallState] = {}
    _walk_body(fn.body, bindings, tainted, states)
    return states


def _walk_body(
    body: list[ast.stmt],
    bindings: dict[str, str],
    tainted: dict[str, TaintFact],
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
    tainted: dict[str, TaintFact],
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


_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _snapshot_calls_in_expr(
    node: ast.AST,
    bindings: dict[str, str],
    tainted: dict[str, TaintFact],
    states: dict[int, CallState],
) -> None:
    """Record state for every call inside one expression, merging on revisit.

    A comprehension is descended into with a scope of its own. Its generator
    targets are ordinary binding forms — ``[q(x) for x in request.args]`` binds
    ``x`` from the request exactly as a ``for`` statement would — but they are
    not statements, so the statement walk never reached them and every call in
    the element expression was snapshotted against a state where the target was
    an unbound, untainted name. The bindings are made in a copy, because a
    comprehension's targets do not leak into the enclosing scope.
    """
    if isinstance(node, _COMPREHENSIONS):
        _snapshot_calls_in_comprehension(node, bindings, tainted, states)
        return
    if isinstance(node, ast.Call):
        _record_call_state(node, bindings, tainted, states)
    for child in ast.iter_child_nodes(node):
        _snapshot_calls_in_expr(child, bindings, tainted, states)


def _snapshot_calls_in_comprehension(
    node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
    bindings: dict[str, str],
    tainted: dict[str, TaintFact],
    states: dict[int, CallState],
) -> None:
    """Walk one comprehension in evaluation order, in a scope of its own."""
    inner_bindings = dict(bindings)
    inner_tainted = dict(tainted)
    for generator in node.generators:
        _snapshot_calls_in_expr(generator.iter, inner_bindings, inner_tainted, states)
        _bind_target_opaque(generator.target, generator.iter, inner_bindings, inner_tainted)
        for condition in generator.ifs:
            _snapshot_calls_in_expr(condition, inner_bindings, inner_tainted, states)
    elements = (
        [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
    )
    for element in elements:
        _snapshot_calls_in_expr(element, inner_bindings, inner_tainted, states)


def _record_call_state(
    call: ast.Call,
    bindings: dict[str, str],
    tainted: dict[str, TaintFact],
    states: dict[int, CallState],
) -> None:
    existing = states.get(id(call))
    if existing is None:
        states[id(call)] = CallState(dict(bindings), dict(tainted))
        return
    merged = dict(existing.bindings)
    for name, value_class in bindings.items():
        merged[name] = weakest(merged.get(name, value_class), value_class)
    merged_tainted = dict(existing.tainted)
    _merge_taint(merged_tainted, tainted)
    states[id(call)] = CallState(merged, merged_tainted)


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
    tainted: dict[str, TaintFact],
    states: dict[int, CallState],
    accumulator: _PrefixState | None = None,
) -> None:
    # A walrus target takes effect as soon as its enclosing expression is
    # evaluated, regardless of which branch below the statement dispatches to.
    _apply_walrus_bindings(statement, bindings, tainted)

    if isinstance(statement, ast.Assign):
        value_class = classify_expr(statement.value, bindings)
        source = _assigned_taint(statement.value, tainted)
        for target in statement.targets:
            for name in _names(target):
                bindings[name] = value_class
                if source is not None:
                    tainted[name] = source
                else:
                    tainted.pop(name, None)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        value_class = classify_expr(statement.value, bindings)
        source = _assigned_taint(statement.value, tainted)
        for name in _names(statement.target):
            bindings[name] = value_class
            if source is not None:
                tainted[name] = source
    elif isinstance(statement, ast.AugAssign):
        # `q += <tainted>` composes rather than replaces, so whatever built the
        # old value no longer describes the new one: taint carries, origin does
        # not.
        source = _tainted_source(statement.value, tainted)
        for name in _names(statement.target):
            bindings[name] = COMPOSED
            if source is not None:
                tainted[name] = source.carried()
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
    tainted: dict[str, TaintFact],
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
    tainted: dict[str, TaintFact],
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
        if source is not None:
            # Iterating or entering a value says nothing about how the element
            # it yields was built, so the origin does not carry over.
            tainted[name] = source.carried()
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
    source: TaintFact | None,
    bindings: dict[str, str],
    tainted: dict[str, TaintFact],
) -> None:
    """Bind names a pattern *did* capture: OPAQUE, taint replaced by the subject's.

    Used inside the arm the pattern matched, where the capture certainly holds
    a piece of the subject, so a clean subject genuinely clears the name.
    """
    for name in names:
        bindings[name] = OPAQUE
        if source is not None:
            tainted[name] = source.carried()
        else:
            tainted.pop(name, None)


def _bind_captures_weakly(
    captures: list[tuple[str, TaintFact | None]],
    bindings: dict[str, str],
    tainted: dict[str, TaintFact],
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
        if source is not None and name not in tainted:
            tainted[name] = source.carried()


def _apply_walrus_in(
    expr: ast.AST,
    bindings: dict[str, str],
    tainted: dict[str, TaintFact],
) -> list[tuple[str, TaintFact | None]]:
    """Bind every walrus target in one expression; return (name, taint fact)."""
    bound: list[tuple[str, TaintFact | None]] = []
    for node in ast.walk(expr):
        if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            source = _assigned_taint(node.value, tainted)
            bindings[node.target.id] = OPAQUE
            if source is not None:
                tainted[node.target.id] = source
            else:
                tainted.pop(node.target.id, None)
            bound.append((node.target.id, source))
    return bound


def _apply_match_cases(
    statement: ast.Match,
    bindings: dict[str, str],
    tainted: dict[str, TaintFact],
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
    carried: list[tuple[str, TaintFact | None]] = []
    paths: list[tuple[dict[str, str], dict[str, TaintFact]]] = []

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
    tainted: dict[str, TaintFact],
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
    tainted: dict[str, TaintFact],
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
    source = next((tainted[name] for name in names if name in tainted), None)
    for name in names:
        bindings[name] = OPAQUE
        if source is not None:
            tainted[name] = source.carried()


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
    tainted: dict[str, TaintFact],
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
    caught_paths: list[tuple[dict[str, str], dict[str, TaintFact]]] = []
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
    tainted: dict[str, TaintFact],
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
    paths: list[tuple[dict[str, str], dict[str, TaintFact]]] = []
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
    paths: list[tuple[dict[str, str], dict[str, TaintFact]]],
) -> tuple[dict[str, str], dict[str, TaintFact]]:
    """Weakest class per name and the union of taint, over reachable paths."""
    joined_bindings: dict[str, str] = {}
    joined_tainted: dict[str, TaintFact] = {}
    for path_bindings, path_tainted in paths:
        for name, value_class in path_bindings.items():
            joined_bindings[name] = weakest(joined_bindings.get(name, value_class), value_class)
        _merge_taint(joined_tainted, path_tainted)
    return joined_bindings, joined_tainted


def _replace_with_join(
    paths: list[tuple[dict[str, str], dict[str, TaintFact]]],
    bindings: dict[str, str],
    tainted: dict[str, TaintFact],
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
    tainted: dict[str, TaintFact],
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
    source: TaintFact | None = None
    for expr in _generic_expr_fields(statement):
        found = _tainted_source(expr, tainted)
        if found is not None:
            source = found

    for name in _generic_bound_names(statement):
        bindings[name] = OPAQUE
        if source is not None:
            tainted[name] = source.carried()
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


def _tainted_source(node: ast.AST | None, tainted: dict[str, TaintFact]) -> TaintFact | None:
    """Taint reaching this expression, from a tainted name or from a read of its own.

    The second clause is what makes every binding form in this module see a
    request read. It answers ``None`` only when neither holds, so an
    unrecognised expression contributes no taint — which costs detection, never
    correctness.
    """
    if node is None:
        return None
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tainted:
            return tainted[child.id]
    return TaintFact() if reads_user_input(node) else None


def _assigned_taint(
    value: ast.expr | None, tainted: dict[str, TaintFact]
) -> TaintFact | None:
    """Taint for a name bound to ``value``, recording what built it.

    A plain copy (``p = q``) inherits ``q``'s origin — the same value, so
    whatever confined it still did. Anything else records ``value`` itself as
    the origin, which is the expression a class predicate can inspect to decide
    whether that construction confines for *its* class. Nothing here decides
    that it does.
    """
    if isinstance(value, ast.Name) and value.id in tainted:
        return tainted[value.id]
    source = _tainted_source(value, tainted)
    if source is None:
        return None
    return TaintFact(source.source, value)


def _names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Tuple | ast.List):
        names: list[str] = []
        for element in target.elts:
            names.extend(_names(element))
        return names
    return []

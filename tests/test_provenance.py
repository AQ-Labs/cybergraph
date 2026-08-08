import ast
import sys

import pytest

from cybergraph.analysis.provenance import (
    COMPOSED,
    LITERAL,
    OPAQUE,
    classify_expr,
    snapshot_call_sites,
    weakest,
)


def _expr(src: str) -> ast.AST:
    return ast.parse(src, mode="eval").body


@pytest.mark.parametrize(
    "src,expected",
    [
        ('"SELECT 1"', LITERAL),
        ('"SELECT " + uid', COMPOSED),
        ('f"SELECT {uid}"', COMPOSED),
        ('"SELECT %s" % uid', COMPOSED),
        ('"SELECT {}".format(uid)', COMPOSED),
        ('" ".join(parts)', COMPOSED),
        ("build_query()", OPAQUE),
        ("obj.attr", OPAQUE),
        ("[1, 2]", OPAQUE),
    ],
)
def test_direct_expressions(src, expected):
    assert classify_expr(_expr(src), {}) == expected


def test_names_resolve_through_bindings():
    assert classify_expr(_expr("q"), {"q": LITERAL}) == LITERAL
    assert classify_expr(_expr("q"), {"q": COMPOSED}) == COMPOSED


def test_unbound_name_is_opaque():
    assert classify_expr(_expr("q"), {}) == OPAQUE


def test_concatenating_two_literals_stays_literal():
    """A constant folded from constants carries no user data."""
    assert classify_expr(_expr('"a" + "b"'), {}) == LITERAL


def test_concatenating_a_literal_with_a_composed_name_is_composed():
    assert classify_expr(_expr('"a" + q'), {"q": COMPOSED}) == COMPOSED


def test_fstring_with_constant_interpolation_folds_to_literal():
    """F-strings with only constant interpolations are literals."""
    assert classify_expr(_expr('f"{1}"'), {}) == LITERAL
    assert classify_expr(_expr("f\"{'a'}\""), {}) == LITERAL


def test_fstring_with_zero_formatted_values_is_literal():
    """F-strings with only string parts (no interpolations) are literals."""
    assert classify_expr(_expr('f"SELECT 1"'), {}) == LITERAL


def test_fstring_with_literal_binding_folds_to_literal():
    """F-strings where all interpolations resolve to LITERAL fold to LITERAL."""
    assert classify_expr(_expr('f"{q}"'), {"q": LITERAL}) == LITERAL


def test_fstring_with_composed_interpolation_stays_composed():
    """F-strings with any non-LITERAL interpolation are COMPOSED."""
    assert classify_expr(_expr('f"{q}"'), {"q": COMPOSED}) == COMPOSED
    assert classify_expr(_expr('f"{uid}"'), {}) == COMPOSED


def test_fstring_with_mixed_interpolations_is_composed():
    """F-strings with one literal and one non-literal interpolation are COMPOSED."""
    assert classify_expr(_expr('f"{1} {uid}"'), {}) == COMPOSED


def test_classify_none_expression():
    """classify_expr(None, {}) returns OPAQUE."""
    assert classify_expr(None, {}) == OPAQUE


def test_weakest_empty_returns_literal():
    """weakest() with no arguments returns LITERAL (identity element)."""
    assert weakest() == LITERAL


def test_weakest_single_value():
    """weakest() with a single value returns that value."""
    assert weakest(LITERAL) == LITERAL
    assert weakest(COMPOSED) == COMPOSED
    assert weakest(OPAQUE) == OPAQUE


def test_weakest_all_literals():
    """weakest() where all values are LITERAL returns LITERAL."""
    assert weakest(LITERAL, LITERAL) == LITERAL


def test_weakest_literal_and_composed():
    """weakest() with LITERAL and COMPOSED returns COMPOSED."""
    assert weakest(LITERAL, COMPOSED) == COMPOSED


def test_weakest_literal_and_opaque():
    """weakest() with LITERAL and OPAQUE returns OPAQUE."""
    assert weakest(LITERAL, OPAQUE) == OPAQUE


def test_weakest_composed_and_opaque():
    """weakest() with COMPOSED and OPAQUE returns OPAQUE."""
    assert weakest(COMPOSED, OPAQUE) == OPAQUE


def test_weakest_all_three():
    """weakest() with all three classes returns OPAQUE."""
    assert weakest(LITERAL, COMPOSED, OPAQUE) == OPAQUE


def _state_at(src: str, callee: str = "execute"):
    fn = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)][0]
    tainted = {a.arg: f"input:{a.arg}" for a in fn.args.args}
    states = snapshot_call_sites(fn, tainted)
    call = next(
        n for n in ast.walk(fn)
        if isinstance(n, ast.Call) and ast.unparse(n.func).endswith(callee)
    )
    return states[id(call)], call


def test_later_assignment_does_not_taint_an_earlier_call():
    """The rev.2 bug: state from the future reached back to an earlier call site."""
    src = (
        "def f(uid):\n"
        '    q = "SELECT 1"\n'
        "    cursor.execute(q)\n"
        '    q = f"SELECT {uid}"\n'
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == LITERAL


def test_earlier_assignment_does_reach_a_later_call():
    src = (
        "def f(uid):\n"
        '    q = f"SELECT {uid}"\n'
        "    cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED


def test_augmented_assignment_composes():
    src = (
        "def f(uid):\n"
        '    q = "SELECT 1"\n'
        '    q += " WHERE id = " + uid\n'
        "    cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED


def test_branch_merge_takes_the_weakest():
    src = (
        "def f(uid, flag):\n"
        '    q = "SELECT 1"\n'
        "    if flag:\n"
        '        q = f"SELECT {uid}"\n'
        "    cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED


def test_call_inside_a_branch_sees_branch_local_state():
    src = (
        "def f(uid, flag):\n"
        '    q = "SELECT 1"\n'
        "    if flag:\n"
        '        q = f"SELECT {uid}"\n'
        "        cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED


def test_parameter_is_opaque_and_tainted():
    state, call = _state_at("def f(q):\n    cursor.execute(q)\n")
    assert classify_expr(call.args[0], state.bindings) == OPAQUE
    assert "q" in state.tainted


def test_loop_carried_composition_is_visible():
    """A value composed on one iteration reaches the call on the next."""
    src = (
        "def f(uid, rows):\n"
        '    q = "SELECT 1"\n'
        "    for row in rows:\n"
        "        cursor.execute(q)\n"
        '        q = f"SELECT {uid}"\n'
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED


def test_taint_is_also_call_site_sensitive():
    src = (
        "def f(uid):\n"
        "    cursor.execute(safe_value)\n"
        "    safe_value = uid\n"
    )
    state, call = _state_at(src)
    assert "safe_value" not in state.tainted


# --- Fix round 1 regressions -------------------------------------------------


def _states_for(src: str, callee: str = "execute"):
    """Like _state_at, but returns every matching call's state, in source order."""
    fn = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)][0]
    tainted = {a.arg: f"input:{a.arg}" for a in fn.args.args}
    states = snapshot_call_sites(fn, tainted)
    calls = [
        n
        for n in ast.walk(fn)
        if isinstance(n, ast.Call) and ast.unparse(n.func).endswith(callee)
    ]
    return [states[id(call)] for call in calls], calls


def test_branch_merge_does_not_leak_if_arm_into_else_arm():
    """C1: an else arm must not see effects from the if arm it never ran after."""
    src = (
        "def f(uid, flag):\n"
        '    q = "SELECT 1"\n'
        "    if flag:\n"
        '        q = f"SELECT {uid}"\n'
        "    else:\n"
        "        cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == LITERAL


def test_loop_two_hop_chain_converges():
    """C2: convergence must track assignment hops, not lattice height."""
    src = (
        "def f(uid, rows):\n"
        '    a = "SELECT 1"\n'
        '    b = "SELECT 1"\n'
        "    for r in rows:\n"
        "        cursor.execute(b)\n"
        "        b = a\n"
        '        a = f"SELECT {uid}"\n'
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED


def test_loop_three_hop_chain_converges():
    """C2: a longer chain still converges within the pass cap."""
    src = (
        "def f(uid, rows):\n"
        '    a = "SELECT 1"\n'
        '    b = "SELECT 1"\n'
        '    c = "SELECT 1"\n'
        "    for r in rows:\n"
        "        cursor.execute(c)\n"
        "        c = b\n"
        "        b = a\n"
        '        a = f"SELECT {uid}"\n'
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED


def test_match_case_composition_is_visible_in_case_and_after():
    """C3: match/case bodies must be walked with their own branch-local state."""
    src = (
        "def f(uid, flag):\n"
        '    q = "SELECT 1"\n'
        "    match flag:\n"
        "        case 1:\n"
        '            q = f"SELECT {uid}"\n'
        "            cursor.execute(q)\n"
        "    cursor.execute(q)\n"
    )
    states, calls = _states_for(src)
    assert len(calls) == 2
    for state, call in zip(states, calls, strict=True):
        assert classify_expr(call.args[0], state.bindings) == COMPOSED


@pytest.mark.skipif(sys.version_info < (3, 11), reason="except* requires Python 3.11+")
def test_except_star_composition_is_visible_in_body_and_after():
    """C4: ast.TryStar must be recognised, not silently fall through to LITERAL."""
    src = (
        "def f(uid):\n"
        '    q = "SELECT 1"\n'
        "    try:\n"
        "        risky()\n"
        "    except* ValueError:\n"
        '        q = f"SELECT {uid}"\n'
        "        cursor.execute(q)\n"
        "    cursor.execute(q)\n"
    )
    states, calls = _states_for(src)
    assert len(calls) == 2
    for state, call in zip(states, calls, strict=True):
        assert classify_expr(call.args[0], state.bindings) == COMPOSED


def test_for_target_shadowing_prior_literal_is_not_literal():
    """C5: a for-loop target must overwrite a prior binding of the same name."""
    src = (
        "def f(uid, rows):\n"
        '    q = "SELECT 1"\n'
        "    for q in rows:\n"
        "        cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) != LITERAL


def test_with_target_shadowing_prior_literal_is_not_literal():
    """C5: a with-target must overwrite a prior binding of the same name."""
    src = (
        "def f(uid):\n"
        '    q = "SELECT 1"\n'
        "    with make(uid) as q:\n"
        "        cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) != LITERAL


def test_except_target_shadowing_prior_literal_is_not_literal():
    """C5: an except-as name must overwrite a prior binding of the same name."""
    src = (
        "def f(uid):\n"
        '    q = "SELECT 1"\n'
        "    try:\n"
        "        risky()\n"
        "    except Exception as q:\n"
        "        cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) != LITERAL


def test_walrus_shadowing_prior_literal_is_not_literal():
    """C5: a walrus target must overwrite a prior binding of the same name."""
    src = (
        "def f(uid):\n"
        '    q = "SELECT 1"\n'
        "    if (q := make(uid)):\n"
        "        pass\n"
        "    cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) != LITERAL


def test_comprehension_target_shadowing_prior_literal_is_not_literal():
    """C5: a comprehension target must overwrite a prior binding of the same name."""
    src = (
        "def f(uid):\n"
        '    q = "SELECT 1"\n'
        "    [q for q in range(3)]\n"
        "    cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) != LITERAL


def test_call_in_for_else_body_is_snapshotted():
    """I1: a for/else body must be covered by the returned mapping."""
    src = (
        "def f(uid, rows):\n"
        '    q = "SELECT 1"\n'
        "    for row in rows:\n"
        "        pass\n"
        "    else:\n"
        "        cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == LITERAL


# --- Fix round 2 regressions -------------------------------------------------


def test_try_body_composition_reaches_finally_call():
    """R1: finally is a sequential successor of the body, not an alternative to it."""
    src = (
        "def f(uid):\n"
        '    q = "SELECT 1"\n'
        "    try:\n"
        '        q = "SELECT * FROM t WHERE id=" + uid\n'
        "    finally:\n"
        "        cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED
    assert "q" in state.tainted


def test_try_body_composition_reaches_else_call():
    """R1: else is a sequential successor of the body, not an alternative to it."""
    src = (
        "def f(uid):\n"
        '    q = "SELECT 1"\n'
        "    try:\n"
        '        q = "SELECT * FROM t WHERE id=" + uid\n'
        "    except Exception:\n"
        "        pass\n"
        "    else:\n"
        "        cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED
    assert "q" in state.tainted


def test_try_body_composition_reaches_except_call():
    """R1: a handler sees the body's post-state, even though it may run partway through."""
    src = (
        "def f(uid):\n"
        '    q = "SELECT 1"\n'
        "    try:\n"
        '        q = "SELECT * FROM t WHERE id=" + uid\n'
        "        raise ValueError()\n"
        "    except ValueError:\n"
        "        cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED
    assert "q" in state.tainted


def test_try_body_opaque_assignment_reaches_finally_call():
    """R1: the worst-case regression — an opaque, tainted value must not read as clean."""
    src = (
        "def f(uid):\n"
        '    q = "SELECT 1"\n'
        "    try:\n"
        "        q = build(uid)\n"
        "    finally:\n"
        "        cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == OPAQUE
    assert "q" in state.tainted


def test_match_case_does_not_leak_into_sibling_case():
    """C1 must still hold for match: sibling cases are alternatives, not successors."""
    src = (
        "def f(uid, flag):\n"
        '    q = "SELECT 1"\n'
        "    match flag:\n"
        "        case 1:\n"
        '            q = f"SELECT {uid}"\n'
        "        case 2:\n"
        "            cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == LITERAL


@pytest.mark.parametrize(
    "case_line",
    [
        "case [q]:",
        "case {'k': q}:",
        "case Point(x=q):",
        "case str() as q:",
        "case [1, *q]:",
    ],
)
def test_match_capture_patterns_shadow_prior_literal(case_line):
    """R2: MatchAs/MatchStar/MatchMapping capture names must rebind, not be missed."""
    src = (
        "def f(payload):\n"
        '    q = "SELECT 1"\n'
        "    match payload:\n"
        f"        {case_line}\n"
        "            cursor.execute(q)\n"
        "    cursor.execute(q)\n"
    )
    states, calls = _states_for(src)
    assert len(calls) == 2
    for state, call in zip(states, calls, strict=True):
        assert classify_expr(call.args[0], state.bindings) != LITERAL
        assert "q" in state.tainted


def test_match_bare_name_and_class_positional_capture_shadow_prior_literal():
    """R2: a bare-name pattern and a positional class-pattern capture are both MatchAs."""
    for case_line in ("case q:", "case Point(q):"):
        src = (
            "def f(payload):\n"
            '    q = "SELECT 1"\n'
            "    match payload:\n"
            f"        {case_line}\n"
            "            cursor.execute(q)\n"
            "    cursor.execute(q)\n"
        )
        states, calls = _states_for(src)
        assert len(calls) == 2
        for state, call in zip(states, calls, strict=True):
            assert classify_expr(call.args[0], state.bindings) != LITERAL
            assert "q" in state.tainted


def test_match_or_pattern_as_capture_shadows_prior_literal():
    """R2: an ``as`` capture on an or-pattern is still MatchAs."""
    src = (
        "def f(payload):\n"
        '    q = "SELECT 1"\n'
        "    match payload:\n"
        "        case (1 | 2) as q:\n"
        "            cursor.execute(q)\n"
        "    cursor.execute(q)\n"
    )
    states, calls = _states_for(src)
    assert len(calls) == 2
    for state, call in zip(states, calls, strict=True):
        assert classify_expr(call.args[0], state.bindings) != LITERAL
        assert "q" in state.tainted


def test_match_double_star_mapping_rest_shadows_prior_literal():
    """R2: MatchMapping's ``**rest`` capture must rebind too."""
    src = (
        "def f(payload):\n"
        '    q = "SELECT 1"\n'
        "    match payload:\n"
        "        case {**q}:\n"
        "            cursor.execute(q)\n"
        "    cursor.execute(q)\n"
    )
    states, calls = _states_for(src)
    assert len(calls) == 2
    for state, call in zip(states, calls, strict=True):
        assert classify_expr(call.args[0], state.bindings) != LITERAL
        assert "q" in state.tainted


def test_match_wildcard_does_not_bind():
    """R2: MatchAs with name=None is the wildcard `_` and captures nothing."""
    src = (
        "def f(payload):\n"
        '    q = "SELECT 1"\n'
        "    match payload:\n"
        "        case _:\n"
        "            pass\n"
        "    cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == LITERAL
    assert "q" not in state.tainted


def test_loop_ten_variable_chain_widens_on_cap_exhaustion():
    """R3: a chain long enough to outrun the pass cap must widen, not miss."""
    names = [f"v{i}" for i in range(10)]
    lines = ["def f(uid, rows):"]
    for name in names:
        lines.append(f'    {name} = "SELECT 1"')
    lines.append("    for r in rows:")
    lines.append(f"        cursor.execute({names[0]})")
    for a, b in zip(names, names[1:]):
        lines.append(f"        {a} = {b}")
    lines.append(f'        {names[-1]} = f"SELECT {{uid}}"')
    src = "\n".join(lines) + "\n"
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) != LITERAL
    assert "v0" in state.tainted


def test_import_as_shadows_prior_literal():
    """R4: import ... as q must rebind q, via alias.asname."""
    src = (
        "def f():\n"
        '    q = "SELECT 1"\n'
        "    import os as q\n"
        "    cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) != LITERAL


def test_del_shadows_prior_literal():
    """R4: del q must rebind q, via Name with Del context."""
    src = (
        "def f():\n"
        '    q = "SELECT 1"\n'
        "    del q\n"
        "    cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) != LITERAL


@pytest.mark.parametrize(
    "name,src",
    [
        ("plain literal", 'def f():\n    q = "SELECT 1"\n    cursor.execute(q)\n'),
        (
            "if",
            'def f(flag):\n    q = "SELECT 1"\n    if flag:\n        pass\n'
            "    cursor.execute(q)\n",
        ),
        (
            "if/else",
            'def f(flag):\n    q = "SELECT 1"\n    if flag:\n        pass\n'
            "    else:\n        pass\n    cursor.execute(q)\n",
        ),
        (
            "for",
            'def f(rows):\n    q = "SELECT 1"\n    for x in rows:\n        pass\n'
            "    cursor.execute(q)\n",
        ),
        (
            "while",
            'def f(flag):\n    q = "SELECT 1"\n    while flag:\n        break\n'
            "    cursor.execute(q)\n",
        ),
        (
            "with",
            "def f():\n    q = \"SELECT 1\"\n    with open('f') as fh:\n        pass\n"
            "    cursor.execute(q)\n",
        ),
        (
            "try/except",
            'def f():\n    q = "SELECT 1"\n    try:\n        pass\n'
            "    except Exception:\n        pass\n    cursor.execute(q)\n",
        ),
        (
            "try/finally",
            'def f():\n    q = "SELECT 1"\n    try:\n        pass\n'
            "    finally:\n        pass\n    cursor.execute(q)\n",
        ),
        (
            "for/else",
            'def f(rows):\n    q = "SELECT 1"\n    for x in rows:\n        pass\n'
            "    else:\n        pass\n    cursor.execute(q)\n",
        ),
        (
            "match",
            'def f(flag):\n    q = "SELECT 1"\n    match flag:\n        case 1:\n'
            "            pass\n    cursor.execute(q)\n",
        ),
        (
            "nested for+if+with",
            "def f(rows, flag):\n    q = \"SELECT 1\"\n    for x in rows:\n"
            "        if flag:\n            with open('f'):\n                pass\n"
            "    cursor.execute(q)\n",
        ),
        ("constant concat", 'def f():\n    q = "a" + "b"\n    cursor.execute(q)\n'),
        ("constant-only f-string", 'def f():\n    q = f"SELECT 1"\n    cursor.execute(q)\n'),
        (
            "comprehension",
            'def f(rows):\n    q = "SELECT 1"\n    [x for x in rows]\n    cursor.execute(q)\n',
        ),
        ("assert", 'def f(flag):\n    q = "SELECT 1"\n    assert flag\n    cursor.execute(q)\n'),
        ("import", 'def f():\n    q = "SELECT 1"\n    import os\n    cursor.execute(q)\n'),
        (
            "nested def",
            'def f():\n    q = "SELECT 1"\n    def helper():\n        pass\n'
            "    cursor.execute(q)\n",
        ),
        ("annotated assign", 'def f():\n    q: str = "SELECT 1"\n    cursor.execute(q)\n'),
        ("global", 'def f():\n    global q\n    q = "SELECT 1"\n    cursor.execute(q)\n'),
    ],
)
def test_ordinary_safe_code_stays_literal(name, src):
    """The round-2 fixes must not make ordinary, unambiguously-safe code noisy."""
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == LITERAL, name

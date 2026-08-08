import ast

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

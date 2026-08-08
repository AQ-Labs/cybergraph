import ast

import pytest

from cybergraph.analysis.provenance import COMPOSED, LITERAL, OPAQUE, classify_expr, weakest


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

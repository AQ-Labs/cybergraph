from __future__ import annotations

from cybergraph.analysis.java_provenance import (
    assess,
    assess_command,
    assess_deserialization,
    classify,
)
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE
from cybergraph.security.sinks import lookup_sink


def _sql():
    return lookup_sink("stmt.executeQuery", "java")


def test_classify():
    assert classify('"SELECT 1"') == "literal"
    assert classify('"SELECT " + id') == "composed"
    assert classify('String.format("SELECT %s", id)') == "composed"
    assert (
        classify("sb.append(id).toString()") == "composed"
        or classify("sb.append(id)") == "composed"
    )
    assert classify("buildQuery()") == "opaque"


def test_assess_sql_literal_safe():
    assert assess(_sql(), '"SELECT 1"', set()) == VERDICT_SAFE


def test_assess_sql_concat_tainted_unsafe():
    assert assess(_sql(), '"SELECT * FROM u WHERE id = " + id', {"id"}) == VERDICT_UNSAFE


def test_assess_sql_format_variable_format_unsafe():
    assert assess(_sql(), "String.format(userFmt, x)", {"userFmt"}) == VERDICT_UNSAFE


def test_assess_sql_unresolved_unknown():
    assert assess(_sql(), '"SELECT " + id', set()) == VERDICT_UNKNOWN


def test_assess_command_shell_tainted_unsafe():
    assert assess_command(['"sh"', '"-c"', "userCmd"], {"userCmd"}) == VERDICT_UNSAFE
    assert assess_command(['"ls"', '"-la"'], set()) == VERDICT_SAFE


def test_deserialization_never_safe():
    assert assess_deserialization(True) == VERDICT_UNSAFE     # tainted stream
    assert assess_deserialization(False) == VERDICT_UNKNOWN   # unresolved -> still not safe


def test_assess_append_text_in_string_literal_does_not_hide_tainted_operand():
    # ".append(" appearing inside a string literal must not be read as a real
    # StringBuilder chain -- doing so would hijack the append branch and drop
    # the tainted `userInput` operand after the `+`, a false SAFE.
    assert assess(_sql(), '"foo.append(1)" + userInput', {"userInput"}) == VERDICT_UNSAFE


def test_assess_format_call_containing_append_text_does_not_hide_tainted_operand():
    # Same hijack, via a `String.format(...)` call whose own string-literal
    # argument happens to contain the text ".append(".
    assert (
        assess(_sql(), 'String.format("x.append(1)") + userInput', {"userInput"})
        == VERDICT_UNSAFE
    )


def test_assess_append_text_in_string_literal_untainted_is_unknown_not_safe():
    # Same shape as above, but the `+` operand is a plain, unresolved
    # identifier rather than a taint-confirmed one -- UNKNOWN, never SAFE.
    assert assess(_sql(), '"foo.append(1)" + other', set()) == VERDICT_UNKNOWN


def test_assess_stringbuilder_chain_tainted_append_unsafe():
    # A genuine StringBuilder chain, assessed (not just classified): a
    # tainted appended operand must read UNSAFE.
    assert assess(_sql(), 'sb.append("x").append(userInput)', {"userInput"}) == VERDICT_UNSAFE


def test_assess_parenthesized_operand_never_safe():
    # A parenthesized operand is not a proven literal even when it wraps a
    # tainted name -- it must never read SAFE. The OPAQUE bare-identifier
    # check does not unwrap parens, so this resolves to UNKNOWN, not UNSAFE --
    # pinned exactly rather than with a weaker `!= VERDICT_SAFE`.
    assert assess(_sql(), "(userInput)", {"userInput"}) == VERDICT_UNKNOWN


def test_assess_stringbuilder_all_literal_chain_is_safe():
    # The one legitimate append-SAFE case: every appended operand is a
    # proven literal, so the fail-safe fix for the unbalanced-quote bug below
    # must not over-correct this into UNKNOWN.
    assert assess(_sql(), 'sb.append("a").append("b")', set()) == VERDICT_SAFE


def test_assess_append_unbalanced_string_swallows_real_call_not_safe():
    # `"a` never closes, so the single-pass quote-tracking scan reads the
    # rest of the text -- including the real `.append(userInput)` -- as
    # still "inside a string." The detected append site's own argument then
    # fails to balance too, which must register as unresolved, not as "no
    # operands found, so every operand is trivially literal."
    assert assess(_sql(), 'sb.append("a).append(userInput)', {"userInput"}) == VERDICT_UNKNOWN


def test_assess_append_escaped_quote_swallows_real_call_not_safe():
    # Same failure mode via an escaped quote (`\"`) that never terminates the
    # string instead of a plain missing closing quote.
    assert (
        assess(_sql(), 'sb.append("a\\").append(userInput)', {"userInput"}) == VERDICT_UNKNOWN
    )

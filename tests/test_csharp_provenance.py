from __future__ import annotations

from cybergraph.analysis.csharp_provenance import (
    assess,
    assess_command,
    assess_deserialization,
    classify,
    variable_names,
)
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE
from cybergraph.security.sinks import lookup_sink


def _sql():
    return lookup_sink("cmd.ExecuteReader", "csharp")


# --- interpolation ---------------------------------------------------------
def test_interpolation_tainted_hole_is_unsafe():
    assert assess(_sql(), '$"SELECT * FROM u WHERE id = {id}"', {"id"}) == VERDICT_UNSAFE

def test_interpolation_unresolved_hole_is_unknown_never_safe():
    assert assess(_sql(), '$"SELECT * FROM u WHERE id = {id}"', set()) == VERDICT_UNKNOWN

def test_interpolation_all_literal_holes_is_safe():
    # holes are literals/constants -> the whole interpolation is constant
    assert assess(_sql(), '$"SELECT * FROM u LIMIT {10}"', set()) == VERDICT_SAFE

def test_interpolation_no_holes_is_safe():
    assert assess(_sql(), '$"SELECT * FROM users"', set()) == VERDICT_SAFE

def test_interpolation_format_and_alignment_suffix_stripped():
    # `{total,10:C}` -> operand `total`; still non-literal -> not safe
    assert assess(_sql(), '$"total = {total,10:C}"', {"total"}) == VERDICT_UNSAFE

def test_interpolation_escaped_braces_are_literal():
    assert assess(_sql(), '$"a literal brace {{ and id {id}}}"', {"id"}) == VERDICT_UNSAFE
    assert assess(_sql(), '$"just braces {{no hole}}"', set()) == VERDICT_SAFE

def test_interpolated_verbatim_quote_in_body_does_not_desync():
    # $@"..." : "" is an escaped quote, not the end; the {id} hole is still seen
    assert assess(_sql(), '$@"WHERE name = ""x"" AND id = {id}"', {"id"}) == VERDICT_UNSAFE

def test_verbatim_string_no_hole_is_safe():
    assert assess(_sql(), '@"SELECT * FROM users"', set()) == VERDICT_SAFE

def test_classify_interpolation_with_hole_is_composed():
    assert classify('$"id = {id}"') == "composed"
    assert classify('$"no holes"') == "literal"

def test_variable_names_reports_interpolation_holes():
    assert "id" in variable_names('$"id = {id}"')


# --- ternary colon must not be mistaken for a `:format` separator ----------
def test_interpolation_ternary_colon_is_not_format_suffix():
    assert assess(_sql(), '$"{true ? 1 : userInput}"', {"userInput"}) == VERDICT_UNSAFE
    assert assess(_sql(), '$"{false ? 2 : userInput}"', {"userInput"}) == VERDICT_UNSAFE

def test_interpolation_ternary_colon_in_sql_is_unsafe():
    assert (
        assess(_sql(), '$"SELECT * FROM u WHERE id={true ? 1 : userId}"', {"userId"})
        == VERDICT_UNSAFE
    )

def test_interpolation_nested_ternary_colon_is_not_format_suffix():
    assert assess(_sql(), '$"{a ? b : c ? d : userInput}"', {"userInput"}) == VERDICT_UNSAFE

def test_variable_names_reports_ternary_branch():
    assert "userId" in variable_names('$"id={true ? 1 : userId}"')

def test_interpolation_genuine_format_suffix_still_stripped():
    assert assess(_sql(), '$"{x:D2}"', {"x"}) == VERDICT_UNSAFE
    assert assess(_sql(), '$"total = {total,10:C}"', {"total"}) == VERDICT_UNSAFE

def test_interpolation_bare_constant_hole_is_safe():
    assert assess(_sql(), '$"{true}"', set()) == VERDICT_SAFE


# --- inherited (ported from java) ------------------------------------------
def test_concat_tainted_is_unsafe():
    assert assess(_sql(), '"SELECT * WHERE id = " + id', {"id"}) == VERDICT_UNSAFE

def test_string_format_tainted_is_unsafe():
    assert assess(_sql(), 'string.Format("id = {0}", id)', {"id"}) == VERDICT_UNSAFE

def test_stringbuilder_all_literal_variable_receiver_never_safe():
    assert assess(_sql(), 'sb.Append("a").Append("b")', set()) == VERDICT_UNKNOWN

def test_plain_literal_is_safe():
    assert assess(_sql(), '"SELECT 1"', set()) == VERDICT_SAFE


# --- command / deserialization ---------------------------------------------
def test_command_shell_form_all_args_assessed():
    assert lookup_sink("Process.Start", "csharp") is not None
    assert assess_command(['"cmd"', '"/c"', "user"], {"user"}) == VERDICT_UNSAFE
    assert assess_command(['"cmd"', '"/c"', '"dir"'], set()) == VERDICT_SAFE

def test_deserialization_is_never_safe():
    assert assess_deserialization(True) == VERDICT_UNSAFE
    assert assess_deserialization(False) == VERDICT_UNKNOWN

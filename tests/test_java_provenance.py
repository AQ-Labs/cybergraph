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

from __future__ import annotations

from cybergraph.analysis.js_provenance import (
    assess,
    classify,
    extract_first_arg,
    variable_names,
)
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE
from cybergraph.security.sinks import lookup_sink


def _sink(name):
    return lookup_sink(name, "javascript")


def test_extract_first_arg_balanced_and_string_aware():
    src = "db.query(`SELECT ${x}`, [y])"
    open_paren = src.index("(")
    assert extract_first_arg(src, open_paren) == "`SELECT ${x}`"
    # a ')' inside a string must not end the arg early
    src2 = "exec('echo )')"
    assert extract_first_arg(src2, src2.index("(")) == "'echo )'"
    # unbalanced -> None
    assert extract_first_arg("db.query(`oops", 8) is None


def test_classify():
    assert classify("'SELECT 1'") == "literal"
    assert classify('"static"') == "literal"
    assert classify("`no interpolation`") == "literal"
    assert classify("`SELECT ${x}`") == "composed"
    assert classify("'SELECT ' + name") == "composed"
    assert classify("someVar") == "opaque"
    assert classify("build()") == "opaque"


def test_variable_names():
    assert variable_names("`SELECT ${name} FROM t`") == ["name"]
    assert variable_names("'a' + b + 'c'") == ["b"]
    assert variable_names("`only literals`") == []


def test_assess_sql_literal_is_safe():
    assert assess(_sink("db.query"), "'SELECT 1'", set()) == VERDICT_SAFE


def test_assess_sql_tainted_variable_is_unsafe():
    assert assess(_sink("db.query"), "`SELECT ${id}`", {"id"}) == VERDICT_UNSAFE


def test_assess_sql_unresolved_variable_is_unknown_not_safe():
    # a variable taint can't confirm must NOT read safe (JS taint is weaker than Python's)
    assert assess(_sink("db.query"), "`SELECT ${id}`", set()) == VERDICT_UNKNOWN


def test_assess_sql_all_literal_template_is_safe():
    assert assess(_sink("db.query"), "`SELECT 1 FROM t`", set()) == VERDICT_SAFE


def test_assess_opaque_is_unknown():
    assert assess(_sink("db.query"), "buildQuery()", set()) == VERDICT_UNKNOWN


def test_assess_unreadable_arg_is_unknown():
    assert assess(_sink("db.query"), None, set()) == VERDICT_UNKNOWN


def test_assess_code_eval_literal_safe_variable_unsafe():
    assert assess(_sink("eval"), "'1 + 1'", set()) == VERDICT_SAFE
    assert assess(_sink("eval"), "userCode", {"userCode"}) == VERDICT_UNSAFE
    assert assess(_sink("eval"), "userCode", set()) == VERDICT_UNKNOWN


def test_assess_command_inherent_shell_tainted_unsafe():
    assert assess(_sink("child_process.exec"), "`ls ${dir}`", {"dir"}) == VERDICT_UNSAFE
    assert assess(_sink("child_process.exec"), "`ls ${dir}`", set()) == VERDICT_UNKNOWN
    assert assess(_sink("child_process.exec"), "'ls -la'", set()) == VERDICT_SAFE

from __future__ import annotations

from cybergraph.analysis.go_provenance import (
    assess,
    assess_command,
    classify,
    extract_all_args,
    extract_first_arg,
)
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE
from cybergraph.security.sinks import lookup_sink


def _sink(name):
    return lookup_sink(name, "go")


def test_extract_first_arg_string_aware():
    src = 'db.Query(fmt.Sprintf("SELECT %s", id), other)'
    assert extract_first_arg(src, src.index("(")) == 'fmt.Sprintf("SELECT %s", id)'
    assert extract_first_arg('db.Query(`raw ) str`)', 8) == '`raw ) str`'
    assert extract_first_arg("db.Query(`oops", 8) is None


def test_classify():
    assert classify('"SELECT 1"') == "literal"
    assert classify("`SELECT 1`") == "literal"
    assert classify('"SELECT " + id') == "composed"
    assert classify('fmt.Sprintf("SELECT %s", id)') == "composed"
    assert classify("userVar") == "opaque"


def test_assess_literal_safe():
    assert assess(_sink("db.Query"), '"SELECT 1"', set()) == VERDICT_SAFE


def test_assess_sprintf_tainted_unsafe():
    assert assess(_sink("db.Query"), 'fmt.Sprintf("SELECT %s", id)', {"id"}) == VERDICT_UNSAFE


def test_assess_sprintf_unresolved_unknown():
    assert assess(_sink("db.Query"), 'fmt.Sprintf("SELECT %s", id)', set()) == VERDICT_UNKNOWN


def test_assess_sprintf_all_literal_safe():
    assert assess(_sink("db.Query"), 'fmt.Sprintf("SELECT %d", 1)', set()) == VERDICT_SAFE


def test_assess_concat_tainted_unsafe():
    assert assess(_sink("db.Query"), '"SELECT " + name', {"name"}) == VERDICT_UNSAFE


def test_assess_non_leading_ident_operand_not_safe():
    # the JS-lesson guard: an operand not led by an identifier must not read SAFE
    assert assess(_sink("db.Query"), '"x = " + (id)', {"id"}) == VERDICT_UNSAFE
    assert assess(_sink("db.Query"), '"x = " + (id)', set()) == VERDICT_UNKNOWN


def test_assess_opaque_unknown():
    assert assess(_sink("db.Query"), "buildQuery()", set()) == VERDICT_UNKNOWN


def test_assess_unreadable_unknown():
    assert assess(_sink("db.Query"), None, set()) == VERDICT_UNKNOWN


# -- C1: fmt.Sprintf's FORMAT argument is a runtime value in Go, not a literal --


def test_sprintf_variable_format_is_unsafe():
    assert assess(
        _sink("db.Query"), "fmt.Sprintf(userQuery)", {"userQuery"}
    ) == VERDICT_UNSAFE
    assert assess(
        _sink("db.Query"), 'fmt.Sprintf("SELECT * FROM " + tbl)', {"tbl"}
    ) == VERDICT_UNSAFE


# -- C2: command sinks must be assessed over ALL arguments, not just argv[0] --


def _cmd_sink():
    return _sink("exec.Command")


def test_command_shell_form_tainted_is_unsafe():
    src = 'exec.Command("sh", "-c", userCmd)'
    args = extract_all_args(src, src.index("("))
    assert args == ['"sh"', '"-c"', "userCmd"]
    assert assess_command(_cmd_sink(), args, {"userCmd"}) == VERDICT_UNSAFE


def test_command_shell_form_unresolved_is_unknown():
    src = 'exec.Command("sh", "-c", userCmd)'
    args = extract_all_args(src, src.index("("))
    assert assess_command(_cmd_sink(), args, set()) == VERDICT_UNKNOWN


def test_command_all_literal_is_safe():
    src = 'exec.Command("ls", "-la")'
    args = extract_all_args(src, src.index("("))
    assert assess_command(_cmd_sink(), args, set()) == VERDICT_SAFE


def test_command_argv_tainted_is_unsafe_or_unknown():
    src = 'exec.Command("git", userBranch)'
    args = extract_all_args(src, src.index("("))
    assert assess_command(_cmd_sink(), args, {"userBranch"}) in (
        VERDICT_UNSAFE,
        VERDICT_UNKNOWN,
    )
    assert assess_command(_cmd_sink(), args, {"userBranch"}) != VERDICT_SAFE

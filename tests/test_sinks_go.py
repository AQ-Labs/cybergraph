from __future__ import annotations

import pytest

from cybergraph.security.sinks import lookup_sink


@pytest.mark.parametrize("call_name,rule_id,vuln", [
    ("db.Query", "CG-SQL-EXEC", "sql"),
    ("db.QueryRow", "CG-SQL-EXEC", "sql"),
    ("tx.Exec", "CG-SQL-EXEC", "sql"),
    ("db.QueryContext", "CG-SQL-EXEC", "sql"),
    ("exec.Command", "CG-CMD-EXEC", "command"),
    ("exec.CommandContext", "CG-CMD-EXEC", "command"),
    ("os.Open", "CG-PATH-TRAVERSAL", "path"),
    ("os.ReadFile", "CG-PATH-TRAVERSAL", "path"),
    ("ioutil.WriteFile", "CG-PATH-TRAVERSAL", "path"),
    ("os.Create", "CG-PATH-TRAVERSAL", "path"),
])
def test_go_sinks_resolve(call_name, rule_id, vuln):
    sink = lookup_sink(call_name, "go")
    assert sink is not None, call_name
    assert sink.rule_id == rule_id
    assert sink.vuln_class == vuln


def test_go_non_sink_is_none():
    assert lookup_sink("fmt.Sprintf", "go") is None  # construction, not a sink
    assert lookup_sink("log.Println", "go") is None


def test_other_languages_unchanged():
    assert lookup_sink("os.system", "python").rule_id == "CG-CMD-EXEC"
    assert lookup_sink("db.Query", "python") is None
    assert lookup_sink("db.query", "javascript").rule_id == "CG-SQL-EXEC"

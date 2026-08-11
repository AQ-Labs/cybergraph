from __future__ import annotations

import pytest

from cybergraph.security.sinks import lookup_sink


@pytest.mark.parametrize("call_name,rule_id,vuln", [
    ("db.query", "CG-SQL-EXEC", "sql"),
    ("pool.query", "CG-SQL-EXEC", "sql"),
    ("knex.raw", "CG-SQL-EXEC", "sql"),
    ("connection.execute", "CG-SQL-EXEC", "sql"),
    ("child_process.exec", "CG-CMD-EXEC", "command"),
    ("execSync", "CG-CMD-EXEC", "command"),
    ("eval", "CG-CODE-EXEC", "code"),
    ("Function", "CG-CODE-EXEC", "code"),
    ("fs.readFile", "CG-PATH-TRAVERSAL", "path"),
    ("fsp.writeFile", "CG-PATH-TRAVERSAL", "path"),
])
def test_javascript_sinks_resolve(call_name, rule_id, vuln):
    sink = lookup_sink(call_name, "javascript")
    assert sink is not None, call_name
    assert sink.rule_id == rule_id
    assert sink.vuln_class == vuln


def test_non_sink_js_name_is_none():
    assert lookup_sink("res.render", "javascript") is None
    assert lookup_sink("console.log", "javascript") is None


def test_python_lookups_unchanged():
    assert lookup_sink("os.system", "python").rule_id == "CG-CMD-EXEC"
    assert lookup_sink("db.query", "python") is None  # JS sink not registered for python

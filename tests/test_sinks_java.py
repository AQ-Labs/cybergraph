from __future__ import annotations

import pytest

from cybergraph.security.sinks import lookup_sink


@pytest.mark.parametrize("call_name,rule_id,vuln", [
    ("stmt.executeQuery", "CG-SQL-EXEC", "sql"),
    ("stmt.executeUpdate", "CG-SQL-EXEC", "sql"),
    ("em.createNativeQuery", "CG-SQL-EXEC", "sql"),
    ("jdbcTemplate.query", "CG-SQL-EXEC", "sql"),
    ("conn.prepareStatement", "CG-SQL-EXEC", "sql"),
    ("conn.prepareCall", "CG-SQL-EXEC", "sql"),
    ("Runtime.exec", "CG-CMD-EXEC", "command"),
    ("pb.start", "CG-CMD-EXEC", "command"),
    ("File", "CG-PATH-TRAVERSAL", "path"),
    ("Files.readAllBytes", "CG-PATH-TRAVERSAL", "path"),
    ("ois.readObject", "CG-DESERIALIZE", "deserialize"),
    ("ois.readUnshared", "CG-DESERIALIZE", "deserialize"),
])
def test_java_sinks_resolve(call_name, rule_id, vuln):
    sink = lookup_sink(call_name, "java")
    assert sink is not None, call_name
    assert sink.rule_id == rule_id
    assert sink.vuln_class == vuln


def test_java_non_sink_is_none():
    assert lookup_sink("logger.info", "java") is None
    assert lookup_sink("list.add", "java") is None


def test_other_languages_unchanged():
    assert lookup_sink("os.system", "python").rule_id == "CG-CMD-EXEC"
    assert lookup_sink("pickle.loads", "python").rule_id == "CG-DESERIALIZE"
    assert lookup_sink("stmt.executeQuery", "python") is None
    assert lookup_sink("db.query", "javascript").rule_id == "CG-SQL-EXEC"

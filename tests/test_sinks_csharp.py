from __future__ import annotations

from cybergraph.security.sinks import lookup_sink


def test_csharp_sql_sinks():
    for name in ("cmd.ExecuteReader", "db.Query", "conn.ExecuteScalarAsync"):
        s = lookup_sink(name, "csharp")
        assert s is not None and s.rule_id == "CG-SQL-EXEC" and s.vuln_class == "sql"


def test_csharp_command_sink_is_shell_conditional():
    from cybergraph.security.sinks import SHELL_CONDITIONAL
    s = lookup_sink("Process.Start", "csharp")
    assert s is not None and s.rule_id == "CG-CMD-EXEC"
    assert s.vuln_class == "command" and s.shell == SHELL_CONDITIONAL


def test_csharp_path_and_deserialization_and_code():
    assert lookup_sink("File.ReadAllText", "csharp").rule_id == "CG-PATH-TRAVERSAL"
    assert lookup_sink("formatter.Deserialize", "csharp").rule_id == "CG-DESERIALIZE"
    assert lookup_sink("reader.ReadObject", "csharp").rule_id == "CG-DESERIALIZE"
    assert lookup_sink("CSharpScript.EvaluateAsync", "csharp").rule_id == "CG-CODE-EXEC"


def test_no_cross_language_leakage():
    assert lookup_sink("cmd.ExecuteReader", "python") is None
    assert lookup_sink("cmd.ExecuteReader", "java") is None
    # existing languages still resolve
    assert lookup_sink("pickle.loads", "python").rule_id == "CG-DESERIALIZE"
    assert lookup_sink("db.Query", "go").rule_id == "CG-SQL-EXEC"

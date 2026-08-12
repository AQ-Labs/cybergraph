from __future__ import annotations

from cybergraph.analysis.csharp import analyze_csharp_file


def _rules(tmp_path, src):
    p = tmp_path / "A.cs"
    p.write_text(src, encoding="utf-8")
    _n, _e, findings = analyze_csharp_file(p, tmp_path)
    return [f.rule_id for f in findings]


def test_interpolated_sql_from_request_is_unsafe(tmp_path):
    src = ('class A { void H(Microsoft.AspNetCore.Http.HttpRequest request) {\n'
           '  var id = request.Query["id"];\n'
           '  var cmd = new SqlCommand($"SELECT * FROM u WHERE id = {id}", conn);\n'
           '  cmd.ExecuteReader(); } }\n')
    assert "CG-SQL-EXEC" in _rules(tmp_path, src)


def test_constructor_stream_reader_tainted_is_flagged(tmp_path):
    src = ('class A { void H(Microsoft.AspNetCore.Http.HttpRequest request) {\n'
           '  var p = request.Query["path"];\n'
           '  var r = new StreamReader(p); } }\n')
    assert "CG-PATH-TRAVERSAL" in _rules(tmp_path, src)


def test_process_start_shell_arg_is_flagged(tmp_path):
    src = ('class A { void H(string user) {\n'
           '  System.Diagnostics.Process.Start("cmd.exe", $"/c {user}"); } }\n')
    assert "CG-CMD-EXEC" in _rules(tmp_path, src)


def test_binaryformatter_deserialize_never_safe(tmp_path):
    src = ('class A { void H(System.IO.Stream s) {\n'
           '  var f = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();\n'
           '  var o = f.Deserialize(s); } }\n')
    # never SAFE: a deserialization sink always emits (confirmed or -UNVERIFIED),
    # never absent-because-safe.
    rules = _rules(tmp_path, src)
    assert "CG-DESERIALIZE" in rules or "CG-DESERIALIZE-UNVERIFIED" in rules


def test_csharp_script_eval_is_code_exec(tmp_path):
    src = ('class A { void H(string code) {\n'
           '  Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript.EvaluateAsync(code); } }\n')
    assert "CG-CODE-EXEC" in _rules(tmp_path, src)


def test_literal_query_is_safe_no_finding(tmp_path):
    src = ('class A { void H() {\n'
           '  var cmd = new SqlCommand("SELECT * FROM users", conn);\n'
           '  cmd.ExecuteReader(); } }\n')
    rules = _rules(tmp_path, src)
    assert "CG-SQL-EXEC" not in rules and "CG-SQL-EXEC-UNVERIFIED" not in rules


def test_zero_arg_execute_reader_is_skipped(tmp_path):
    # ExecuteReader() with no arg: query lives elsewhere; guarded, not a spurious finding.
    src = ('class A { void H(System.Data.SqlClient.SqlCommand cmd) {\n'
           '  cmd.ExecuteReader(); } }\n')
    assert "CG-SQL-EXEC" not in _rules(tmp_path, src)


def test_commented_out_sink_is_not_flagged(tmp_path):
    src = ('class A { void H(string id) {\n'
           '  // var c = new SqlCommand($"SELECT {id}", conn); c.ExecuteReader();\n'
           '} }\n')
    assert "CG-SQL-EXEC" not in _rules(tmp_path, src)

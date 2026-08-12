from __future__ import annotations

from cybergraph.analysis.java import analyze_java_file


def _rules(tmp_path, src):
    p = tmp_path / "A.java"
    p.write_text(src, encoding="utf-8")
    _n, _e, findings = analyze_java_file(p, tmp_path)
    return [f.rule_id for f in findings]


def test_prepared_statement_is_safe(tmp_path):
    src = ("class A { void h(java.sql.Connection c, String id) throws Exception {\n"
           "  var ps = c.prepareStatement(\"SELECT * FROM u WHERE id = ?\");\n"
           "  ps.setString(1, id); ps.executeQuery(); } }\n")
    rules = _rules(tmp_path, src)
    assert "CG-SQL-EXEC" not in rules  # executeQuery() has no string arg -> not a string-SQL sink


def test_concat_sqli_is_unsafe(tmp_path):
    src = ("class A { void h(java.sql.Statement st, "
           "javax.servlet.http.HttpServletRequest req) throws Exception {\n"
           "  String id = req.getParameter(\"id\");\n"
           "  st.executeQuery(\"SELECT * FROM u WHERE id = \" + id); } }\n")
    assert "CG-SQL-EXEC" in _rules(tmp_path, src)


def test_new_file_user_path_is_flagged(tmp_path):
    src = ("class A { void h(javax.servlet.http.HttpServletRequest req) throws Exception {\n"
           "  String p = req.getParameter(\"p\");\n"
           "  new java.io.File(p); } }\n")
    rules = _rules(tmp_path, src)
    assert "CG-PATH-TRAVERSAL" in rules  # new File(...) constructor sink, CALL_RE would miss it


def test_runtime_exec_chained_is_flagged(tmp_path):
    src = ("class A { void h(javax.servlet.http.HttpServletRequest req) throws Exception {\n"
           "  String c = req.getParameter(\"c\");\n"
           "  Runtime.getRuntime().exec(new String[]{\"sh\", \"-c\", c}); } }\n")
    assert "CG-CMD-EXEC" in _rules(tmp_path, src)  # chained .exec(...) after )


def test_readobject_never_safe(tmp_path):
    src = ("class A { Object h(javax.servlet.http.HttpServletRequest req) throws Exception {\n"
           "  var ois = new java.io.ObjectInputStream(req.getInputStream());\n"
           "  return ois.readObject(); } }\n")
    rules = _rules(tmp_path, src)
    assert "CG-DESERIALIZE" in rules or "CG-DESERIALIZE-UNVERIFIED" in rules

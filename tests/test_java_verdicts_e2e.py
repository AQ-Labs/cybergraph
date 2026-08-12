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
    # `prepareStatement` is itself a graded sql sink (Task 3 round 1): its
    # argument is an all-literal string (the `?` placeholder lives inside the
    # literal), so it must read the confirmed SAFE verdict -- no finding at
    # all, and specifically neither the confirmed nor the -UNVERIFIED rule id
    # (ruling out a silent UNKNOWN masquerading as "no finding"). The trailing
    # `executeQuery()` is separately zero-arg-guarded.
    assert "CG-SQL-EXEC" not in rules
    assert "CG-SQL-EXEC-UNVERIFIED" not in rules


def test_prepared_statement_concat_is_unsafe(tmp_path):
    src = ("class A { void h(java.sql.Connection c, "
           "javax.servlet.http.HttpServletRequest req) throws Exception {\n"
           "  String id = req.getParameter(\"id\");\n"
           "  var ps = c.prepareStatement(\"SELECT * FROM u WHERE id = \" + id);\n"
           "  ps.executeQuery(); } }\n")
    # A concatenated PreparedStatement is exactly as unsafe as a concatenated
    # Statement.executeQuery -- this is the case that previously produced ZERO
    # findings because `prepareStatement` was not a registered sink at all.
    assert "CG-SQL-EXEC" in _rules(tmp_path, src)


def test_commented_out_new_file_sink_is_not_flagged(tmp_path):
    src = ("class A { void h(javax.servlet.http.HttpServletRequest req) throws Exception {\n"
           "  String p = req.getParameter(\"p\");\n"
           "  // new java.io.File(p);\n"
           "} }\n")
    rules = _rules(tmp_path, src)
    assert "CG-PATH-TRAVERSAL" not in rules
    assert "CG-PATH-TRAVERSAL-UNVERIFIED" not in rules


def test_block_commented_out_sqli_is_not_flagged(tmp_path):
    src = ("class A { void h(java.sql.Statement st, "
           "javax.servlet.http.HttpServletRequest req) throws Exception {\n"
           "  String id = req.getParameter(\"id\");\n"
           "  /* st.executeQuery(\"SELECT * FROM u WHERE id = \" + id); */\n"
           "} }\n")
    rules = _rules(tmp_path, src)
    assert "CG-SQL-EXEC" not in rules
    assert "CG-SQL-EXEC-UNVERIFIED" not in rules


def test_comment_only_parens_read_as_empty_not_unverified(tmp_path):
    # A sink call whose parens hold only a comment (`/* n/a */`) must be read
    # as the zero-arg guard's genuinely-empty case, not as an opaque,
    # unreadable argument that would otherwise surface as -UNVERIFIED noise.
    src = ("class A { void h(java.sql.Statement st) throws Exception {\n"
           "  st.executeQuery(/* n/a */); } }\n")
    rules = _rules(tmp_path, src)
    assert "CG-SQL-EXEC" not in rules
    assert "CG-SQL-EXEC-UNVERIFIED" not in rules


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

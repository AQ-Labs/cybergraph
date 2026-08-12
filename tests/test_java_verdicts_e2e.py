from __future__ import annotations

import subprocess

from cybergraph.analysis.java import analyze_java_file
from cybergraph.security.capability import CAPABILITIES, FAIL, NOT_SUPPORTED
from cybergraph.security.check import check_change
from cybergraph.security.verdict import STATE_REVIEW


def _rules(tmp_path, src):
    p = tmp_path / "A.java"
    p.write_text(src, encoding="utf-8")
    _n, _e, findings = analyze_java_file(p, tmp_path)
    return [f.rule_id for f in findings]


def _findings(tmp_path, src):
    p = tmp_path / "A.java"
    p.write_text(src, encoding="utf-8")
    _n, _e, findings = analyze_java_file(p, tmp_path)
    return findings


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


def test_opaque_call_receiver_chain_is_not_reported_clean(tmp_path):
    # Whole-branch review C1: an opaque bare-call receiver seeding an append
    # chain (`currentQuery().append(" LIMIT 1").toString()`) must not read a
    # confirmed-SAFE verdict end-to-end. It now surfaces as UNVERIFIED (UNKNOWN)
    # rather than being silently dropped as clean.
    src = ("class A { void h(java.sql.Statement st) throws Exception {\n"
           "  st.executeQuery(currentQuery().append(\" LIMIT 1\").toString());\n"
           "} }\n")
    rules = _rules(tmp_path, src)
    assert "CG-SQL-EXEC" not in rules  # not falsely confirmed
    assert "CG-SQL-EXEC-UNVERIFIED" in rules  # surfaced as UNKNOWN, not absent


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


def test_text_block_with_odd_quotes_then_commented_sink_is_not_flagged(tmp_path):
    # Round 2 regression: a text block whose body contains an ODD number of
    # unescaped `"` desyncs a naive single-quote-parity scanner, so a later
    # `//` stops being recognised as a comment opener at all and a genuinely
    # commented-out sink gets graded as live.
    src = ('class A { void h(javax.servlet.http.HttpServletRequest req) throws Exception {\n'
           '  String id = req.getParameter("id");\n'
           '  String block = """\n'
           '    she said "hi\n'
           '    """;\n'
           '  // new java.io.File(id);\n'
           '} }\n')
    rules = _rules(tmp_path, src)
    assert "CG-PATH-TRAVERSAL" not in rules
    assert "CG-PATH-TRAVERSAL-UNVERIFIED" not in rules


def test_text_block_with_odd_quotes_then_real_sink_is_flagged(tmp_path):
    # Same text block as above, but the sink on the next line is live (not
    # commented out) -- proves the text-block fix does not over-correct into
    # dropping a real sink after one.
    src = ('class A { void h(javax.servlet.http.HttpServletRequest req) throws Exception {\n'
           '  String id = req.getParameter("id");\n'
           '  String block = """\n'
           '    she said "hi\n'
           '    """;\n'
           '  new java.io.File(id);\n'
           '} }\n')
    assert "CG-PATH-TRAVERSAL" in _rules(tmp_path, src)


def test_slash_slash_inside_string_literal_still_flags_concat(tmp_path):
    # A `//` inside a real string literal must not be mistaken for a comment
    # opener -- it must not blank the `+ id` that follows it on the same line.
    src = ('class A { void h(java.sql.Statement st, '
           'javax.servlet.http.HttpServletRequest req) throws Exception {\n'
           '  String id = req.getParameter("id");\n'
           '  st.executeQuery("... \'http://host/\' ..." + id); } }\n')
    assert "CG-SQL-EXEC" in _rules(tmp_path, src)


def test_block_comment_token_inside_string_literal_still_flags_concat(tmp_path):
    # A `/*` inside a real string literal must not be mistaken for a comment
    # opener -- it must not swallow the `+ id` that follows it.
    src = ('class A { void h(java.sql.Statement st, '
           'javax.servlet.http.HttpServletRequest req) throws Exception {\n'
           '  String id = req.getParameter("id");\n'
           '  st.executeQuery("a /* b" + id); } }\n')
    assert "CG-SQL-EXEC" in _rules(tmp_path, src)


def test_trailing_line_comment_after_real_sink_still_flags(tmp_path):
    # A genuine trailing `// note` must be blanked (it is a real comment), but
    # the live sink call earlier on the same line must still be graded.
    src = ('class A { void h(java.sql.Statement st, '
           'javax.servlet.http.HttpServletRequest req) throws Exception {\n'
           '  String id = req.getParameter("id");\n'
           '  st.executeQuery("q" + id); // note\n'
           '} }\n')
    assert "CG-SQL-EXEC" in _rules(tmp_path, src)


def test_block_comment_spanning_lines_preserves_sink_line_number(tmp_path):
    # A multi-line `/* ... */` block comment must not shift line numbers: a
    # real sink several lines later must report ITS OWN line, not one offset
    # by however many lines the comment blanking touched.
    src = (
        'class A { void h(java.sql.Statement st, '
        'javax.servlet.http.HttpServletRequest req) throws Exception {\n'  # line 1
        '  String id = req.getParameter("id");\n'                          # line 2
        '  /* start of a\n'                                                # line 3
        '     multi-line\n'                                                # line 4
        '     comment */\n'                                                # line 5
        '  int x = 1;\n'                                                   # line 6
        '  int y = 2;\n'                                                   # line 7
        '  int z = 3;\n'                                                   # line 8
        '  st.executeQuery("SELECT " + id);\n'                             # line 9
        '} }\n'                                                           # line 10
    )
    findings = _findings(tmp_path, src)
    sql = [f for f in findings if f.rule_id == "CG-SQL-EXEC"]
    assert len(sql) == 1
    assert sql[0].line_start == 9


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


def _cap(cid):
    return next(c for c in CAPABILITIES if c.id == cid)


def test_four_capabilities_cover_java():
    for cid in ("sql_construction", "command_execution", "path_access", "deserialization"):
        assert "*.java" in _cap(cid).covers, cid
    assert "*.java" not in _cap("code_execution").covers


def _repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    for a in (["init", "-q"], ["config", "user.email", "t@e.com"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *a], check=True)
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "base"], check=True)
    return repo


def test_java_sqli_reviews(tmp_path):
    repo = _repo(tmp_path)
    (repo / "A.java").write_text(
        "class A { void h(java.sql.Statement st, javax.servlet.http.HttpServletRequest req) "
        "throws Exception {\n"
        "  String id = req.getParameter(\"id\");\n"
        "  st.executeQuery(\"SELECT * FROM u WHERE id = \" + id); } }\n", encoding="utf-8")
    v = check_change(repo, mode="worktree")
    assert v.state == STATE_REVIEW
    assert any(c.capability_id == "sql_construction" and c.status == FAIL for c in v.checks)


def test_java_still_not_supported_overall(tmp_path):
    repo = _repo(tmp_path)
    (repo / "A.java").write_text("class A { int x = 1; }\n", encoding="utf-8")
    v = check_change(repo, mode="worktree")
    assert any(c.capability_id == "source_analysis_support" and c.status == NOT_SUPPORTED
               for c in v.checks)

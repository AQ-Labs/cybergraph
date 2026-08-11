from __future__ import annotations

import subprocess

from cybergraph.analysis.go import analyze_go_file
from cybergraph.security.capability import CAPABILITIES, FAIL, NOT_SUPPORTED
from cybergraph.security.check import check_change
from cybergraph.security.verdict import STATE_REVIEW


def _rules(tmp_path, src):
    p = tmp_path / "main.go"
    p.write_text(src, encoding="utf-8")
    _n, _e, findings = analyze_go_file(p, tmp_path)
    return [f.rule_id for f in findings]


def test_parameterized_query_is_safe(tmp_path):
    src = 'func h(db *sql.DB, id string) { db.Query("SELECT * FROM u WHERE id = $1", id) }\n'
    rules = _rules(tmp_path, src)
    assert "CG-SQL-EXEC" not in rules and "CG-SQL-EXEC-UNVERIFIED" not in rules
    assert "CG-GO-SINK-CALL" not in rules  # a registered sink no longer emits inventory


def test_sprintf_tainted_query_is_unsafe(tmp_path):
    src = (
        'func h(db *sql.DB, r *http.Request) {\n'
        '  id := r.URL.Query().Get("id")\n'
        '  db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %s", id))\n}\n'
    )
    assert "CG-SQL-EXEC" in _rules(tmp_path, src)


def test_sprintf_unresolved_query_is_unverified(tmp_path):
    src = 'func h(db *sql.DB, id string) { db.Query(fmt.Sprintf("SELECT %s", id)) }\n'
    rules = _rules(tmp_path, src)
    assert "CG-SQL-EXEC-UNVERIFIED" in rules and "CG-SQL-EXEC" not in rules


def test_url_query_reader_is_not_a_sql_sink(tmp_path):
    # `r.URL.Query()` (net/http's zero-arg query-param reader) shares its bare
    # final segment with the SQL `Query` sink but takes no argument -- it must
    # not be treated as reaching a sink at all, with no db call anywhere.
    src = (
        'func listUsers(w http.ResponseWriter, r *http.Request) {\n'
        '  name := r.URL.Query().Get("name")\n'
        '}\n'
    )
    rules = _rules(tmp_path, src)
    assert "CG-SQL-EXEC" not in rules
    assert "CG-SQL-EXEC-UNVERIFIED" not in rules
    assert "CG-GO-SINK-CALL" not in rules


def test_url_query_reader_and_real_sink_only_flags_the_sink(tmp_path):
    # The same zero-arg reader alongside a genuine, tainted `db.Query(...)`
    # call: only the real injection is flagged, and it is flagged exactly
    # once (the reader itself must not add a second, spurious finding).
    src = (
        'func listUsers(w http.ResponseWriter, r *http.Request) {\n'
        '  name := r.URL.Query().Get("name")\n'
        '  db.Query("select * from users where name = \'" + name + "\'")\n'
        '}\n'
    )
    rules = _rules(tmp_path, src)
    assert rules.count("CG-SQL-EXEC") == 1
    assert "CG-SQL-EXEC-UNVERIFIED" not in rules
    assert "CG-GO-SINK-CALL" not in rules


def _cap(cid):
    return next(c for c in CAPABILITIES if c.id == cid)


def test_three_capabilities_cover_go():
    for cid in ("sql_construction", "command_execution", "path_access"):
        assert "*.go" in _cap(cid).covers, cid
    assert "*.go" not in _cap("code_execution").covers   # no Go code sink
    assert "*.go" not in _cap("deserialization").covers


def _repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    for a in (["init", "-q"], ["config", "user.email", "t@e.com"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *a], check=True)
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "base"], check=True)
    return repo


def test_go_sqli_reviews_under_sql_construction(tmp_path):
    repo = _repo(tmp_path)
    (repo / "h.go").write_text(
        'package m\nimport ("database/sql"; "fmt"; "net/http")\n'
        'func h(db *sql.DB, r *http.Request) {\n'
        '  id := r.URL.Query().Get("id")\n'
        '  db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %s", id))\n}\n',
        encoding="utf-8",
    )
    verdict = check_change(repo, mode="worktree")
    assert verdict.state == STATE_REVIEW
    assert any(c.capability_id == "sql_construction" and c.status == FAIL
               for c in verdict.checks)


def test_go_shell_command_injection_reviews(tmp_path):
    repo = _repo(tmp_path)
    (repo / "h.go").write_text(
        'package m\nimport ("net/http"; "os/exec")\n'
        'func h(w http.ResponseWriter, r *http.Request) {\n'
        '  userCmd := r.URL.Query().Get("cmd")\n'
        '  exec.Command("sh", "-c", userCmd)\n}\n',
        encoding="utf-8",
    )
    _n, _e, findings = analyze_go_file(repo / "h.go", repo)
    assert any(f.rule_id == "CG-CMD-EXEC" for f in findings)

    verdict = check_change(repo, mode="worktree")
    assert verdict.state == STATE_REVIEW
    assert any(c.capability_id == "command_execution" and c.status == FAIL
               for c in verdict.checks)


def test_go_still_not_supported_overall(tmp_path):
    repo = _repo(tmp_path)
    (repo / "h.go").write_text("package m\nvar X = 1\n", encoding="utf-8")
    verdict = check_change(repo, mode="worktree")
    assert any(c.capability_id == "source_analysis_support" and c.status == NOT_SUPPORTED
               for c in verdict.checks)

from __future__ import annotations

from cybergraph.analysis.go import analyze_go_file


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

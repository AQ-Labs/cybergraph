from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.javascript import analyze_javascript_file


def _rules(tmp_path: Path, name: str, src: str):
    p = tmp_path / name
    p.write_text(src, encoding="utf-8")
    _n, _e, findings = analyze_javascript_file(p, tmp_path)
    return [f.rule_id for f in findings]


def test_parameterized_query_is_safe(tmp_path):
    src = "function h(db,id){ return db.query('SELECT * FROM u WHERE id = ?', [id]); }\n"
    rules = _rules(tmp_path, "a.js", src)
    assert "CG-SQL-EXEC" not in rules
    assert "CG-SQL-EXEC-UNVERIFIED" not in rules
    assert "CG-JS-SINK-CALL" not in rules  # a registered sink no longer emits inventory


def test_tainted_template_query_is_unsafe(tmp_path):
    src = (
        "function h(db, req){ const id = req.query.id;\n"
        "  return db.query(`SELECT * FROM u WHERE id = ${id}`); }\n"
    )
    assert "CG-SQL-EXEC" in _rules(tmp_path, "a.js", src)


def test_unresolved_variable_query_is_unverified(tmp_path):
    src = "function h(db, id){ return db.query(`SELECT * FROM u WHERE id = ${id}`); }\n"
    rules = _rules(tmp_path, "a.js", src)
    assert "CG-SQL-EXEC-UNVERIFIED" in rules
    assert "CG-SQL-EXEC" not in rules  # not a confident unsafe on an unproven variable


def test_non_registry_sink_stays_inventory(tmp_path):
    # res.render is in the legacy SINK_CALLS but not the verdict registry -> inventory-grade
    rules = _rules(tmp_path, "a.js", "function h(res, x){ return res.render(x); }\n")
    assert "CG-JS-SINK-CALL" in rules
    assert "CG-SQL-EXEC" not in rules

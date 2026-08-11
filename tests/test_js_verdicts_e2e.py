from __future__ import annotations

import subprocess
from pathlib import Path

from cybergraph.analysis.javascript import analyze_javascript_file
from cybergraph.security.capability import CAPABILITIES, FAIL, NOT_SUPPORTED
from cybergraph.security.check import check_change
from cybergraph.security.verdict import STATE_REVIEW


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


def test_tainted_concat_operand_shapes_are_unsafe(tmp_path):
    # each of these begins the '+' operand with '(', '[', or a ternary rather
    # than a leading identifier character -- all must still confirm unsafe
    idioms = [
        "db.query('SELECT * FROM u WHERE id = ' + (id))",
        "db.query('SELECT * FROM u WHERE id = ' + (id || 1))",
        "db.query('SELECT * FROM u WHERE id = ' + [id])",
        "db.query('SELECT ' + (id ? id : 1))",
    ]
    for i, call in enumerate(idioms):
        src = f"function h(db, req){{ const id = req.query.id;\n  return {call}; }}\n"
        rules = _rules(tmp_path, f"c{i}.js", src)
        assert "CG-SQL-EXEC" in rules, call


def test_non_registry_sink_stays_inventory(tmp_path):
    # res.render is in the legacy SINK_CALLS but not the verdict registry -> inventory-grade
    rules = _rules(tmp_path, "a.js", "function h(res, x){ return res.render(x); }\n")
    assert "CG-JS-SINK-CALL" in rules
    assert "CG-SQL-EXEC" not in rules


def _cap(cid):
    return next(c for c in CAPABILITIES if c.id == cid)


def test_four_capabilities_cover_web():
    for cid in ("sql_construction", "command_execution", "code_execution", "path_access"):
        assert any(g in _cap(cid).covers for g in ("*.ts", "*.js")), cid
    assert "*.ts" not in _cap("deserialization").covers  # unchanged


def _repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    for a in (["init", "-q"], ["config", "user.email", "t@e.com"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *a], check=True)
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "base"], check=True)
    return repo


def test_js_sqli_reviews_under_sql_construction(tmp_path):
    repo = _repo(tmp_path)
    (repo / "h.ts").write_text(
        "export function h(db, req){ const id = req.query.id;\n"
        "  return db.query(`SELECT * FROM u WHERE id = ${id}`); }\n",
        encoding="utf-8",
    )
    verdict = check_change(repo, mode="worktree")
    assert verdict.state == STATE_REVIEW
    assert any(c.capability_id == "sql_construction" and c.status == FAIL
               for c in verdict.checks)


def test_js_still_not_supported_overall(tmp_path):
    # source_analysis_support stays NOT_SUPPORTED for JS (the tool doesn't overclaim)
    repo = _repo(tmp_path)
    (repo / "h.ts").write_text("export const x = 1;\n", encoding="utf-8")
    verdict = check_change(repo, mode="worktree")
    assert any(c.capability_id == "source_analysis_support" and c.status == NOT_SUPPORTED
               for c in verdict.checks)

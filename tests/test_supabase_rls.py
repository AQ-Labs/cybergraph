from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.supabase_rls import analyze_supabase_rls_file


def _write(tmp_path: Path, text: str) -> Path:
    d = tmp_path / "supabase" / "migrations"
    d.mkdir(parents=True)
    p = d / "0001_init.sql"
    p.write_text(text, encoding="utf-8")
    return p


def test_disable_rls_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, "ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY;\n")
    _n, _e, findings = analyze_supabase_rls_file(p, tmp_path)
    assert [f.rule_id for f in findings] == ["CG-SUPABASE-RLS-DISABLED"]
    assert findings[0].cwe == "CWE-1230"


def test_policy_using_true_is_flagged(tmp_path: Path) -> None:
    text = (
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\n"
        'CREATE POLICY p ON t FOR SELECT USING (true);\n'
    )
    p = _write(tmp_path, text)
    _n, _e, findings = analyze_supabase_rls_file(p, tmp_path)
    assert [f.rule_id for f in findings] == ["CG-SUPABASE-RLS-DISABLED"]


def test_create_without_enable_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, "CREATE TABLE public.secrets (id int, val text);\n")
    _n, _e, findings = analyze_supabase_rls_file(p, tmp_path)
    assert [f.rule_id for f in findings] == ["CG-SUPABASE-RLS-DISABLED"]


def test_create_then_enable_is_clean(tmp_path: Path) -> None:
    text = (
        "CREATE TABLE public.secrets (id int, val text);\n"
        "ALTER TABLE public.secrets ENABLE ROW LEVEL SECURITY;\n"
    )
    p = _write(tmp_path, text)
    _n, _e, findings = analyze_supabase_rls_file(p, tmp_path)
    assert findings == []


def test_file_node_always_present(tmp_path: Path) -> None:
    p = _write(tmp_path, "-- just a comment\n")
    nodes, _e, findings = analyze_supabase_rls_file(p, tmp_path)
    assert any(n.kind == "File" for n in nodes)
    assert findings == []

"""Tests for Strix scope generation and validated-finding prioritization."""

from __future__ import annotations

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph import GraphStore
from cybergraph.security import load_strix_findings
from cybergraph.security.investigate import collect_top_risks
from cybergraph.security.strix_plan import build_strix_instructions, write_strix_instructions

FIXTURE = Path(__file__).parent / "fixtures" / "strix_run"


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.get('/search')\n"
        "def search(request):\n"
        "    q = request.query['q']\n"
        "    return db.execute('select ' + q)\n",
        encoding="utf-8",
    )
    build_graph(repo)
    return repo


def test_strix_plan_lists_reachable_attack_paths(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    brief = build_strix_instructions(repo)

    assert "CyberGraph-guided penetration test scope" in brief
    assert "Priority attack paths" in brief
    assert "search" in brief
    assert "Only report vulnerabilities you validate" in brief


def test_write_strix_instructions_creates_file(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    output = write_strix_instructions(repo, repo / ".cybergraph" / "strix-plan.md")
    assert output.exists()
    assert output.read_text(encoding="utf-8").strip()


def test_validated_findings_rank_at_top_of_investigation(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    store = GraphStore.open_for_repo(repo)
    store.add_findings(load_strix_findings(FIXTURE))
    store.close()

    risks = collect_top_risks(repo, limit=10)

    assert risks
    assert risks[0].category == "validated"
    assert "PoC-validated by Strix" in risks[0].detail


def test_imported_strix_findings_survive_a_rebuild(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    store = GraphStore.open_for_repo(repo)
    store.add_findings(load_strix_findings(FIXTURE))
    store.close()

    # A later rebuild (as top-risks/investigate trigger) must not drop imported
    # external findings, only regenerate analyzer-produced ones.
    build_graph(repo)

    store = GraphStore.open_for_repo(repo)
    strix_count = store.conn.execute(
        "SELECT COUNT(*) FROM findings WHERE tool = 'strix'"
    ).fetchone()[0]
    store.close()
    assert strix_count == 1

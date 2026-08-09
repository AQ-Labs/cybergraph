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


SUPPRESSED_HEADER = "from fastapi import FastAPI\napp = FastAPI()\n"
SUPPRESSED_ROUTE = (
    '\n@app.get("/r")\n'
    "def run(cmd: str):\n"
    '    subprocess.run("echo " + cmd, shell=True)\n'
)


def test_strix_scope_applies_suppressions(tmp_path: Path) -> None:
    """Pins ``strix_plan.py``'s ranked ``find_attack_paths`` call site.

    The Strix scope is a prioritized brief; a wholly-suppressed path must not
    appear in it. Flipping the call to ``apply_suppressions=False`` would ship
    accepted fixture noise to the pentester as a priority target.
    """
    repo = tmp_path / "repo"
    (repo / "fixtures").mkdir(parents=True)
    (repo / "fixtures" / "app.py").write_text(
        SUPPRESSED_HEADER + SUPPRESSED_ROUTE, encoding="utf-8"
    )
    (repo / ".cybergraph.toml").write_text(
        '[suppressions]\npaths = ["fixtures/*"]\n', encoding="utf-8"
    )
    build_graph(repo)

    brief = build_strix_instructions(repo)

    assert "fixtures/app.py" not in brief, brief
    assert "No entrypoint-to-sink paths were found statically" in brief, brief


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

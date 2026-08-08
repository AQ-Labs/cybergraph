from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph import GraphStore
from cybergraph.graph_export import build_graph_data
from cybergraph.security.attack_paths import find_attack_paths
from cybergraph.security.ontology import EDGE_REACHES_SINK

ROUTE = '''
@app.get("/r{n}")
def run{n}(cmd: str):
    subprocess.run("echo " + cmd, shell=True)
'''
HEADER = "from fastapi import FastAPI\napp = FastAPI()\n"
CONFIG = '[suppressions]\npaths = ["fixtures/*"]\n'


def test_suppressed_paths_are_excluded(tmp_path: Path):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "app.py").write_text(HEADER + ROUTE.format(n=0), encoding="utf-8")
    (tmp_path / ".cybergraph.toml").write_text(CONFIG, encoding="utf-8")
    build_graph(tmp_path)

    assert find_attack_paths(tmp_path) == []
    assert find_attack_paths(tmp_path, apply_suppressions=False)


def test_suppressed_results_do_not_consume_the_limit(tmp_path: Path):
    """25 suppressed fixtures must not hide the 3 real results behind them."""
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "app.py").write_text(
        HEADER + "".join(ROUTE.format(n=i) for i in range(25)), encoding="utf-8"
    )
    (tmp_path / "real.py").write_text(
        HEADER + "".join(ROUTE.format(n=i) for i in range(100, 103)), encoding="utf-8"
    )
    (tmp_path / ".cybergraph.toml").write_text(CONFIG, encoding="utf-8")
    build_graph(tmp_path)

    paths = find_attack_paths(tmp_path, limit=20)
    assert len(paths) == 3, f"expected the 3 real paths, got {len(paths)}"
    assert all("real.py" in path.nodes[0] for path in paths)


def test_suppression_hides_the_finding_but_keeps_the_code_path(tmp_path: Path):
    """README: suppressions hide findings, the graph still keeps REACHES_SINK.

    A suppressed path must be absent from a ranked/actionable surface and still
    present on an exploration surface, with the underlying edge intact.
    """
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "app.py").write_text(HEADER + ROUTE.format(n=0), encoding="utf-8")
    (tmp_path / ".cybergraph.toml").write_text(CONFIG, encoding="utf-8")
    build_graph(tmp_path)

    # Ranked surface: the suppressed path is gone.
    assert find_attack_paths(tmp_path) == []

    # Exploration surface: the graph export still carries it.
    exported = build_graph_data(tmp_path)["attack_paths"]
    assert exported, "graph export must keep suppressed paths for reviewers"
    assert any("fixtures/app.py" in node for path in exported for node in path["nodes"])

    # And the underlying edge is untouched, exactly as the README promises.
    store = GraphStore.open_for_repo(tmp_path)
    try:
        rows = store.conn.execute(
            "SELECT source FROM edges WHERE kind = ?", (EDGE_REACHES_SINK,)
        ).fetchall()
    finally:
        store.close()
    assert any("fixtures/app.py" in row["source"] for row in rows)

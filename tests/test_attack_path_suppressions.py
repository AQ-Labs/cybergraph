from pathlib import Path

import pytest

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


def _suppressed_repo(tmp_path: Path) -> Path:
    """One attack path, entirely inside a suppressed directory."""
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "app.py").write_text(HEADER + ROUTE.format(n=0), encoding="utf-8")
    (tmp_path / ".cybergraph.toml").write_text(CONFIG, encoding="utf-8")
    build_graph(tmp_path)
    # Precondition: the ranked default really does hide it, so the assertions
    # below are pinning the exploration surfaces and not a no-op config.
    assert find_attack_paths(tmp_path) == []
    return tmp_path


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
    data = build_graph_data(tmp_path)
    exported = data["attack_paths"]
    assert exported, "graph export must keep suppressed paths for reviewers"
    assert any("fixtures/app.py" in node for path in exported for node in path["nodes"])

    # The document ships two suppression policies, so it must say so.
    assert data["top_risks"] == []
    assert data["suppression"] == {
        "paths": ["fixtures/*"],
        "attack_paths_suppressed": False,
        "top_risks_suppressed": True,
    }

    # And the underlying edge is untouched, exactly as the README promises.
    store = GraphStore.open_for_repo(tmp_path)
    try:
        rows = store.conn.execute(
            "SELECT source FROM edges WHERE kind = ?", (EDGE_REACHES_SINK,)
        ).fetchall()
    finally:
        store.close()
    assert any("fixtures/app.py" in row["source"] for row in rows)


# --- Each exploration/evidence call site is pinned below, so deleting its
# --- ``apply_suppressions=False`` fails a test rather than a code comment.


def test_html_report_keeps_suppressed_paths(tmp_path: Path):
    """Pins ``visualize.py``'s ``apply_suppressions=False``."""
    from cybergraph.visualize import generate_html_report

    repo = _suppressed_repo(tmp_path)
    html = generate_html_report(repo, tmp_path / "report.html").read_text(encoding="utf-8")

    # The attack-path section is rendered from visualize's own call, not from
    # the embedded graph JSON, so this cannot pass via graph_export.
    assert "No entrypoint-to-sink paths found yet." not in html
    cards = [block for block in html.split("<div class='path'>")[1:]]
    assert any("fixtures/app.py" in card.split("</div>")[0] for card in cards), (
        "the HTML report must still show the suppressed code path"
    )


def test_mcp_explain_tool_keeps_suppressed_paths(tmp_path: Path):
    """Pins ``mcp_server.py``'s ``apply_suppressions=False``."""
    pytest.importorskip("fastmcp")
    from cybergraph import mcp_server

    repo = _suppressed_repo(tmp_path)
    answer = mcp_server.explain_attack_path_tool(str(repo))["answer"]

    assert "fixtures/app.py" in answer, "explain_attack_path_tool exists to trace real paths"
    assert "subprocess.run" in answer


def test_grounded_records_can_cite_a_suppressed_path(tmp_path: Path):
    """Pins ``rag/grounded.py``'s ``apply_suppressions=False``."""
    from cybergraph.rag.grounded import collect_records

    repo = _suppressed_repo(tmp_path)
    paths = [r for r in collect_records(repo) if r.kind == "attack_path"]

    assert paths, "grounded evidence must be able to cite a suppressed path"
    assert any("fixtures/app.py" in node for r in paths for node in r.citation.path)


# --- ... and showing them must not cost the real paths their slot -------------


def _starved_repo(tmp_path: Path) -> Path:
    """80 suppressed routes ahead of 3 real ones.

    ``ORDER BY target`` puts every ``fixtures/`` entrypoint before ``real.py``,
    and 80 outnumbers each exploration surface's cap (25 for the HTML report,
    50 for the graph export and grounded RAG, 20 for the MCP tool), so on the
    old code the real paths fell off the end of every one of them.
    """
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "app.py").write_text(
        HEADER + "".join(ROUTE.format(n=i) for i in range(80)), encoding="utf-8"
    )
    (tmp_path / "real.py").write_text(
        HEADER + "".join(ROUTE.format(n=i) for i in range(100, 103)), encoding="utf-8"
    )
    (tmp_path / ".cybergraph.toml").write_text(CONFIG, encoding="utf-8")
    build_graph(tmp_path)
    # Precondition: the ranked surface finds exactly the 3 real ones, so any
    # exploration surface that reports none is starving them, not missing them.
    ranked = find_attack_paths(tmp_path, limit=20)
    assert len(ranked) == 3 and all("real.py" in path.nodes[0] for path in ranked)
    return tmp_path


def test_suppressed_paths_do_not_consume_an_exploration_limit(tmp_path: Path):
    """Measured before the fix: 25 cards, 0 real. Both halves are asserted.

    The suppressed paths must still be *there* -- that is what
    ``apply_suppressions=False`` and the README promise -- and the real ones
    must be there too, at an unchanged total.
    """
    repo = _starved_repo(tmp_path)
    paths = find_attack_paths(repo, limit=25, apply_suppressions=False)

    real = [path for path in paths if any("real.py" in node for node in path.nodes)]
    suppressed = [path for path in paths if path not in real]
    assert len(real) == 3, f"the real paths were starved: {len(real)}/{len(paths)}"
    assert suppressed, "suppressed paths must still be visible on an exploration surface"
    assert len(paths) <= 25, "the caller's cap on the total still holds"


def test_the_html_report_shows_the_real_path_behind_the_suppressed_ones(tmp_path: Path):
    from cybergraph.visualize import generate_html_report

    repo = _starved_repo(tmp_path)
    html = generate_html_report(repo, tmp_path / "report.html").read_text(encoding="utf-8")
    cards = [block.split("</div>")[0] for block in html.split("<div class='path'>")[1:]]

    assert cards
    assert any("real.py" in card for card in cards), "measured before the fix: 25 cards, 0 real"
    assert any("fixtures/app.py" in card for card in cards)


def test_the_graph_export_keeps_the_real_paths(tmp_path: Path):
    repo = _starved_repo(tmp_path)
    exported = build_graph_data(repo)["attack_paths"]

    assert any(
        "real.py" in node for path in exported for node in path["nodes"]
    ), "measured before the fix: 50 exported paths, 0 real"
    assert any("fixtures/app.py" in node for path in exported for node in path["nodes"])


def test_grounded_evidence_keeps_the_real_paths(tmp_path: Path):
    """The evidence an LLM is grounded on: 50 records, 0 real, before the fix."""
    from cybergraph.rag.grounded import collect_records

    repo = _starved_repo(tmp_path)
    records = [r for r in collect_records(repo) if r.kind == "attack_path"]

    assert any("real.py" in node for r in records for node in r.citation.path)
    assert any("fixtures/app.py" in node for r in records for node in r.citation.path)


def test_the_mcp_explain_tool_keeps_the_real_paths(tmp_path: Path):
    pytest.importorskip("fastmcp")
    from cybergraph import mcp_server

    repo = _starved_repo(tmp_path)
    answer = mcp_server.explain_attack_path_tool(str(repo))["answer"]

    assert "real.py" in answer, "the tool exists to trace real paths"
    assert "fixtures/app.py" in answer


def test_a_path_crossing_out_of_suppressed_code_is_never_hidden(tmp_path: Path):
    """``path_is_suppressed`` suppresses only when *every* file is suppressed.

    The exploration surfaces now ask this predicate too, which widens what
    relaxing it to ``any`` would cost: a route entering through suppressed
    fixture code and reaching a live sink in ``real.py`` would be reclassified
    as accepted noise on every surface at once. It is a real, reachable path
    and must stay on the ranked one.
    """
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "app.py").write_text(
        "from fastapi import FastAPI\nfrom real import run_it\napp = FastAPI()\n"
        '\n@app.get("/x")\ndef cross(cmd: str):\n    return run_it(cmd)\n',
        encoding="utf-8",
    )
    (tmp_path / "real.py").write_text(
        'import subprocess\n\ndef run_it(cmd):\n    subprocess.run("echo " + cmd, shell=True)\n',
        encoding="utf-8",
    )
    (tmp_path / ".cybergraph.toml").write_text(CONFIG, encoding="utf-8")
    build_graph(tmp_path)

    ranked = find_attack_paths(tmp_path, limit=20)

    assert [path.nodes for path in ranked] == [
        ("fixtures/app.py::cross", "real.py::run_it", "subprocess.run")
    ], ranked

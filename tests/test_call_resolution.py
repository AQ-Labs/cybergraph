"""Tests for cross-file call resolution."""

from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.resolve import EDGE_CALLS_RESOLVED, resolve_calls
from cybergraph.build import build_graph
from cybergraph.graph import Edge, GraphStore, Node


def test_unique_name_resolves_high_confidence() -> None:
    nodes = [
        Node("Function", "routes.py::handler", "handler", "routes.py", 1, 3),
        Node("Function", "service.py::run_query", "run_query", "service.py", 1, 3),
    ]
    edges = [Edge("CALLS", "routes.py::handler", "service.run_query", "routes.py", 2)]

    resolved = resolve_calls(nodes, edges)

    assert len(resolved) == 1
    edge = resolved[0]
    assert edge.kind == EDGE_CALLS_RESOLVED
    assert edge.source == "routes.py::handler"
    assert edge.target == "service.py::run_query"
    assert edge.properties["confidence"] == "high"


def test_ambiguous_name_resolves_low_confidence_to_all() -> None:
    nodes = [
        Node("Function", "a.py::caller", "caller", "a.py", 1, 2),
        Node("Function", "b.py::process", "process", "b.py", 1, 2),
        Node("Function", "c.py::process", "process", "c.py", 1, 2),
    ]
    edges = [Edge("CALLS", "a.py::caller", "process", "a.py", 2)]

    resolved = resolve_calls(nodes, edges)

    assert len(resolved) == 2
    assert all(edge.properties["confidence"] == "low" for edge in resolved)
    assert all(edge.properties["ambiguous"] for edge in resolved)


def test_same_file_disambiguates_to_medium() -> None:
    nodes = [
        Node("Function", "a.py::caller", "caller", "a.py", 1, 2),
        Node("Function", "a.py::process", "process", "a.py", 4, 5),
        Node("Function", "b.py::process", "process", "b.py", 1, 2),
    ]
    edges = [Edge("CALLS", "a.py::caller", "process", "a.py", 2)]

    resolved = resolve_calls(nodes, edges)

    assert len(resolved) == 1
    assert resolved[0].target == "a.py::process"
    assert resolved[0].properties["confidence"] == "medium"


def test_unresolvable_sink_name_is_not_resolved() -> None:
    nodes = [Node("Function", "a.py::caller", "caller", "a.py", 1, 2)]
    edges = [Edge("CALLS", "a.py::caller", "db.execute", "a.py", 2)]
    # No function named "execute" exists, so nothing resolves.
    assert resolve_calls(nodes, edges) == []


def test_build_emits_resolved_edges_across_files(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "@app.get('/users')\n"
        "def list_users(request):\n"
        "    return run_query(request.query['q'])\n",
        encoding="utf-8",
    )
    (repo / "service.py").write_text(
        "def run_query(q):\n"
        "    return db.execute('select ' + q)\n",
        encoding="utf-8",
    )
    build_graph(repo)

    store = GraphStore.open_for_repo(repo)
    try:
        rows = store.conn.execute(
            "SELECT source, target FROM edges WHERE kind = ?", (EDGE_CALLS_RESOLVED,)
        ).fetchall()
    finally:
        store.close()

    pairs = {(row["source"], row["target"]) for row in rows}
    assert ("routes.py::list_users", "service.py::run_query") in pairs

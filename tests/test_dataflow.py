"""Tests for user-input and taint data-flow graph edges."""

from __future__ import annotations

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph import GraphStore
from cybergraph.security.ontology import EDGE_FLOWS_TO, EDGE_READS_INPUT, EDGE_TAINTS


def _edge_kinds(repo: Path) -> set[str]:
    store = GraphStore.open_for_repo(repo)
    try:
        rows = store.conn.execute("SELECT kind FROM edges").fetchall()
    finally:
        store.close()
    return {row["kind"] for row in rows}


def test_python_route_input_flows_to_sink(tmp_path: Path) -> None:
    repo = tmp_path / "pyapp"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.get('/search')\n"
        "def search(request):\n"
        "    q = request.query['q']\n"
        "    return db.execute('select * from users where name=' + q)\n",
        encoding="utf-8",
    )

    build_graph(repo)

    kinds = _edge_kinds(repo)
    assert EDGE_READS_INPUT in kinds
    assert EDGE_FLOWS_TO in kinds
    assert EDGE_TAINTS in kinds


def test_javascript_request_input_flows_to_sink(tmp_path: Path) -> None:
    repo = tmp_path / "jsapp"
    repo.mkdir()
    (repo / "app.js").write_text(
        "function search(req, res) {\n"
        "  const q = req.query.q;\n"
        "  db.query('select ' + q);\n"
        "}\n",
        encoding="utf-8",
    )

    build_graph(repo)

    kinds = _edge_kinds(repo)
    assert EDGE_READS_INPUT in kinds
    assert EDGE_FLOWS_TO in kinds
    assert EDGE_TAINTS in kinds


def test_go_request_input_flows_to_sink(tmp_path: Path) -> None:
    repo = tmp_path / "goapp"
    repo.mkdir()
    (repo / "main.go").write_text(
        "package main\n"
        "func search(w http.ResponseWriter, r *http.Request) {\n"
        "  q := r.URL.Query().Get(\"q\")\n"
        "  db.Query(\"select \" + q)\n"
        "}\n",
        encoding="utf-8",
    )

    build_graph(repo)

    kinds = _edge_kinds(repo)
    assert EDGE_READS_INPUT in kinds
    assert EDGE_FLOWS_TO in kinds
    assert EDGE_TAINTS in kinds

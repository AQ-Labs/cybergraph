"""Tests for the Cytoscape graph-data exporter."""

from __future__ import annotations

import json
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph_export import build_graph_data, export_graph_json
from cybergraph.security.ontology import LAYERS


def _build_demo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import sqlite3\n"
        "\n"
        "def get_db():\n"
        "    return sqlite3.connect('app.db')\n"
        "\n"
        "@app.route('/users')\n"
        "def list_users(request):\n"
        "    user_input = request.query['q']\n"
        "    return get_db().execute('select * from users where name=' + user_input)\n",
        encoding="utf-8",
    )
    build_graph(repo)
    return repo


def test_build_graph_data_has_nodes_edges_and_layers(tmp_path: Path) -> None:
    repo = _build_demo(tmp_path)
    data = build_graph_data(repo)

    assert data["counts"]["nodes"] > 0
    assert data["nodes"], "expected at least one node"
    assert data["edges"], "expected at least one edge"
    assert len(data["layers"]) == len(LAYERS)  # one per security ontology layer

    groups = {node["group"] for node in data["nodes"]}
    assert "entrypoint" in groups  # the @app.route handler
    assert "dataflow" in groups  # route input/data propagation
    assert "sink" in groups  # synthesized from REACHES_SINK to execute()


def test_export_graph_json_writes_valid_document(tmp_path: Path) -> None:
    repo = _build_demo(tmp_path)
    output = tmp_path / "graph.json"

    result = export_graph_json(repo, output)

    assert result == output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert set(payload) >= {"counts", "nodes", "edges", "layers", "attack_paths"}
    # Every edge endpoint must resolve to a node in the document.
    node_ids = {node["id"] for node in payload["nodes"]}
    for edge in payload["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids


def test_max_nodes_cap_is_respected(tmp_path: Path) -> None:
    repo = _build_demo(tmp_path)
    data = build_graph_data(repo, max_nodes=2)
    assert len(data["nodes"]) <= 2
    assert data["truncated"] is True

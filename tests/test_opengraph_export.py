"""Tests for the BloodHound OpenGraph exporter."""

from __future__ import annotations

import json
import re
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.opengraph_export import SOURCE_KIND, build_opengraph, export_opengraph

_EDGE_KIND_RE = re.compile(r"^[A-Za-z0-9_]+$")  # BloodHound OpenGraph edge-kind rule


def _build_demo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    (repo / "app.py").write_text(
        "import flask\n"
        "@app.route('/users')\n"
        "def list_users(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    build_graph(repo)
    return repo


def test_opengraph_matches_schema_shape(tmp_path: Path):
    repo = _build_demo(tmp_path)
    doc = build_opengraph(repo)

    # Top-level: metadata + graph{nodes, edges}.
    assert doc["metadata"]["source_kind"] == SOURCE_KIND
    assert set(doc["graph"]) == {"nodes", "edges"}
    nodes = doc["graph"]["nodes"]
    edges = doc["graph"]["edges"]
    assert nodes and edges

    # Nodes: top-level id, non-empty kinds list, properties dict, lowercase prop keys.
    node_ids = set()
    for node in nodes:
        assert node["id"]
        node_ids.add(node["id"])
        assert isinstance(node["kinds"], list) and node["kinds"]
        assert SOURCE_KIND in node["kinds"]
        assert isinstance(node["properties"], dict)
        assert all(k == k.lower() for k in node["properties"]), node["properties"]
    assert len(node_ids) == len(nodes)  # ids unique


def test_opengraph_edges_valid_and_resolve_to_nodes(tmp_path: Path):
    repo = _build_demo(tmp_path)
    doc = build_opengraph(repo)
    node_ids = {n["id"] for n in doc["graph"]["nodes"]}

    for edge in doc["graph"]["edges"]:
        assert _EDGE_KIND_RE.match(edge["kind"]), edge["kind"]
        for endpoint in (edge["start"], edge["end"]):
            assert endpoint["match_by"] == "id"
            assert endpoint["value"] in node_ids  # no dangling endpoints


def test_opengraph_includes_entrypoint_and_sink_kinds(tmp_path: Path):
    repo = _build_demo(tmp_path)
    doc = build_opengraph(repo)
    primary_kinds = {n["kinds"][0] for n in doc["graph"]["nodes"]}
    assert "Sink" in primary_kinds          # synthesized from REACHES_SINK
    assert "Entrypoint" in primary_kinds     # the @app.route handler
    # the EXPOSES_ENTRYPOINT relationship is present
    assert any(e["kind"] == "EXPOSES_ENTRYPOINT" for e in doc["graph"]["edges"])


def test_export_opengraph_writes_valid_json(tmp_path: Path):
    repo = _build_demo(tmp_path)
    output = tmp_path / "og.json"
    result = export_opengraph(repo, output)

    assert result == output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["graph"]["nodes"]
    assert payload["graph"]["edges"]

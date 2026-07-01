"""Tests for local investigation summaries."""

from __future__ import annotations

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph_export import build_graph_data
from cybergraph.security.investigate import (
    collect_top_risks,
    export_investigation_markdown,
    format_top_risks,
)


def test_collect_top_risks_and_export_markdown(tmp_path: Path) -> None:
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

    risks = collect_top_risks(repo)
    output = format_top_risks(risks)
    markdown = export_investigation_markdown(repo, tmp_path / "investigation.md")
    graph_data = build_graph_data(repo)

    assert risks
    assert "attack-path" in output
    assert markdown.exists()
    assert "CyberGraph Investigation" in markdown.read_text(encoding="utf-8")
    assert graph_data["top_risks"]

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.security.layers import format_layer_summary, summarize_layers


def test_layer_summary_counts_security_nodes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "def authenticate_user(token):\n"
        "    return token == 'ok'\n\n"
        "def run_query(db):\n"
        "    return db.execute('select 1')\n",
        encoding="utf-8",
    )
    build_graph(repo)

    summary = summarize_layers(repo)
    text = format_layer_summary(summary)

    assert "Authentication" in text
    assert "Sensitive Sinks" in text
    assert any(item.key == "authentication" and item.node_count >= 1 for item in summary)
    assert any(item.key == "sink" and item.edge_count >= 1 for item in summary)


def test_layer_summary_counts_dependencies(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("fastapi==0.110.0\n", encoding="utf-8")
    build_graph(repo)

    summary = summarize_layers(repo)

    assert any(item.key == "dependency" and item.node_count >= 2 for item in summary)

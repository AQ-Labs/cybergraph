"""Tests for secret exposure reachability."""

from __future__ import annotations

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph import GraphStore
from cybergraph.security.ontology import EDGE_EXPOSES_SECRET
from cybergraph.security.secrets import find_secret_exposures, format_secret_exposures


def test_python_secret_logged_from_entrypoint_is_prioritized(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import os\n"
        "@app.get('/debug')\n"
        "def debug(request):\n"
        "    secret = os.getenv('API_TOKEN')\n"
        "    logger.info(secret)\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )
    build_graph(repo)

    store = GraphStore.open_for_repo(repo)
    try:
        edge_count = store.conn.execute(
            "SELECT COUNT(*) FROM edges WHERE kind = ?", (EDGE_EXPOSES_SECRET,)
        ).fetchone()[0]
    finally:
        store.close()

    exposures = find_secret_exposures(repo)
    output = format_secret_exposures(exposures)

    assert edge_count == 1
    assert exposures
    assert exposures[0].entrypoint_reachable is True
    assert "logger.info" in output
    assert "Fix:" in output

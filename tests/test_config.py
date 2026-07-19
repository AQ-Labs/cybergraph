from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.config import load_config
from cybergraph.graph import GraphStore


def test_load_config_reads_ignored_paths_and_markers(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".cybergraph.toml").write_text(
        "[ignore]\n"
        "paths = ['vendor/**']\n\n"
        "[security]\n"
        "sinks = ['dangerous_call']\n"
        "auth_markers = ['require_admin']\n"
        "\n[suppressions]\n"
        "rules = ['CG-SINK-CALL']\n"
        "paths = ['legacy/**']\n",
        encoding="utf-8",
    )

    config = load_config(repo)

    assert config.ignored_paths == ("vendor/**",)
    assert config.custom_sinks == ("dangerous_call",)
    assert config.auth_markers == ("require_admin",)
    assert config.suppressed_rules == ("CG-SINK-CALL",)
    assert config.suppressed_paths == ("legacy/**",)


def test_build_graph_respects_ignored_paths(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    vendor = repo / "vendor"
    vendor.mkdir(parents=True)
    (repo / ".cybergraph.toml").write_text("[ignore]\npaths = ['vendor/**']\n", encoding="utf-8")
    (repo / "app.py").write_text("def app():\n    return 1\n", encoding="utf-8")
    (vendor / "ignored.py").write_text("def ignored():\n    return 1\n", encoding="utf-8")

    build_graph(repo)

    store = GraphStore.open_for_repo(repo)
    try:
        ignored = store.conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE file_path = 'vendor/ignored.py'"
        ).fetchone()[0]
    finally:
        store.close()
    assert ignored == 0


def test_build_graph_applies_custom_sink(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".cybergraph.toml").write_text(
        "[security]\nsinks = ['dangerous_call']\n",
        encoding="utf-8",
    )
    (repo / "app.py").write_text(
        "def handler():\n"
        "    return dangerous_call()\n",
        encoding="utf-8",
    )

    build_graph(repo)

    store = GraphStore.open_for_repo(repo)
    try:
        sink_edges = store.conn.execute(
            "SELECT COUNT(*) FROM edges WHERE kind = 'REACHES_SINK'"
        ).fetchone()[0]
    finally:
        store.close()
    assert sink_edges == 1


def test_build_graph_suppresses_configured_finding_rules(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".cybergraph.toml").write_text(
        "[suppressions]\nrules = ['CG-SINK-CALL']\n",
        encoding="utf-8",
    )
    (repo / "app.py").write_text(
        "def handler():\n"
        "    return db.execute('select 1')\n",
        encoding="utf-8",
    )

    build_graph(repo)

    store = GraphStore.open_for_repo(repo)
    try:
        finding_count = store.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        sink_edges = store.conn.execute(
            "SELECT COUNT(*) FROM edges WHERE kind = 'REACHES_SINK'"
        ).fetchone()[0]
    finally:
        store.close()
    assert finding_count == 0
    assert sink_edges == 1

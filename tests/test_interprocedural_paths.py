"""Tests for interprocedural attack-path traversal."""

from __future__ import annotations

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.security.attack_paths import find_attack_paths, format_attack_paths


def _multi_file_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "@app.get('/users')\n"
        "def list_users(name: str):\n"
        "    return run_query(name)\n",
        encoding="utf-8",
    )
    (repo / "service.py").write_text(
        "def run_query(name):\n"
        "    return db.execute('select * from users where n=' + name)\n",
        encoding="utf-8",
    )
    build_graph(repo)
    return repo


def test_attack_path_crosses_files(tmp_path: Path) -> None:
    repo = _multi_file_repo(tmp_path)

    paths = find_attack_paths(repo)

    # The entrypoint in routes.py should reach the sink in service.py.
    crossing = [
        p for p in paths
        if p.entrypoint == "routes.py::list_users" and "service.py::run_query" in p.nodes
    ]
    assert crossing, f"expected a cross-file path, got {[p.nodes for p in paths]}"
    assert crossing[0].confidence in {"high", "medium", "low"}


def test_shallow_mode_does_not_cross_files(tmp_path: Path) -> None:
    repo = _multi_file_repo(tmp_path)

    shallow = find_attack_paths(repo, interprocedural=False)
    deep = find_attack_paths(repo, interprocedural=True)

    shallow_crosses = any("service.py::run_query" in p.nodes for p in shallow)
    deep_crosses = any("service.py::run_query" in p.nodes for p in deep)
    assert not shallow_crosses
    assert deep_crosses


def test_sanitizer_barrier_is_flagged(tmp_path: Path) -> None:
    repo = tmp_path / "san"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.get('/items')\n"
        "def get_item(name: str):\n"
        "    clean = validate_input(name)\n"
        "    return run_sql(clean)\n"
        "\n"
        "def validate_input(value):\n"
        "    return sanitize(value)\n"
        "\n"
        "def run_sql(value):\n"
        "    return db.execute('select ' + value)\n",
        encoding="utf-8",
    )
    build_graph(repo)

    paths = find_attack_paths(repo)
    # At least one reported path should be marked as passing through a sanitizer.
    assert any(p.sanitized for p in paths), "expected a sanitized/validated path flag"


def test_confidence_present_on_every_path(tmp_path: Path) -> None:
    repo = _multi_file_repo(tmp_path)
    for path in find_attack_paths(repo):
        assert path.confidence in {"high", "medium", "low"}


def test_tainted_sink_path_reports_data_reachability(tmp_path: Path) -> None:
    repo = tmp_path / "tainted"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.get('/search')\n"
        "def search(request):\n"
        "    q = request.query['q']\n"
        "    return db.execute('select ' + q)\n",
        encoding="utf-8",
    )
    build_graph(repo)

    paths = find_attack_paths(repo)
    tainted = [path for path in paths if path.sink == "db.execute"]

    assert tainted
    assert tainted[0].data_reachable is True
    assert tainted[0].taint_sources
    assert any("user-controlled data reaches" in reason for reason in tainted[0].reasons)
    assert "data=tainted" in format_attack_paths(tainted)

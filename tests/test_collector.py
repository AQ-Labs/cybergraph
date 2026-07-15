from pathlib import Path

from cybergraph.analysis.collector import iter_source_files


def test_collector_excludes_are_relative_to_repo_root(tmp_path: Path) -> None:
    parent = tmp_path / "dist"
    repo = parent / "repo"
    repo.mkdir(parents=True)
    app = repo / "app.py"
    app.write_text("def handler():\n    return 1\n", encoding="utf-8")

    files = [path.relative_to(repo).as_posix() for path in iter_source_files(repo)]

    assert files == ["app.py"]


def test_collector_normalizes_windows_style_ignored_paths(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    generated = repo / "src" / "generated"
    generated.mkdir(parents=True)
    (repo / "src").mkdir(exist_ok=True)
    (repo / "src" / "app.py").write_text("def app():\n    return 1\n", encoding="utf-8")
    (generated / "ignored.py").write_text("def ignored():\n    return 1\n", encoding="utf-8")

    files = [
        path.relative_to(repo).as_posix()
        for path in iter_source_files(repo, ignored_paths=("src\\generated",))
    ]

    assert files == ["src/app.py"]

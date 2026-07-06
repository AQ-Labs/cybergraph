"""CLI import commands should fail cleanly on bad report paths, not traceback."""

from __future__ import annotations

from pathlib import Path

import pytest

from cybergraph.build import build_graph
from cybergraph.cli import main


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    build_graph(repo)
    return repo


@pytest.mark.parametrize("command", ["import-report", "import-vulns", "enrich-vulns"])
def test_import_missing_file_exits_cleanly(tmp_path: Path, command: str) -> None:
    repo = _repo(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main([command, str(tmp_path / "nope.json"), "--repo", str(repo)])
    assert exc.value.code == 2


@pytest.mark.parametrize("command", ["import-report", "import-vulns", "enrich-vulns"])
def test_import_malformed_json_exits_cleanly(tmp_path: Path, command: str) -> None:
    repo = _repo(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json ", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main([command, str(bad), "--repo", str(repo)])
    assert exc.value.code == 2


def test_import_report_directory_exits_cleanly(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main(["import-report", str(tmp_path), "--repo", str(repo)])
    assert exc.value.code == 2


def test_import_strix_bad_input_is_tolerated(tmp_path: Path) -> None:
    # Strix import intentionally tolerates junk (returns nothing) rather than
    # aborting, since run directories can be partially written.
    repo = _repo(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json ", encoding="utf-8")
    assert main(["import-strix", str(bad), "--repo", str(repo)]) == 0

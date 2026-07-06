"""Tests for the optional Strix orchestration wrapper (no real Strix/Docker)."""

from __future__ import annotations

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.security import strix_runner
from cybergraph.security.strix_runner import run_strix


def _make_repo(tmp_path: Path) -> Path:
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
    return repo


def test_run_strix_reports_missing_binary(tmp_path: Path, monkeypatch) -> None:
    repo = _make_repo(tmp_path)
    monkeypatch.setattr(strix_runner.shutil, "which", lambda _name: None)

    result = run_strix(repo)

    assert result.ran is False
    assert "not installed" in result.message
    assert result.imported == 0


def test_run_strix_reports_docker_down(tmp_path: Path, monkeypatch) -> None:
    repo = _make_repo(tmp_path)
    monkeypatch.setattr(strix_runner.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(strix_runner, "docker_running", lambda: False)

    result = run_strix(repo)

    assert result.ran is False
    assert "Docker is not running" in result.message


def test_run_strix_imports_findings_from_latest_run(tmp_path: Path, monkeypatch) -> None:
    repo = _make_repo(tmp_path)
    monkeypatch.setattr(strix_runner.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(strix_runner, "docker_running", lambda: True)

    fixture = Path(__file__).parent / "fixtures" / "strix_run" / "vulnerabilities.json"
    run_dir = repo / "strix_runs" / "demo"
    run_dir.mkdir(parents=True)
    (run_dir / "vulnerabilities.json").write_text(
        fixture.read_text(encoding="utf-8"), encoding="utf-8"
    )

    def fake_run(cmd, **kwargs):  # noqa: ANN001 - test stub
        class _Completed:
            returncode = 2

        return _Completed()

    monkeypatch.setattr(strix_runner.subprocess, "run", fake_run)

    result = run_strix(repo)

    assert result.ran is True
    assert result.imported == 1
    assert result.run_dir is not None

from __future__ import annotations

import subprocess
from pathlib import Path

from cybergraph.security.revisions import MODE_STAGED, resolve_revisions


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    (repo / "base.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "base.py")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def test_staged_mode_reports_only_staged_files(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "staged.py").write_text("s = 1\n", encoding="utf-8")
    (repo / "unstaged.py").write_text("u = 1\n", encoding="utf-8")
    _git(repo, "add", "staged.py")  # unstaged.py left untracked/unstaged

    rev = resolve_revisions(repo, mode=MODE_STAGED)

    assert rev.mode == MODE_STAGED
    assert rev.failure == ""
    assert "staged.py" in rev.changed_files
    assert "unstaged.py" not in rev.changed_files


def test_staged_mode_empty_index_is_established_not_failed(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "unstaged.py").write_text("u = 1\n", encoding="utf-8")  # nothing staged

    rev = resolve_revisions(repo, mode=MODE_STAGED)

    assert rev.mode == MODE_STAGED
    assert rev.failure == ""
    assert rev.changed_files == ()

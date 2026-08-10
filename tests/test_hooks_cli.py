from __future__ import annotations

import subprocess
from pathlib import Path

from cybergraph.cli import main


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    return repo


def test_install_status_uninstall_pre_commit(tmp_path, capsys):
    repo = _repo(tmp_path)
    assert main(["hook", "install", "pre-commit", "--repo", str(repo)]) == 0
    assert (repo / ".git" / "hooks" / "pre-commit").exists()

    assert main(["hook", "status", "--repo", str(repo)]) == 0
    out = capsys.readouterr().out
    assert "pre-commit" in out and "advisory" in out

    assert main(["hook", "uninstall", "pre-commit", "--repo", str(repo)]) == 0
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()


def test_install_claude_code(tmp_path):
    repo = _repo(tmp_path)
    assert main(["hook", "install", "claude-code", "--repo", str(repo)]) == 0
    assert (repo / ".claude" / "settings.json").exists()


def test_foreign_pre_commit_refusal_returns_nonzero(tmp_path):
    repo = _repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    assert main(["hook", "install", "pre-commit", "--repo", str(repo)]) == 1
    assert hook.read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"


def test_status_reports_both_targets(tmp_path, capsys):
    repo = _repo(tmp_path)
    assert main(["hook", "status", "--repo", str(repo)]) == 0
    out = capsys.readouterr().out
    assert "claude-code" in out
    assert "pre-commit" in out

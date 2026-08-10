from __future__ import annotations

import subprocess
from pathlib import Path

from cybergraph.hooks.base import MARKER, Status
from cybergraph.hooks.pre_commit import PreCommitTarget


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    return repo


def _hook(repo: Path) -> Path:
    return repo / ".git" / "hooks" / "pre-commit"


def test_fresh_install_writes_marked_executable_staged_hook(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    res = PreCommitTarget().install(repo, strict=False, force=False)
    assert res.status is Status.INSTALLED
    body = _hook(repo).read_text(encoding="utf-8")
    assert MARKER in body
    assert "check . --mode staged" in body
    assert "--fail-on-review" not in body  # advisory
    import os
    import stat

    if os.name != "nt":
        assert stat.S_IMODE(_hook(repo).stat().st_mode) & stat.S_IXUSR


def test_strict_install_adds_fail_on_review(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    PreCommitTarget().install(repo, strict=True, force=False)
    assert "--fail-on-review" in _hook(repo).read_text(encoding="utf-8")


def test_reinstall_is_idempotent(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    PreCommitTarget().install(repo, strict=False, force=False)
    res = PreCommitTarget().install(repo, strict=False, force=False)
    assert res.status is Status.ALREADY_PRESENT


def test_foreign_hook_is_refused_and_untouched(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _hook(repo).parent.mkdir(parents=True, exist_ok=True)
    _hook(repo).write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    res = PreCommitTarget().install(repo, strict=False, force=False)
    assert res.status is Status.REFUSED_FOREIGN
    assert _hook(repo).read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"
    assert not (repo / ".git" / "hooks" / "pre-commit.cybergraph.bak").exists()


def test_force_backs_up_foreign_then_replaces(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _hook(repo).parent.mkdir(parents=True, exist_ok=True)
    _hook(repo).write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    res = PreCommitTarget().install(repo, strict=False, force=True)
    assert res.status is Status.INSTALLED
    bak = repo / ".git" / "hooks" / "pre-commit.cybergraph.bak"
    assert bak.read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"
    assert MARKER in _hook(repo).read_text(encoding="utf-8")


def test_uninstall_removes_only_ours(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    PreCommitTarget().install(repo, strict=False, force=False)
    res = PreCommitTarget().uninstall(repo)
    assert res.status is Status.REMOVED
    assert not _hook(repo).exists()


def test_uninstall_leaves_foreign_hook_intact(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _hook(repo).parent.mkdir(parents=True, exist_ok=True)
    _hook(repo).write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    res = PreCommitTarget().uninstall(repo)
    assert res.status is Status.ABSENT  # nothing of ours to remove
    assert _hook(repo).read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"


def test_foreign_hook_mentioning_marker_in_prose_is_still_refused(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _hook(repo).parent.mkdir(parents=True, exist_ok=True)
    body = "#!/bin/sh\n# we intentionally do not use cybergraph-hook here\necho custom-lint\n"
    _hook(repo).write_text(body, encoding="utf-8")
    res = PreCommitTarget().install(repo, strict=False, force=False)
    assert res.status is Status.REFUSED_FOREIGN
    assert _hook(repo).read_text(encoding="utf-8") == body
    assert not (repo / ".git" / "hooks" / "pre-commit.cybergraph.bak").exists()


def test_uninstall_leaves_foreign_hook_mentioning_marker_intact(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _hook(repo).parent.mkdir(parents=True, exist_ok=True)
    body = "#!/bin/sh\n# we intentionally do not use cybergraph-hook here\necho custom-lint\n"
    _hook(repo).write_text(body, encoding="utf-8")
    res = PreCommitTarget().uninstall(repo)
    assert res.status is Status.ABSENT
    assert _hook(repo).read_text(encoding="utf-8") == body


def test_install_outside_git_repo_is_not_a_repo(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    res = PreCommitTarget().install(plain, strict=False, force=False)
    assert res.status is Status.NOT_A_REPO

import subprocess
from pathlib import Path

from cybergraph.security.revisions import (
    MODE_MERGE_BASE,
    MODE_RANGE,
    MODE_WORKTREE,
    resolve_revisions,
)


def _run(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    ).stdout.strip()


def _repo(tmp_path: Path) -> Path:
    _run(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    _run(tmp_path, "add", "-A")
    _run(tmp_path, "commit", "-qm", "base")
    return tmp_path


def test_modified_file_is_seen(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
    revisions = resolve_revisions(repo)
    assert revisions.mode == MODE_WORKTREE
    assert revisions.changed_files == ("a.py",)


def test_untracked_file_is_seen(tmp_path: Path):
    """The blocker: `git diff HEAD` does not list untracked files."""
    repo = _repo(tmp_path)
    (repo / "new_admin_endpoint.py").write_text("x = 1\n", encoding="utf-8")
    revisions = resolve_revisions(repo)
    assert revisions.changed_files == ("new_admin_endpoint.py",)
    assert revisions.failure == ""


def test_untracked_and_modified_are_unioned(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
    (repo / "b.py").write_text("y = 1\n", encoding="utf-8")
    assert resolve_revisions(repo).changed_files == ("a.py", "b.py")


def test_gitignored_files_are_not_reported(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / ".gitignore").write_text("secret.py\n", encoding="utf-8")
    (repo / "secret.py").write_text("x = 1\n", encoding="utf-8")
    assert "secret.py" not in resolve_revisions(repo).changed_files


def test_clean_tree_on_a_branch_uses_merge_base(tmp_path: Path):
    repo = _repo(tmp_path)
    _run(repo, "checkout", "-qb", "feature")
    (repo / "b.py").write_text("y = 1\n", encoding="utf-8")
    _run(repo, "add", "-A")
    _run(repo, "commit", "-qm", "feature work")

    revisions = resolve_revisions(repo)
    assert revisions.mode == MODE_MERGE_BASE
    assert revisions.changed_files == ("b.py",), "the PR-CI false-ACCEPT case"


def test_explicit_merge_base_mode_is_honoured(tmp_path: Path):
    """C7: --base alone silently fell back to worktree mode."""
    repo = _repo(tmp_path)
    _run(repo, "checkout", "-qb", "feature")
    (repo / "b.py").write_text("y = 1\n", encoding="utf-8")
    _run(repo, "add", "-A")
    _run(repo, "commit", "-qm", "feature work")

    revisions = resolve_revisions(repo, base="main", mode=MODE_MERGE_BASE)
    assert revisions.mode == MODE_MERGE_BASE
    assert revisions.changed_files == ("b.py",)


def test_explicit_range(tmp_path: Path):
    repo = _repo(tmp_path)
    first = _run(repo, "rev-parse", "HEAD")
    (repo / "c.py").write_text("z = 1\n", encoding="utf-8")
    _run(repo, "add", "-A")
    _run(repo, "commit", "-qm", "second")
    second = _run(repo, "rev-parse", "HEAD")

    revisions = resolve_revisions(repo, base=f"{first}..{second}")
    assert revisions.mode == MODE_RANGE
    assert revisions.changed_files == ("c.py",)


def test_unknown_ref_is_a_failure_not_an_empty_diff(tmp_path: Path):
    """Failing to establish the comparison must not read as 'nothing changed'."""
    repo = _repo(tmp_path)
    revisions = resolve_revisions(repo, base="origin/does-not-exist")
    assert revisions.failure
    assert revisions.changed_files == ()


def test_missing_merge_base_is_a_failure(tmp_path: Path):
    repo = _repo(tmp_path)
    revisions = resolve_revisions(repo, mode=MODE_MERGE_BASE, base="origin/nope")
    assert revisions.failure


def test_not_a_git_repository_is_a_failure(tmp_path: Path):
    assert resolve_revisions(tmp_path).failure


def test_clean_tree_on_main_with_no_base_is_not_a_failure(tmp_path: Path):
    """On the default branch with a clean tree there is nothing to compare, but
    that is not a tool failure -- it is an empty, established comparison."""
    repo = _repo(tmp_path)
    revisions = resolve_revisions(repo)
    assert revisions.failure == ""
    assert revisions.changed_files == ()

"""Resolve what changed, and fail closed when the comparison cannot be established.

"The comparison could not be established" and "nothing changed" must never render
as the same verdict, so a git failure produces a non-empty ``failure`` string --
never an empty diff that reads as a clean bill of health.

Untracked files are unioned in explicitly: ``git diff --name-only HEAD`` does not
list them, so a brand-new endpoint file would otherwise be invisible, and creating
files is what coding agents do most.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

MODE_WORKTREE = "worktree"
MODE_MERGE_BASE = "merge_base"
MODE_RANGE = "range"


@dataclass(frozen=True)
class Revisions:
    mode: str
    base_ref: str
    head_ref: str
    changed_files: tuple[str, ...]
    failure: str = ""


def _git(repo_root: Path, *args: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=repo_root, capture_output=True, text=True,
        )
    except OSError as exc:
        return False, str(exc)
    if proc.returncode != 0:
        return False, proc.stderr.strip() or f"git {' '.join(args)} failed"
    return True, proc.stdout


def _names(output: str) -> tuple[str, ...]:
    return tuple(sorted({line.strip() for line in output.splitlines() if line.strip()}))


def _verify(repo_root: Path, ref: str) -> bool:
    ok, _ = _git(repo_root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    return ok


def _current_branch(repo_root: Path) -> str:
    ok, out = _git(repo_root, "rev-parse", "--abbrev-ref", "HEAD")
    return out.strip() if ok else ""


def _default_base(repo_root: Path) -> str:
    ok, out = _git(repo_root, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD")
    if ok and out.strip():
        return out.strip().removeprefix("refs/remotes/")
    current = _current_branch(repo_root)
    for candidate in ("main", "master"):
        if candidate != current and _verify(repo_root, candidate):
            return candidate
    return ""


def _worktree_changes(repo_root: Path) -> tuple[tuple[str, ...], str]:
    """Return (changed_files, failure). ``failure`` is non-empty iff git could not
    be read -- an unreadable worktree must never collapse into an empty diff."""
    ok_diff, diff = _git(repo_root, "diff", "--name-only", "HEAD")
    if not ok_diff:
        return (), diff
    ok_unt, untracked = _git(repo_root, "ls-files", "--others", "--exclude-standard")
    if not ok_unt:
        return (), untracked
    return _names(diff + "\n" + untracked), ""


def _merge_base_diff(repo_root: Path, ref: str, head: str) -> Revisions:
    if not _verify(repo_root, ref):
        return Revisions(MODE_MERGE_BASE, ref, head, (),
                         failure=f"base ref does not exist: {ref}")
    ok, out = _git(repo_root, "diff", "--name-only", f"{ref}...HEAD")
    if not ok:
        return Revisions(MODE_MERGE_BASE, ref, head, (),
                         failure=f"could not establish merge base with {ref}: {out}")
    return Revisions(MODE_MERGE_BASE, ref, head, _names(out))


def resolve_revisions(repo_root, base: str | None = None,
                      mode: str | None = None) -> Revisions:
    repo_root = Path(repo_root).resolve()

    ok, _ = _git(repo_root, "rev-parse", "--git-dir")
    if not ok:
        return Revisions(MODE_WORKTREE, "", "", (), failure="not a git repository")

    head = _current_branch(repo_root) or "HEAD"

    # Explicit range: base contains "..".
    if base and ".." in base:
        ok, out = _git(repo_root, "diff", "--name-only", base)
        if not ok:
            return Revisions(MODE_RANGE, base, "", (),
                             failure=f"could not diff range {base}: {out}")
        return Revisions(MODE_RANGE, base, "", _names(out))

    # Merge base: requested explicitly, or a base ref was supplied.
    if mode == MODE_MERGE_BASE or base is not None:
        ref = base or _default_base(repo_root)
        if not ref:
            return Revisions(MODE_MERGE_BASE, "", head, (),
                             failure="could not determine a base branch to compare against")
        return _merge_base_diff(repo_root, ref, head)

    # Default: worktree when dirty, else merge base against the default branch.
    changes, worktree_failure = _worktree_changes(repo_root)
    if worktree_failure:
        return Revisions(MODE_WORKTREE, "HEAD", head, (),
                         failure=f"could not read the working tree: {worktree_failure}")
    if changes:
        return Revisions(MODE_WORKTREE, "HEAD", head, changes)

    ref = _default_base(repo_root)
    if not ref:
        # Clean tree on the default branch: an empty but *established* comparison.
        return Revisions(MODE_WORKTREE, "HEAD", head, ())
    return _merge_base_diff(repo_root, ref, head)

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

from .base import MARKER, InstallResult, Status, quoted_invocation

_BAK = "pre-commit.cybergraph.bak"


def _hooks_dir(repo_root: Path) -> Path | None:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--git-path", "hooks"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return None
    raw = proc.stdout.strip()
    p = Path(raw)
    return p if p.is_absolute() else (repo_root / p)


def _script(strict: bool) -> str:
    fail = " --fail-on-review" if strict else ""
    mode = "strict" if strict else "advisory"
    return (
        "#!/bin/sh\n"
        f"# {MARKER} ({mode}) -- managed by `cybergraph hook`; edits will be overwritten.\n"
        f"exec {quoted_invocation()} check . --mode staged{fail}\n"
    )


def _make_executable(path: Path) -> None:
    if os.name == "nt":
        return
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class PreCommitTarget:
    name = "pre-commit"

    def install(self, repo_root: Path, *, strict: bool, force: bool) -> InstallResult:
        hooks = _hooks_dir(repo_root)
        if hooks is None:
            return InstallResult(
                Status.NOT_A_REPO,
                "not a git repository; a pre-commit hook needs a .git directory",
            )
        path = hooks / "pre-commit"
        desired = _script(strict)
        if path.exists():
            existing = path.read_text(encoding="utf-8", errors="replace")
            if MARKER not in existing:
                if not force:
                    return InstallResult(
                        Status.REFUSED_FOREIGN,
                        "a pre-commit hook already exists and was not written by "
                        "CyberGraph. Refusing to overwrite it. Re-run with --force to "
                        "back it up and replace it.",
                    )
                shutil.copy2(path, hooks / _BAK)
            elif existing == desired:
                return InstallResult(
                    Status.ALREADY_PRESENT,
                    f"CyberGraph pre-commit hook already installed ("
                    f"{'strict' if strict else 'advisory'}).",
                )
        hooks.mkdir(parents=True, exist_ok=True)
        path.write_text(desired, encoding="utf-8")
        _make_executable(path)
        return InstallResult(
            Status.INSTALLED,
            f"Installed the CyberGraph pre-commit hook "
            f"({'strict' if strict else 'advisory'}) in {path}.",
        )

    def uninstall(self, repo_root: Path) -> InstallResult:
        hooks = _hooks_dir(repo_root)
        if hooks is None:
            return InstallResult(Status.NOT_A_REPO, "not a git repository")
        path = hooks / "pre-commit"
        if not path.exists() or MARKER not in path.read_text(
            encoding="utf-8", errors="replace"
        ):
            return InstallResult(
                Status.ABSENT,
                "no CyberGraph pre-commit hook to remove (any other hook was left intact).",
            )
        path.unlink()
        return InstallResult(Status.REMOVED, "Removed the CyberGraph pre-commit hook.")

    def status(self, repo_root: Path) -> InstallResult:
        hooks = _hooks_dir(repo_root)
        if hooks is None:
            return InstallResult(Status.NOT_A_REPO, "not installed (not a git repository)")
        path = hooks / "pre-commit"
        if not path.exists():
            return InstallResult(Status.ABSENT, "not installed")
        body = path.read_text(encoding="utf-8", errors="replace")
        if MARKER not in body:
            return InstallResult(Status.REFUSED_FOREIGN, "a foreign pre-commit hook is present")
        mode = "strict" if "--fail-on-review" in body else "advisory"
        return InstallResult(Status.ALREADY_PRESENT, f"installed ({mode})")

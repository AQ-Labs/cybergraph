# Client Hooks for Reliable Invocation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let CyberGraph install itself into the two places code is accepted — the Claude Code turn (a Stop hook) and the git commit (a pre-commit hook) — so `cybergraph check` runs on its own at that moment, advisory by default and blocking only under `--strict`.

**Architecture:** A new `cybergraph.hooks` subsystem with a shared `base.py` (a stable marker, a PATH-independent invocation resolver, JSON-settings merge helpers, and an `InstallResult`) and two pluggable targets (`claude_code.py`, `pre_commit.py`). A nested `cybergraph hook install|uninstall|status` CLI group drives them, plus an internal `cybergraph hook run claude-code` that the installed Stop hook invokes to translate a verdict into Claude Code's stdin/JSON contract. Two correctness additions ride along: `MODE_STAGED` in the revision resolver (so the pre-commit hook verifies the index, not unstaged edits) and a two-line `__main__.py` (so the hooks can call `python -m cybergraph` without PATH).

**Tech Stack:** Python 3.10–3.13, standard library only (`json`, `subprocess`, `pathlib`, `shlex`, `enum`). Existing `cybergraph.security.check.check_change` and `cybergraph.security.revisions`. Pytest.

## Global Constraints

- **Zero runtime dependencies** (`dependencies = []` in `pyproject.toml`); standard library only. No `pre-commit` framework, `husky`, or `lefthook`.
- Python 3.10–3.13. `from __future__ import annotations` as the first line of every new `.py` file.
- Ruff line-length 100; run `ruff check .` clean before every commit.
- No network access; no API keys on any default path.
- Cross-platform: the repo runs on Windows. The pre-commit hook is a POSIX `sh` script (git runs it via its bundled shell on Windows); resolve the git hooks directory via `git rev-parse --git-path hooks` (correct even for worktrees/submodules); build shell command strings with `shlex.quote`.
- A CyberGraph-written hook is always identifiable by the marker string `cybergraph-hook` (in `base.MARKER`) and/or the stable command substring `hook run claude-code` — the installer must never overwrite or delete a hook that lacks its own marker.
- Advisory is the default everywhere; `--strict` is the only thing that turns a REVIEW into a block. ACCEPT is always silent.
- Commits authored `Laraib <lxh417bham@gmail.com>` only (the repo-local git config already carries this — do **not** pass `-c user.email=`); never `azizur@sirio-strategies.com`; no `Co-Authored-By`, no AI attribution. Many small commits; never squash. Push only to `https://github.com/AQ-Labs/cybergraph`.

---

## File Structure

- `src/cybergraph/security/revisions.py` (modify) — add `MODE_STAGED` and `_staged_diff`.
- `src/cybergraph/cli.py` (modify) — add `"staged"` to `check --mode`; add the `hook` command group and `_run_hook`.
- `src/cybergraph/__main__.py` (create) — `python -m cybergraph` entrypoint.
- `src/cybergraph/hooks/__init__.py` (create) — target registry, `resolve_target`.
- `src/cybergraph/hooks/base.py` (create) — `MARKER`, `Status`, `InstallResult`, `Target`, `resolve_invocation`, JSON helpers.
- `src/cybergraph/hooks/pre_commit.py` (create) — the pre-commit target.
- `src/cybergraph/hooks/claude_code.py` (create) — the Claude Code target + the fire-time `run` wrapper.
- `tests/test_revisions_staged.py`, `tests/test_hooks_base.py`, `tests/test_hooks_pre_commit.py`, `tests/test_hooks_claude_code.py`, `tests/test_hooks_cli.py`, `tests/test_main_module.py` (create).
- `benchmark/mutation_harness.py` (modify) — two seeded hook fail-opens.
- `README.md` (modify) — document `cybergraph hook`.

---

## Task 1: `MODE_STAGED` — compare the staged index

**Files:**
- Modify: `src/cybergraph/security/revisions.py`
- Modify: `src/cybergraph/cli.py:190-193` (the `check --mode` choices)
- Test: `tests/test_revisions_staged.py` (create)

**Interfaces:**
- Consumes: existing `_git`, `_names`, `_current_branch`, `Revisions`, `resolve_revisions` in `revisions.py`.
- Produces: `MODE_STAGED = "staged"` (string constant) and a `resolve_revisions(repo, mode="staged")` path that diffs `git diff --cached --name-only` against HEAD. `check --mode staged` reaches it because `check_change` already forwards `mode` to `resolve_revisions`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_revisions_staged.py`:

```python
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
```

> Note: confirm the `Revisions` field name for the file tuple before running (the resolver builds `Revisions(mode, base, head, <names>)`); if it is not `changed_files`, use the actual attribute in the asserts. Do not change the dataclass.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_revisions_staged.py -v`
Expected: FAIL with `ImportError: cannot import name 'MODE_STAGED'`.

- [ ] **Step 3: Add `MODE_STAGED` and `_staged_diff`**

In `revisions.py`, beside `MODE_MERGE_BASE = "merge_base"` add:

```python
MODE_STAGED = "staged"
```

Add this helper next to `_worktree_changes`:

```python
def _staged_diff(repo_root: Path) -> Revisions:
    """Files in the index that differ from HEAD -- exactly what a commit will take.

    Distinct from worktree mode, which also includes unstaged and untracked
    changes: a pre-commit hook must verify the index, not files the commit
    leaves behind.
    """
    head = _current_branch(repo_root) or "HEAD"
    ok, out = _git(repo_root, "diff", "--cached", "--name-only")
    if not ok:
        return Revisions(MODE_STAGED, "HEAD", head, (),
                         failure=f"could not read the staged index: {out}")
    return Revisions(MODE_STAGED, "HEAD", head, _names(out))
```

In `resolve_revisions`, immediately after `head = _current_branch(repo_root) or "HEAD"` and before the range check, add:

```python
    if mode == MODE_STAGED:
        return _staged_diff(repo_root)
```

- [ ] **Step 4: Expose `staged` in the CLI**

In `cli.py`, change the `check --mode` choices (around line 191) from
`choices=["worktree", "merge-base", "range"]` to
`choices=["worktree", "merge-base", "range", "staged"]`, and extend the help text to
`"Comparison mode. Detected from the working tree when omitted"` → append `" (staged = the git index)"`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_revisions_staged.py -v` — Expected: PASS.
Run: `ruff check src/cybergraph/security/revisions.py src/cybergraph/cli.py` — Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/cybergraph/security/revisions.py src/cybergraph/cli.py tests/test_revisions_staged.py
git commit -m "feat(check): add staged mode to compare the git index"
```

---

## Task 2: `python -m cybergraph` entrypoint

**Files:**
- Create: `src/cybergraph/__main__.py`
- Test: `tests/test_main_module.py` (create)

**Interfaces:**
- Consumes: `cybergraph.cli.main(argv) -> int`.
- Produces: a runnable module so `sys.executable -m cybergraph …` works. `hooks.base.resolve_invocation` (Task 3) depends on this file existing.

- [ ] **Step 1: Write the failing test**

Create `tests/test_main_module.py`:

```python
from __future__ import annotations

import subprocess
import sys


def test_python_dash_m_cybergraph_runs() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "cybergraph", "check", "--help"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "--mode" in proc.stdout
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_main_module.py -v`
Expected: FAIL — `No module named cybergraph.__main__`.

- [ ] **Step 3: Create the entrypoint**

Create `src/cybergraph/__main__.py`:

```python
from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_main_module.py -v` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/__main__.py tests/test_main_module.py
git commit -m "feat: add python -m cybergraph entrypoint for hook invocation"
```

---

## Task 3: `hooks/base.py` — shared machinery

**Files:**
- Create: `src/cybergraph/hooks/__init__.py` (empty for now; the registry lands in Task 7)
- Create: `src/cybergraph/hooks/base.py`
- Test: `tests/test_hooks_base.py` (create)

**Interfaces:**
- Consumes: nothing beyond stdlib and Task 2's `__main__`.
- Produces (imported by Tasks 4–7):
  - `MARKER: str = "cybergraph-hook"`
  - `class Status(str, Enum)` with `INSTALLED, ALREADY_PRESENT, REFUSED_FOREIGN, NOT_A_REPO, REMOVED, ABSENT, MALFORMED, ERROR`
  - `@dataclass(frozen=True) class InstallResult` with `status: Status`, `message: str`, and a property `ok: bool` (True for `INSTALLED, ALREADY_PRESENT, REMOVED, ABSENT`)
  - `resolve_invocation() -> list[str]` returning `[sys.executable, "-m", "cybergraph"]`
  - `quoted_invocation() -> str` — the invocation joined with `shlex.quote`
  - `read_json(path: Path) -> dict` (empty dict for missing/blank; raises `json.JSONDecodeError` on malformed) and `write_json(path: Path, data: dict) -> None` (creates parents, `indent=2`, trailing newline)
  - `class Target(Protocol)` with `name: str`, `install(self, repo_root, *, strict, force) -> InstallResult`, `uninstall(self, repo_root) -> InstallResult`, `status(self, repo_root) -> InstallResult`

- [ ] **Step 1: Write the failing test**

Create `tests/test_hooks_base.py`:

```python
from __future__ import annotations

import json
import sys

import pytest

from cybergraph.hooks import base


def test_resolve_invocation_is_path_independent() -> None:
    assert base.resolve_invocation() == [sys.executable, "-m", "cybergraph"]
    assert "-m cybergraph" in base.quoted_invocation()


def test_read_json_missing_and_blank_are_empty(tmp_path) -> None:
    assert base.read_json(tmp_path / "nope.json") == {}
    blank = tmp_path / "blank.json"
    blank.write_text("   \n", encoding="utf-8")
    assert base.read_json(blank) == {}


def test_read_json_malformed_raises(tmp_path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        base.read_json(bad)


def test_write_json_roundtrips_and_creates_parents(tmp_path) -> None:
    target = tmp_path / "nested" / "settings.json"
    base.write_json(target, {"a": 1, "hooks": {"Stop": []}})
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1, "hooks": {"Stop": []}}


def test_install_result_ok_flags() -> None:
    assert base.InstallResult(base.Status.INSTALLED, "x").ok
    assert base.InstallResult(base.Status.ALREADY_PRESENT, "x").ok
    assert base.InstallResult(base.Status.ABSENT, "x").ok
    assert not base.InstallResult(base.Status.REFUSED_FOREIGN, "x").ok
    assert not base.InstallResult(base.Status.NOT_A_REPO, "x").ok
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_hooks_base.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.hooks'`.

- [ ] **Step 3: Implement**

Create empty `src/cybergraph/hooks/__init__.py`. Create `src/cybergraph/hooks/base.py`:

```python
from __future__ import annotations

import json
import shlex
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

MARKER = "cybergraph-hook"


class Status(str, Enum):
    INSTALLED = "installed"
    ALREADY_PRESENT = "already_present"
    REFUSED_FOREIGN = "refused_foreign"
    NOT_A_REPO = "not_a_repo"
    REMOVED = "removed"
    ABSENT = "absent"
    MALFORMED = "malformed"
    ERROR = "error"


@dataclass(frozen=True)
class InstallResult:
    status: Status
    message: str

    @property
    def ok(self) -> bool:
        return self.status in {
            Status.INSTALLED, Status.ALREADY_PRESENT, Status.REMOVED, Status.ABSENT,
        }


def resolve_invocation() -> list[str]:
    """A command that runs the CyberGraph CLI without depending on PATH.

    Git hooks and the Claude Code hook shell often run with a bare environment
    where the `cybergraph` console script is not on PATH; `python -m cybergraph`
    resolves whenever the package is importable in this interpreter.
    """
    return [sys.executable, "-m", "cybergraph"]


def quoted_invocation() -> str:
    return " ".join(shlex.quote(part) for part in resolve_invocation())


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return {}
    return json.loads(text)


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


@runtime_checkable
class Target(Protocol):
    name: str

    def install(self, repo_root: Path, *, strict: bool, force: bool) -> InstallResult: ...
    def uninstall(self, repo_root: Path) -> InstallResult: ...
    def status(self, repo_root: Path) -> InstallResult: ...
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hooks_base.py -v` — Expected: PASS.
Run: `ruff check src/cybergraph/hooks/` — Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/hooks/__init__.py src/cybergraph/hooks/base.py tests/test_hooks_base.py
git commit -m "feat(hooks): shared base -- marker, invocation resolver, json helpers"
```

---

## Task 4: `hooks/pre_commit.py` — the pre-commit target (safety core)

**Files:**
- Create: `src/cybergraph/hooks/pre_commit.py`
- Test: `tests/test_hooks_pre_commit.py` (create)

**Interfaces:**
- Consumes: `base.MARKER`, `base.Status`, `base.InstallResult`, `base.quoted_invocation`.
- Produces: `class PreCommitTarget` implementing `Target` with `name = "pre-commit"`. Install writes `<git-hooks-dir>/pre-commit` running `<invocation> check . --mode staged` (+` --fail-on-review` when strict). Foreign hook (no `MARKER`) → `REFUSED_FOREIGN` unless `force`, which backs up to `pre-commit.cybergraph.bak` first. Uninstall removes the file only if it carries `MARKER`.

Resolve the hooks directory with:

```python
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
```

- [ ] **Step 1: Write the failing test**

Create `tests/test_hooks_pre_commit.py`:

```python
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
    import os, stat
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


def test_install_outside_git_repo_is_not_a_repo(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    res = PreCommitTarget().install(plain, strict=False, force=False)
    assert res.status is Status.NOT_A_REPO
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_hooks_pre_commit.py -v`
Expected: FAIL — `ModuleNotFoundError: cybergraph.hooks.pre_commit`.

- [ ] **Step 3: Implement**

Create `src/cybergraph/hooks/pre_commit.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hooks_pre_commit.py -v` — Expected: PASS.
Run: `ruff check src/cybergraph/hooks/pre_commit.py` — Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/hooks/pre_commit.py tests/test_hooks_pre_commit.py
git commit -m "feat(hooks): pre-commit target -- never clobbers a foreign hook"
```

---

## Task 5: `hooks/claude_code.py` — install/uninstall/status (settings merge)

**Files:**
- Create: `src/cybergraph/hooks/claude_code.py` (the `run` wrapper is added in Task 6)
- Test: `tests/test_hooks_claude_code.py` (create — the install/status half)

**Interfaces:**
- Consumes: `base.MARKER`, `base.Status`, `base.InstallResult`, `base.quoted_invocation`, `base.read_json`, `base.write_json`.
- Produces: `class ClaudeCodeTarget` (`name = "claude-code"`) that merges a **Stop** hook entry into `<repo>/.claude/settings.json`. The entry's command is `<invocation> hook run claude-code` (+` --strict`). Our entry is identified by the command substring `hook run claude-code`. Install preserves all sibling keys and other Stop entries; it is idempotent. A malformed `settings.json` → `MALFORMED`, never overwritten. Uninstall removes only our entries and prunes an emptied `Stop`/`hooks`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_hooks_claude_code.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

from cybergraph.hooks.base import Status
from cybergraph.hooks.claude_code import ClaudeCodeTarget

RUN_CMD = "hook run claude-code"


def _settings(repo: Path) -> Path:
    return repo / ".claude" / "settings.json"


def _load(repo: Path) -> dict:
    return json.loads(_settings(repo).read_text(encoding="utf-8"))


def test_fresh_install_creates_stop_hook(tmp_path: Path) -> None:
    res = ClaudeCodeTarget().install(tmp_path, strict=False, force=False)
    assert res.status is Status.INSTALLED
    data = _load(tmp_path)
    cmds = [h["command"] for e in data["hooks"]["Stop"] for h in e["hooks"]]
    assert any(RUN_CMD in c for c in cmds)
    assert not any("--strict" in c for c in cmds)  # advisory


def test_strict_encodes_strict_flag(tmp_path: Path) -> None:
    ClaudeCodeTarget().install(tmp_path, strict=True, force=False)
    data = _load(tmp_path)
    cmds = [h["command"] for e in data["hooks"]["Stop"] for h in e["hooks"]]
    assert any(RUN_CMD in c and "--strict" in c for c in cmds)


def test_install_preserves_siblings_and_other_hooks(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({
        "model": "opus",
        "hooks": {
            "PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": "echo pre"}]}],
            "Stop": [{"matcher": "*", "hooks": [
                {"type": "command", "command": "echo other-stop"}]}],
        },
    }), encoding="utf-8")

    ClaudeCodeTarget().install(tmp_path, strict=False, force=False)
    data = _load(tmp_path)

    assert data["model"] == "opus"
    assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "echo pre"
    stop_cmds = [h["command"] for e in data["hooks"]["Stop"] for h in e["hooks"]]
    assert "echo other-stop" in stop_cmds
    assert any(RUN_CMD in c for c in stop_cmds)


def test_reinstall_does_not_duplicate(tmp_path: Path) -> None:
    ClaudeCodeTarget().install(tmp_path, strict=False, force=False)
    ClaudeCodeTarget().install(tmp_path, strict=False, force=False)
    data = _load(tmp_path)
    ours = [h for e in data["hooks"]["Stop"] for h in e["hooks"] if RUN_CMD in h["command"]]
    assert len(ours) == 1


def test_uninstall_removes_only_ours(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({
        "hooks": {"Stop": [{"matcher": "*", "hooks": [
            {"type": "command", "command": "echo other-stop"}]}]},
    }), encoding="utf-8")
    ClaudeCodeTarget().install(tmp_path, strict=False, force=False)

    res = ClaudeCodeTarget().uninstall(tmp_path)
    assert res.status is Status.REMOVED
    stop_cmds = [h["command"] for e in _load(tmp_path)["hooks"]["Stop"] for h in e["hooks"]]
    assert "echo other-stop" in stop_cmds
    assert not any(RUN_CMD in c for c in stop_cmds)


def test_malformed_settings_is_refused_not_overwritten(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text("{not json", encoding="utf-8")
    res = ClaudeCodeTarget().install(tmp_path, strict=False, force=False)
    assert res.status is Status.MALFORMED
    assert settings.read_text(encoding="utf-8") == "{not json"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_hooks_claude_code.py -v`
Expected: FAIL — `ModuleNotFoundError: cybergraph.hooks.claude_code`.

- [ ] **Step 3: Implement (install/uninstall/status only)**

Create `src/cybergraph/hooks/claude_code.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

from .base import (
    InstallResult,
    Status,
    quoted_invocation,
    read_json,
    write_json,
)

_RUN_CMD = "hook run claude-code"


def _settings_path(repo_root: Path) -> Path:
    return repo_root / ".claude" / "settings.json"


def _our_command(strict: bool) -> str:
    return f"{quoted_invocation()} {_RUN_CMD}" + (" --strict" if strict else "")


def _entry(strict: bool) -> dict:
    return {"matcher": "*", "hooks": [{"type": "command", "command": _our_command(strict)}]}


def _is_ours(entry: dict) -> bool:
    return any(
        _RUN_CMD in h.get("command", "")
        for h in entry.get("hooks", [])
        if isinstance(h, dict)
    )


class ClaudeCodeTarget:
    name = "claude-code"

    def install(self, repo_root: Path, *, strict: bool, force: bool) -> InstallResult:
        settings = _settings_path(repo_root)
        try:
            data = read_json(settings)
        except json.JSONDecodeError:
            return InstallResult(
                Status.MALFORMED,
                f"{settings} is not valid JSON; refusing to overwrite it. Fix or remove it, "
                "then re-run.",
            )
        hooks = data.setdefault("hooks", {})
        stop = hooks.setdefault("Stop", [])
        already = [e for e in stop if _is_ours(e)]
        if len(already) == 1 and already[0] == _entry(strict):
            return InstallResult(
                Status.ALREADY_PRESENT,
                f"CyberGraph Stop hook already installed "
                f"({'strict' if strict else 'advisory'}).",
            )
        stop[:] = [e for e in stop if not _is_ours(e)]
        stop.append(_entry(strict))
        write_json(settings, data)
        return InstallResult(
            Status.INSTALLED,
            f"Installed the CyberGraph Stop hook "
            f"({'strict' if strict else 'advisory'}) in {settings}. It runs `cybergraph "
            "check` when an agent turn ends; a REVIEW is "
            f"{'blocked' if strict else 'surfaced, not blocked'}.",
        )

    def uninstall(self, repo_root: Path) -> InstallResult:
        settings = _settings_path(repo_root)
        try:
            data = read_json(settings)
        except json.JSONDecodeError:
            return InstallResult(Status.MALFORMED, f"{settings} is not valid JSON")
        stop = data.get("hooks", {}).get("Stop", [])
        if not any(_is_ours(e) for e in stop):
            return InstallResult(Status.ABSENT, "no CyberGraph Stop hook to remove.")
        stop[:] = [e for e in stop if not _is_ours(e)]
        if not stop:
            data["hooks"].pop("Stop", None)
        if not data.get("hooks"):
            data.pop("hooks", None)
        write_json(settings, data)
        return InstallResult(Status.REMOVED, "Removed the CyberGraph Stop hook.")

    def status(self, repo_root: Path) -> InstallResult:
        settings = _settings_path(repo_root)
        try:
            data = read_json(settings)
        except json.JSONDecodeError:
            return InstallResult(Status.MALFORMED, "settings.json is not valid JSON")
        ours = [
            h.get("command", "")
            for e in data.get("hooks", {}).get("Stop", [])
            if _is_ours(e)
            for h in e.get("hooks", [])
            if _RUN_CMD in h.get("command", "")
        ]
        if not ours:
            return InstallResult(Status.ABSENT, "not installed")
        mode = "strict" if any("--strict" in c for c in ours) else "advisory"
        return InstallResult(Status.ALREADY_PRESENT, f"installed ({mode})")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hooks_claude_code.py -v` — Expected: PASS.
Run: `ruff check src/cybergraph/hooks/claude_code.py` — Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/hooks/claude_code.py tests/test_hooks_claude_code.py
git commit -m "feat(hooks): claude-code target -- merge Stop hook, preserve siblings"
```

---

## Task 6: the Claude Code fire-time wrapper (`hook run claude-code`)

**Files:**
- Modify: `src/cybergraph/hooks/claude_code.py` (add `run`)
- Test: `tests/test_hooks_claude_code.py` (append the `run` cases)

**Interfaces:**
- Consumes: `cybergraph.security.check.check_change`, `cybergraph.security.verdict.STATE_REVIEW` and `format_verdict`.
- Produces: `run(strict: bool, stdin_text: str, *, check=check_change) -> int` — reads the Stop-event JSON, runs `check_change(cwd, mode="worktree")`, and emits the Claude Code Stop contract on stdout. Always returns 0 (the JSON carries the signal). The `check` keyword argument exists so tests inject a fake verdict without building a graph.

Contract (pinned against the current Claude Code hooks docs — re-verify before wiring; the installer stays inert-safe if it drifts):
- ACCEPT (or any non-REVIEW state) → print nothing, return 0 (silent).
- REVIEW + advisory → print `{"systemMessage": "CyberGraph REVIEW — <summary>"}` (user sees it; the turn ends).
- REVIEW + strict, and `stop_hook_active` is false → print `{"decision": "block", "reason": "CyberGraph REVIEW — <summary> Address these before finishing."}` (blocks the stop; the agent must act).
- REVIEW + strict, but `stop_hook_active` is true → downgrade to the advisory `systemMessage` (loop guard: never block twice in a row, or a persistent REVIEW traps the agent).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_hooks_claude_code.py`:

```python
import json as _json

from cybergraph.hooks import claude_code
from cybergraph.security.verdict import STATE_ACCEPT, STATE_REVIEW, Reason, Verdict


def _fake_check(state, headline="dropped login on /admin/export"):
    def _c(repo, base=None, mode=None):
        reasons = () if state == STATE_ACCEPT else (Reason(headline=headline),)
        return Verdict(state, reasons)
    return _c


def _stdin(cwd, stop_active=False):
    return _json.dumps({"cwd": str(cwd), "stop_hook_active": stop_active,
                        "hook_event_name": "Stop"})


def test_accept_is_silent(tmp_path, capsys):
    rc = claude_code.run(False, _stdin(tmp_path), check=_fake_check(STATE_ACCEPT))
    assert rc == 0
    assert capsys.readouterr().out.strip() == ""


def test_review_advisory_emits_system_message(tmp_path, capsys):
    rc = claude_code.run(False, _stdin(tmp_path), check=_fake_check(STATE_REVIEW))
    assert rc == 0
    payload = _json.loads(capsys.readouterr().out)
    assert "systemMessage" in payload
    assert "REVIEW" in payload["systemMessage"]
    assert "decision" not in payload


def test_review_strict_blocks(tmp_path, capsys):
    rc = claude_code.run(True, _stdin(tmp_path), check=_fake_check(STATE_REVIEW))
    assert rc == 0
    payload = _json.loads(capsys.readouterr().out)
    assert payload["decision"] == "block"
    assert "REVIEW" in payload["reason"]


def test_strict_downgrades_when_stop_hook_active(tmp_path, capsys):
    rc = claude_code.run(True, _stdin(tmp_path, stop_active=True),
                         check=_fake_check(STATE_REVIEW))
    assert rc == 0
    payload = _json.loads(capsys.readouterr().out)
    assert "decision" not in payload          # loop guard: no second block
    assert "systemMessage" in payload
```

> Note: confirm `Reason` and `Verdict` constructor signatures in `verdict.py` before running (Verdict is `Verdict(state, reasons=(), ...)`; `Reason` carries a `headline`). Adjust the fake to the real constructors — do not change them.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_hooks_claude_code.py -k run or advisory or strict or accept -v`
Expected: FAIL — `AttributeError: module 'cybergraph.hooks.claude_code' has no attribute 'run'`.

- [ ] **Step 3: Implement `run`**

Add to `claude_code.py`:

```python
import json

from ..security.check import check_change
from ..security.verdict import STATE_REVIEW, format_verdict


def _summary(verdict) -> str:
    heads = [r.headline for r in verdict.reasons if getattr(r, "headline", "")]
    if heads:
        return " ".join(heads[:3])
    return format_verdict(verdict).strip().splitlines()[0] if format_verdict(verdict) else "review"


def run(strict: bool, stdin_text: str, *, check=check_change) -> int:
    try:
        payload = json.loads(stdin_text) if stdin_text.strip() else {}
    except json.JSONDecodeError:
        payload = {}
    cwd = Path(payload.get("cwd") or ".").resolve()
    stop_active = bool(payload.get("stop_hook_active"))

    try:
        verdict = check(cwd, mode="worktree")
    except Exception as exc:  # never trap the agent on our own failure
        print(json.dumps({"systemMessage": f"CyberGraph could not run: {exc}"}))
        return 0

    if verdict.state != STATE_REVIEW:
        return 0  # ACCEPT (or anything non-review): silent

    summary = _summary(verdict)
    if strict and not stop_active:
        print(json.dumps({
            "decision": "block",
            "reason": f"CyberGraph REVIEW — {summary} Address these before finishing.",
        }))
        return 0
    print(json.dumps({"systemMessage": f"CyberGraph REVIEW — {summary}"}))
    return 0
```

Put the `from pathlib import Path` import at the top of the file if not already present (Task 5 already imports it).

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hooks_claude_code.py -v` — Expected: PASS.
Run: `ruff check src/cybergraph/hooks/claude_code.py` — Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/hooks/claude_code.py tests/test_hooks_claude_code.py
git commit -m "feat(hooks): claude-code fire-time wrapper with stop_hook_active guard"
```

---

## Task 7: registry + `cybergraph hook` CLI group

**Files:**
- Modify: `src/cybergraph/hooks/__init__.py` (registry)
- Modify: `src/cybergraph/cli.py` (parser group + `_run_hook` + dispatch)
- Test: `tests/test_hooks_cli.py` (create)

**Interfaces:**
- Consumes: `PreCommitTarget`, `ClaudeCodeTarget`, `base.InstallResult`, `claude_code.run`.
- Produces:
  - In `hooks/__init__.py`: `TARGETS: dict[str, Target]` = `{"claude-code": ClaudeCodeTarget(), "pre-commit": PreCommitTarget()}` and `resolve_target(name) -> Target`.
  - CLI: `cybergraph hook install <target> [--strict] [--force] [--repo R]`, `cybergraph hook uninstall <target> [--repo R]`, `cybergraph hook status [--repo R]`, and the internal `cybergraph hook run claude-code [--strict]` (reads stdin). `main()` dispatches `args.command == "hook"` to `_run_hook(args)`, which returns `0` on `InstallResult.ok`/status and `1` otherwise.

- [ ] **Step 1: Write the failing test**

Create `tests/test_hooks_cli.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_hooks_cli.py -v`
Expected: FAIL — argparse rejects `hook` as an invalid choice (SystemExit).

- [ ] **Step 3: Implement the registry**

Set `src/cybergraph/hooks/__init__.py` to:

```python
from __future__ import annotations

from .base import InstallResult, Status, Target
from .claude_code import ClaudeCodeTarget
from .pre_commit import PreCommitTarget

TARGETS: dict[str, Target] = {
    "claude-code": ClaudeCodeTarget(),
    "pre-commit": PreCommitTarget(),
}


def resolve_target(name: str) -> Target:
    return TARGETS[name]


__all__ = ["TARGETS", "resolve_target", "InstallResult", "Status", "Target"]
```

- [ ] **Step 4: Add the parser group**

In `cli.py` `build_parser`, after the `check` subparser block, add:

```python
    hook = sub.add_parser("hook", help="Install/inspect CyberGraph client hooks")
    hsub = hook.add_subparsers(dest="hook_action", required=True)

    for action, helptext in (
        ("install", "Install a CyberGraph hook"),
        ("uninstall", "Remove a CyberGraph hook"),
    ):
        p = hsub.add_parser(action, help=helptext)
        p.add_argument("target", choices=["claude-code", "pre-commit"])
        p.add_argument("--repo", default=".", help="Repository root")
        if action == "install":
            p.add_argument("--strict", action="store_true",
                           help="A REVIEW blocks (commit / agent turn) instead of warning")
            p.add_argument("--force", action="store_true",
                           help="Back up and replace a foreign pre-commit hook")

    st = hsub.add_parser("status", help="Show which hooks are installed")
    st.add_argument("--repo", default=".", help="Repository root")

    run_p = hsub.add_parser("run", help="(internal) run a hook; invoked by the installed hook")
    run_p.add_argument("target", choices=["claude-code"])
    run_p.add_argument("--strict", action="store_true")
    run_p.add_argument("--repo", default=".")
```

- [ ] **Step 5: Add `_run_hook` and dispatch**

Add near `_run_check` in `cli.py`:

```python
def _run_hook(args) -> int:
    import sys as _sys

    from .hooks import TARGETS, resolve_target

    if args.hook_action == "run":
        from .hooks import claude_code
        return claude_code.run(args.strict, _sys.stdin.read())

    if args.hook_action == "status":
        repo = Path(args.repo).resolve()
        for name, target in TARGETS.items():
            res = target.status(repo)
            print(f"{name:<12} {res.message}")
        return 0

    repo = Path(args.repo).resolve()
    target = resolve_target(args.target)
    if args.hook_action == "install":
        res = target.install(repo, strict=args.strict, force=args.force)
    else:
        res = target.uninstall(repo)
    print(res.message)
    return 0 if res.ok else 1
```

In `main()`, add beside the other dispatch branches:

```python
    elif args.command == "hook":
        return _run_hook(args)
```

> `hook run` reads stdin and must not trigger the graph-not-built early return; it is not in `read_commands`, so no change is needed there. Confirm `_resolve_repo(args)` tolerates a `hook` command (it reads `args.repo`, which every `hook` action defines).

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_hooks_cli.py -v` — Expected: PASS.
Run: `ruff check src/cybergraph/cli.py src/cybergraph/hooks/__init__.py` — Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/cybergraph/hooks/__init__.py src/cybergraph/cli.py tests/test_hooks_cli.py
git commit -m "feat(hooks): cybergraph hook install|uninstall|status|run CLI"
```

---

## Task 8: mutation harness + docs

**Files:**
- Modify: `benchmark/mutation_harness.py` (append two `Mutation` entries)
- Modify: `README.md` (document `cybergraph hook`)
- Test: the mutation harness itself is the test (`python benchmark/mutation_harness.py`)

**Interfaces:**
- Consumes: the finished `pre_commit.py` and `revisions.py` from Tasks 1 and 4.
- Produces: two seeded fail-opens, each red under its guard test.

- [ ] **Step 1: Add the mutations**

Append to `MUTATIONS` in `mutation_harness.py` (match the `old` strings to the code exactly as written in Tasks 1 and 4):

```python
    # -- D9: a client hook fails open ------------------------------------
    Mutation(
        id="D9-pre-commit-overwrites-foreign-hook",
        disaster="D9",
        file="cybergraph/hooks/pre_commit.py",
        old="            if MARKER not in existing:\n"
            "                if not force:\n"
            "                    return InstallResult(\n"
            "                        Status.REFUSED_FOREIGN,",
        new="            if MARKER not in existing:\n"
            "                if False:\n"
            "                    return InstallResult(\n"
            "                        Status.REFUSED_FOREIGN,",
        tests=(
            "tests/test_hooks_pre_commit.py::test_foreign_hook_is_refused_and_untouched",
        ),
        note="installing over a foreign pre-commit hook must refuse, never clobber",
    ),
    Mutation(
        id="D9-staged-falls-back-to-worktree",
        disaster="D9",
        file="cybergraph/security/revisions.py",
        old='    ok, out = _git(repo_root, "diff", "--cached", "--name-only")',
        new='    ok, out = _git(repo_root, "diff", "--name-only", "HEAD")',
        tests=(
            "tests/test_revisions_staged.py::test_staged_mode_reports_only_staged_files",
        ),
        note="staged mode must read the index (--cached), not the working tree",
    ),
```

> If either `old` string does not match the committed source verbatim, fix the `old` string to match — do not edit the source to fit the mutation.

- [ ] **Step 2: Run the harness for the two new mutations**

Run: `python benchmark/mutation_harness.py --only D9-pre-commit-overwrites-foreign-hook D9-staged-falls-back-to-worktree`
(If `--only` is not a supported flag, run the whole harness: `python benchmark/mutation_harness.py`.)
Expected: both report **CAUGHT** (clean tests pass; mutated tests fail).

- [ ] **Step 3: Document `cybergraph hook` in the README**

Add a short section after the `cybergraph check` documentation:

````markdown
### Run the check automatically — `cybergraph hook`

`cybergraph check` verifies a change, but something has to invoke it. Install a hook so it
runs on its own at the moment code is accepted:

```bash
cybergraph hook install claude-code   # runs when an agent turn ends (Stop hook)
cybergraph hook install pre-commit     # runs before each commit (the staged index)
cybergraph hook status                 # what's installed
cybergraph hook uninstall pre-commit
```

By default a REVIEW is **surfaced, not blocking** — the commit proceeds and the agent
continues. Install with `--strict` to make a REVIEW block (a non-zero pre-commit exit, or a
Claude Code stop-block the agent must resolve). Installing over a pre-commit hook you already
have is refused unless you pass `--force` (which backs the old hook up first).
````

- [ ] **Step 4: Full verification**

Run: `pytest -q` — Expected: all pass (prior count + the new hook/staged/main tests).
Run: `ruff check .` — Expected: clean.
Run: `python benchmark/mutation_harness.py` — Expected: every mutation CAUGHT, including the two new ones.
Run: `python benchmark/run_precision.py` and `python run_eval.py` — Expected: unchanged from `main` (1.0/1.0/1.0).

- [ ] **Step 5: Commit**

```bash
git add benchmark/mutation_harness.py README.md
git commit -m "test(hooks): seed hook fail-open mutations; document cybergraph hook"
```

---

## Notes for the executor

- **Verify-before-wiring:** Task 6's Stop-hook JSON contract was pinned against the current
  Claude Code hooks docs during planning; re-confirm the field names (`decision`/`reason`,
  `systemMessage`, `stop_hook_active`) against the installed Claude Code version before trusting
  the block path. The wrapper is inert-safe: if the contract drifts, the worst case is a hook
  that prints its findings without blocking — never a spurious block or a corrupted settings file.
- **Do not** add a `pre-commit` framework, `husky`, or `lefthook` dependency, or a Cursor/other
  editor target — those are future slices the registry is shaped to accept, explicitly out of
  scope here.
- Confirm dataclass field/constructor names (`Revisions`, `Verdict`, `Reason`) against the
  source before running each task's tests; adapt the test to the real names, never the reverse.
```

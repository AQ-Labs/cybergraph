# Coverage Honesty Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give CyberGraph the honesty primitives — capability model, coverage assessment, fail-closed revision resolution — and a read-only `cybergraph coverage` surface that states exactly which files it analyzed, which it could not, and which declared checks are therefore blind on a change, without ever mistaking "I could not look" for "nothing to see."

**Architecture:** Three independent primitives (`capability.py`, `revisions.py`, `coverage.py`) plus a thin composer (`coverage_report.py`) and a CLI verb that only renders. The primitives have no consumer-side decision logic; the composer assembles a `CoverageReport` that a later verdict layer and MCP surface will reuse. No ACCEPT/REVIEW/BLOCK decision is made in this slice.

**Tech Stack:** Python 3.10–3.13, standard library only (`ast`, `subprocess`, `fnmatch`, `sqlite3` via the existing `GraphStore`), pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-08-09-coverage-honesty-design.md`
**Parent roadmap:** `docs/superpowers/plans/2026-08-08-verdict-core.md` (this is Tasks 8, 9, 14 of Milestone 1B, plus a read-only surface).

## Global Constraints

- **Python 3.10–3.13.** Every file opens with `from __future__ import annotations`.
- **Zero runtime dependencies.** `pyproject.toml` declares `dependencies = []`. Standard library only.
- **Ruff:** line-length 100, `select = ["E","F","I","N","W","UP"]`.
- **No network, no API keys** on any default path.
- **Governing invariant:** uncertainty never becomes safety — and its coverage-layer form, *"I could not look" must never render as "nothing to see."* A failure to establish the comparison is a non-empty `failure`, never an empty diff.
- **Coverage is declared, never inferred.** A capability names the file globs it claims; nothing asks a non-existent analyzer whether it would have found something.
- **Commits:** author `Laraib <lxh417bham@gmail.com>` only. Never `azizur@sirio-strategies.com`, never `-c user.email=…`, no `Co-Authored-By`, no AI attribution. Multiple small commits. Inherit the repo git config, which is already correct.
- **Baseline:** the full suite is green before this slice (`python -m pytest -q`), `python benchmark/run_precision.py` prints `GATE PASSED` and exits 0, `python benchmark/run_eval.py` is 1.0/1.0/1.0. None of these may regress.

## File Structure

| File | Responsibility |
|---|---|
| `src/cybergraph/security/capability.py` | The five-state model, declared `CAPABILITIES` and their globs, `relevance`/`triggers_review`. Pure. |
| `src/cybergraph/security/revisions.py` | Resolve the changed-file set + comparison mode; fail closed. Pure git subprocess. |
| `src/cybergraph/security/coverage.py` | Per changed source file: analyzed / failed / unsupported / missing. Reads the graph store. |
| `src/cybergraph/security/coverage_report.py` | Compose the three into a `CoverageReport`; render it. No decision logic. |
| `src/cybergraph/cli.py` (modify) | Register the `coverage` subcommand; dispatch to the composer; print. |
| `benchmark/mutation_harness.py` (modify) | Seed the fail-open mutations that would resurrect these bugs. |

---

### Task 1: Capability model

**Files:**
- Create: `src/cybergraph/security/capability.py`
- Test: `tests/test_capability.py`

**Interfaces:**
- Consumes: nothing (stdlib only).
- Produces: constants `PASS`, `FAIL`, `NOT_APPLICABLE`, `UNKNOWN`, `NOT_SUPPORTED`; glob tuples `PYTHON_GLOBS`, `WEB_GLOBS`, `INFRA_GLOBS`, `SOURCE_GLOBS`, `VERIFIED_GLOBS`; `Capability(id, label, covers, supported)`; `CAPABILITIES: tuple[Capability, ...]`; `CheckResult(capability_id, status, detail="", evidence_count=0)`; `relevance(changed_files: tuple[str, ...]) -> dict[str, bool]`; `unverified_source_files(changed_files: tuple[str, ...]) -> tuple[str, ...]`; `label_for(capability_id: str) -> str`; `triggers_review(results: list[CheckResult]) -> bool`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_capability.py`:

```python
import pytest

from cybergraph.security.capability import (
    CAPABILITIES,
    FAIL,
    NOT_APPLICABLE,
    NOT_SUPPORTED,
    PASS,
    UNKNOWN,
    CheckResult,
    relevance,
    triggers_review,
)


def test_python_change_makes_python_capabilities_relevant():
    rel = relevance(("app/main.py",))
    assert rel["sql_construction"] is True
    assert rel["client_secret_boundary"] is False


def test_typescript_change_makes_the_web_capability_relevant():
    rel = relevance(("web/page.tsx",))
    assert rel["client_secret_boundary"] is True
    assert rel["sql_construction"] is False


def test_go_change_is_caught_by_general_source_support():
    """Rev.2 accepted a Go-only change because nothing claimed .go files."""
    rel = relevance(("cmd/main.go",))
    assert rel["source_analysis_support"] is True


def test_python_change_also_claims_source_support():
    assert relevance(("app.py",))["source_analysis_support"] is True


def test_readme_change_makes_nothing_relevant():
    assert not any(relevance(("README.md",)).values())


@pytest.mark.parametrize(
    "status,expected",
    [(PASS, False), (NOT_APPLICABLE, False), (FAIL, True), (UNKNOWN, True),
     (NOT_SUPPORTED, True)],
)
def test_review_triggers(status, expected):
    assert triggers_review([CheckResult("sql_construction", status)]) is expected


def test_runtime_exploitability_is_not_a_phase_one_capability():
    """It was listed then special-cased to stop it reviewing everything."""
    assert "runtime_exploitability" not in {c.id for c in CAPABILITIES}


def test_no_capability_claims_everything():
    """A wildcard capability forces a verdict on every change; none should exist."""
    for capability in CAPABILITIES:
        assert capability.covers != ("*",), capability.id
        assert capability.covers and capability.label
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_capability.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.capability'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/capability.py`:

```python
"""What CyberGraph claims to check, and what it admits it cannot.

Five states. The distinctions between the last three carry the product's
credibility:

``PASS``            the check ran on this change and found nothing
``FAIL``            the check ran and found something
``NOT_APPLICABLE``  supported, but nothing in this change is in its scope
``UNKNOWN``         supported, but it could not run here
``NOT_SUPPORTED``   the capability does not exist yet

``NOT_APPLICABLE`` and ``NOT_SUPPORTED`` look alike and are not. A README-only
change is NOT_APPLICABLE everywhere and can honestly accept. A change to a
language with no analyzer is NOT_SUPPORTED and cannot -- accepting there is false
assurance, which for a verification tool is worse than a false positive.

Coverage is *declared*, never inferred: a capability states the file globs it
claims. Asking a non-existent analyzer whether it would have found something is
circular. ``source_analysis_support`` exists so that general language blindness
is represented directly, rather than being implied by whichever future
capability happens to list an extension.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

PASS = "pass"
FAIL = "fail"
NOT_APPLICABLE = "not_applicable"
UNKNOWN = "unknown"
NOT_SUPPORTED = "not_supported"

_REVIEW_STATES = frozenset({FAIL, UNKNOWN, NOT_SUPPORTED})

PYTHON_GLOBS = ("*.py",)
WEB_GLOBS = ("*.ts", "*.tsx", "*.js", "*.jsx", "*.vue", "*.svelte", "*.mjs", "*.cjs")
INFRA_GLOBS = ("*.tf", "*.tfvars", "supabase/*", "firebase.json", "*.yaml", "*.yml")

# Every extension CyberGraph recognises as executable source, supported or not.
SOURCE_GLOBS = (
    *PYTHON_GLOBS, *WEB_GLOBS,
    "*.go", "*.java", "*.cs", "*.rb", "*.php", "*.rs", "*.kt", "*.swift",
    "*.scala", "*.c", "*.cc", "*.cpp", "*.h", "*.hpp", "*.sh", "*.bash",
)
# The subset with a Phase 1 analyzer that produces findings.
VERIFIED_GLOBS = PYTHON_GLOBS


@dataclass(frozen=True)
class Capability:
    id: str
    label: str
    covers: tuple[str, ...]
    supported: bool


CAPABILITIES: tuple[Capability, ...] = (
    Capability("sql_construction", "Unsafe database queries", PYTHON_GLOBS, True),
    Capability("command_execution", "Unsafe system commands", PYTHON_GLOBS, True),
    Capability("code_execution", "Code run from user input", PYTHON_GLOBS, True),
    Capability("deserialization", "Unsafe data loading", PYTHON_GLOBS, True),
    Capability("path_access", "Files opened from user input", PYTHON_GLOBS, True),
    Capability("declared_login_rules", "Your declared login rules", PYTHON_GLOBS, True),
    Capability("reachable_data_paths",
               "New routes from the internet to sensitive code", PYTHON_GLOBS, True),
    Capability("source_analysis_support",
               "Languages CyberGraph can read", SOURCE_GLOBS, True),
    Capability("client_secret_boundary", "Secrets reaching the browser", WEB_GLOBS, False),
    Capability("cloud_configuration",
               "Cloud and database configuration", INFRA_GLOBS, False),
)

_BY_ID = {capability.id: capability for capability in CAPABILITIES}


@dataclass(frozen=True)
class CheckResult:
    capability_id: str
    status: str
    detail: str = ""
    evidence_count: int = 0


def relevance(changed_files: tuple[str, ...]) -> dict[str, bool]:
    """Which capabilities this change falls within the declared scope of."""
    return {
        capability.id: any(
            fnmatch(file, pattern)
            for file in changed_files
            for pattern in capability.covers
        )
        for capability in CAPABILITIES
    }


def unverified_source_files(changed_files: tuple[str, ...]) -> tuple[str, ...]:
    """Changed source files in a language with no Phase 1 analyzer."""
    return tuple(
        file
        for file in changed_files
        if any(fnmatch(file, pattern) for pattern in SOURCE_GLOBS)
        and not any(fnmatch(file, pattern) for pattern in VERIFIED_GLOBS)
    )


def label_for(capability_id: str) -> str:
    capability = _BY_ID.get(capability_id)
    return capability.label if capability else capability_id


def triggers_review(results: list[CheckResult]) -> bool:
    """Any failure, blind spot, or unsupported-but-relevant check forces review."""
    return any(result.status in _REVIEW_STATES for result in results)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_capability.py -v`
Expected: PASS (12 tests)

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/security/capability.py tests/test_capability.py
git commit -m "feat(capability): five-state results with general source-language coverage"
```

---

### Task 2: Revision resolution that fails closed

**Files:**
- Create: `src/cybergraph/security/revisions.py`
- Test: `tests/test_revisions.py`

**Interfaces:**
- Consumes: nothing (stdlib `subprocess` only).
- Produces: constants `MODE_WORKTREE = "worktree"`, `MODE_MERGE_BASE = "merge_base"`, `MODE_RANGE = "range"`; `Revisions(mode: str, base_ref: str, head_ref: str, changed_files: tuple[str, ...], failure: str = "")`; `resolve_revisions(repo_root, base: str | None = None, mode: str | None = None) -> Revisions`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_revisions.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_revisions.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.revisions'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/revisions.py`:

```python
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


def _worktree_changes(repo_root: Path) -> tuple[str, ...]:
    ok_diff, diff = _git(repo_root, "diff", "--name-only", "HEAD")
    ok_unt, untracked = _git(repo_root, "ls-files", "--others", "--exclude-standard")
    return _names((diff if ok_diff else "") + "\n" + (untracked if ok_unt else ""))


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
    changes = _worktree_changes(repo_root)
    if changes:
        return Revisions(MODE_WORKTREE, "HEAD", head, changes)

    ref = _default_base(repo_root)
    if not ref:
        # Clean tree on the default branch: an empty but *established* comparison.
        return Revisions(MODE_WORKTREE, "HEAD", head, ())
    return _merge_base_diff(repo_root, ref, head)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_revisions.py -v`
Expected: PASS (11 tests)

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/security/revisions.py tests/test_revisions.py
git commit -m "feat(revisions): fail-closed change resolution that sees untracked files"
```

---

### Task 3: Analysis coverage

**Files:**
- Create: `src/cybergraph/security/coverage.py`
- Test: `tests/test_coverage.py`

**Interfaces:**
- Consumes: `cybergraph.security.capability.SOURCE_GLOBS`, `cybergraph.security.capability.VERIFIED_GLOBS`; `cybergraph.graph.GraphStore.open_for_repo(repo_root)` returning an object with a `.conn` sqlite connection (row factory set) and a `.close()`; the `nodes` table (`kind`, `key` columns) and `findings` table (`rule_id`, `file_path` columns); `cybergraph.build.build_graph(repo_root)`.
- Produces: constants `STATUS_ANALYZED = "analyzed"`, `STATUS_FAILED = "failed"`, `STATUS_UNSUPPORTED = "unsupported"`, `STATUS_MISSING = "missing"`; `FileCoverage(path: str, status: str, reason: str = "")`; `assess_coverage(repo_root: Path, changed_files: tuple[str, ...]) -> tuple[FileCoverage, ...]`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_coverage.py`:

```python
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.security.coverage import assess_coverage

GOOD = "def add(a, b):\n    return a + b\n"
BROKEN = "def add(a, b)\n    return a + b\n"  # missing colon


def _status(tmp_path: Path, changed: tuple[str, ...]) -> dict[str, str]:
    build_graph(tmp_path)
    return {item.path: item.status for item in assess_coverage(tmp_path, changed)}


def test_parsed_file_is_analyzed(tmp_path: Path):
    (tmp_path / "good.py").write_text(GOOD, encoding="utf-8")
    assert _status(tmp_path, ("good.py",)) == {"good.py": "analyzed"}


def test_unparseable_file_is_failed_not_clean(tmp_path: Path):
    """Zero findings from a file that never parsed is not evidence of safety."""
    (tmp_path / "broken.py").write_text(BROKEN, encoding="utf-8")
    assert _status(tmp_path, ("broken.py",)) == {"broken.py": "failed"}


def test_language_without_an_analyzer_is_unsupported(tmp_path: Path):
    (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
    assert _status(tmp_path, ("main.go",)) == {"main.go": "unsupported"}


def test_deleted_file_is_missing_not_failed(tmp_path: Path):
    (tmp_path / "good.py").write_text(GOOD, encoding="utf-8")
    build_graph(tmp_path)
    (tmp_path / "good.py").unlink()
    statuses = {i.path: i.status for i in assess_coverage(tmp_path, ("good.py", "gone.py"))}
    assert statuses["gone.py"] == "missing"


def test_non_source_file_is_not_reported(tmp_path: Path):
    (tmp_path / "README.md").write_text("hi\n", encoding="utf-8")
    assert _status(tmp_path, ("README.md",)) == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_coverage.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.coverage'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/coverage.py`:

```python
"""Which changed files were actually analyzed.

Zero findings has two very different causes: the analyzer looked and found
nothing, or it never looked. Without this module they are indistinguishable, and
a Python file with a syntax error reads as clean.

``analyze_python_file`` already records a ``PY-SYNTAX`` finding when a file fails
to parse; nothing consumed it. A changed source file counts as ``analyzed`` only
when the graph holds a ``File`` node for it and no parse failure is recorded
against it.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security.capability import SOURCE_GLOBS, VERIFIED_GLOBS

STATUS_ANALYZED = "analyzed"
STATUS_FAILED = "failed"
STATUS_UNSUPPORTED = "unsupported"
STATUS_MISSING = "missing"

_PARSE_FAILURE_RULES = ("PY-SYNTAX",)


@dataclass(frozen=True)
class FileCoverage:
    path: str
    status: str
    reason: str = ""


def assess_coverage(
    repo_root: Path, changed_files: tuple[str, ...]
) -> tuple[FileCoverage, ...]:
    """Report analysis status for every changed *source* file."""
    repo_root = Path(repo_root).resolve()
    sources = tuple(
        file for file in changed_files
        if any(fnmatch(file, pattern) for pattern in SOURCE_GLOBS)
    )
    if not sources:
        return ()

    store = GraphStore.open_for_repo(repo_root)
    try:
        known = {
            row["key"]
            for row in store.conn.execute("SELECT key FROM nodes WHERE kind = 'File'")
        }
        failed = {
            row["file_path"]
            for row in store.conn.execute(
                "SELECT file_path FROM findings WHERE rule_id IN "
                f"({','.join('?' for _ in _PARSE_FAILURE_RULES)})",
                _PARSE_FAILURE_RULES,
            )
        }
    finally:
        store.close()

    results: list[FileCoverage] = []
    for file in sources:
        if file in failed:
            results.append(FileCoverage(file, STATUS_FAILED, "the file could not be read"))
        elif not any(fnmatch(file, pattern) for pattern in VERIFIED_GLOBS):
            results.append(
                FileCoverage(file, STATUS_UNSUPPORTED, "no analyzer for this language yet")
            )
        elif file in known:
            results.append(FileCoverage(file, STATUS_ANALYZED))
        elif not (repo_root / file).exists():
            results.append(FileCoverage(file, STATUS_MISSING, "deleted in this change"))
        else:
            results.append(
                FileCoverage(file, STATUS_FAILED, "the file was not analyzed")
            )
    return tuple(results)
```

**Note for the implementer:** the `coverage.py` spec imports `from cybergraph.graph import GraphStore`. Confirm the import path first — `GraphStore` is defined in `src/cybergraph/graph/store.py`. If `cybergraph.graph` does not re-export it, import `from cybergraph.graph.store import GraphStore` instead. Do not change `store.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_coverage.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/security/coverage.py tests/test_coverage.py
git commit -m "feat(coverage): record whether each changed file was actually analyzed"
```

---

### Task 4: Coverage report and the `cybergraph coverage` surface

**Files:**
- Create: `src/cybergraph/security/coverage_report.py`
- Modify: `src/cybergraph/cli.py` (register the `coverage` subparser near the other `sub.add_parser(...)` calls around line 35–295; add an `elif args.command == "coverage":` branch in the dispatch chain around line 403–525)
- Test: `tests/test_coverage_report.py`

**Interfaces:**
- Consumes: `cybergraph.security.revisions.resolve_revisions`, `Revisions`, `MODE_*`; `cybergraph.security.coverage.assess_coverage`, `FileCoverage`, `STATUS_*`; `cybergraph.security.capability.CAPABILITIES`, `relevance`, `label_for`, `NOT_APPLICABLE`, `NOT_SUPPORTED`, `UNKNOWN`; `cybergraph.build.build_graph`.
- Produces: constant `CAP_CHECKED = "checked"`; `CapabilityCoverage(capability_id: str, label: str, status: str)`; `CoverageReport(mode: str, changed_files: tuple[str, ...], files: tuple[FileCoverage, ...], capabilities: tuple[CapabilityCoverage, ...], failure: str = "")` with a `@property established -> bool`; `build_coverage_report(repo_root, base=None, mode=None) -> CoverageReport`; `format_coverage_report(report: CoverageReport) -> str`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_coverage_report.py`:

```python
import subprocess
from pathlib import Path

from cybergraph.security.capability import NOT_SUPPORTED, UNKNOWN
from cybergraph.security.coverage_report import (
    CAP_CHECKED,
    build_coverage_report,
    format_coverage_report,
)


def _run(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    )


def _repo(tmp_path: Path) -> Path:
    _run(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "seed.py").write_text("x = 1\n", encoding="utf-8")
    _run(tmp_path, "add", "-A")
    _run(tmp_path, "commit", "-qm", "base")
    return tmp_path


def _cap(report, capability_id):
    return next(c for c in report.capabilities if c.capability_id == capability_id)


def test_untracked_python_file_is_analyzed_and_in_scope(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "routes.py").write_text(
        "def f(a, b):\n    return a + b\n", encoding="utf-8"
    )
    report = build_coverage_report(repo)
    assert report.established
    assert "routes.py" in report.changed_files
    assert _cap(report, "sql_construction").status == CAP_CHECKED


def test_unparseable_python_makes_its_capabilities_unknown(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "broken.py").write_text("def f(a, b)\n    return a\n", encoding="utf-8")
    report = build_coverage_report(repo)
    assert _cap(report, "sql_construction").status == UNKNOWN


def test_go_file_makes_source_support_not_supported(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "main.go").write_text("package main\n", encoding="utf-8")
    report = build_coverage_report(repo)
    assert _cap(report, "source_analysis_support").status == NOT_SUPPORTED


def test_readme_only_change_establishes_an_empty_report(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    report = build_coverage_report(repo)
    assert report.established
    assert report.files == ()


def test_bad_ref_is_a_failure_not_an_empty_report(tmp_path: Path):
    repo = _repo(tmp_path)
    report = build_coverage_report(repo, base="origin/does-not-exist")
    assert not report.established
    assert report.failure
    assert report.files == ()


def test_format_names_the_failure_and_never_says_clean(tmp_path: Path):
    repo = _repo(tmp_path)
    report = build_coverage_report(repo, base="origin/does-not-exist")
    text = format_coverage_report(report)
    assert "could not" in text.lower()
    assert "clean" not in text.lower()
```

Create `tests/test_cli_coverage.py`:

```python
import subprocess
import sys
from pathlib import Path


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    )


def _repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "seed.py").write_text("x = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "base")
    return tmp_path


def _cli(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "cybergraph", "coverage", "--repo", str(repo), *args],
        capture_output=True, text=True,
    )


def test_coverage_command_exits_zero_on_a_clean_report(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "routes.py").write_text("def f(a):\n    return a\n", encoding="utf-8")
    result = _cli(repo)
    assert result.returncode == 0
    assert "routes.py" in result.stdout


def test_coverage_command_exits_nonzero_when_comparison_fails(tmp_path: Path):
    repo = _repo(tmp_path)
    result = _cli(repo, "--base", "origin/does-not-exist")
    assert result.returncode != 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_coverage_report.py tests/test_cli_coverage.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.coverage_report'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/coverage_report.py`:

```python
"""Compose the honesty primitives into one report, and render it.

This surface reports coverage; it makes no accept/block decision. A capability's
status here is derived from whether the files it covers were analyzable, never
from running its predicate -- that is the verdict layer's job (roadmap Tasks
15-17). ``CAP_CHECKED`` means only "the analyzer ran on the files in scope",
never "safe".
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.security.capability import (
    CAPABILITIES,
    NOT_APPLICABLE,
    NOT_SUPPORTED,
    UNKNOWN,
    label_for,
    relevance,
)
from cybergraph.security.coverage import (
    STATUS_FAILED,
    STATUS_UNSUPPORTED,
    FileCoverage,
    assess_coverage,
)
from cybergraph.security.revisions import resolve_revisions

CAP_CHECKED = "checked"


@dataclass(frozen=True)
class CapabilityCoverage:
    capability_id: str
    label: str
    status: str


@dataclass(frozen=True)
class CoverageReport:
    mode: str
    changed_files: tuple[str, ...]
    files: tuple[FileCoverage, ...]
    capabilities: tuple[CapabilityCoverage, ...]
    failure: str = ""

    @property
    def established(self) -> bool:
        return not self.failure


def _covered_file_failed(
    covers: tuple[str, ...], failed_paths: set[str]
) -> bool:
    return any(
        fnmatch(path, pattern) for path in failed_paths for pattern in covers
    )


def build_coverage_report(repo_root, base=None, mode=None) -> CoverageReport:
    repo_root = Path(repo_root).resolve()
    revisions = resolve_revisions(repo_root, base=base, mode=mode)
    if revisions.failure:
        return CoverageReport(revisions.mode, (), (), (), failure=revisions.failure)

    build_graph(repo_root)
    files = assess_coverage(repo_root, revisions.changed_files)
    rel = relevance(revisions.changed_files)

    failed_paths = {f.path for f in files if f.status == STATUS_FAILED}
    has_unsupported = any(f.status == STATUS_UNSUPPORTED for f in files)

    capabilities: list[CapabilityCoverage] = []
    for capability in CAPABILITIES:
        if not rel[capability.id]:
            status = NOT_APPLICABLE
        elif capability.id == "source_analysis_support":
            status = NOT_SUPPORTED if has_unsupported else CAP_CHECKED
        elif not capability.supported:
            status = NOT_SUPPORTED
        elif _covered_file_failed(capability.covers, failed_paths):
            status = UNKNOWN
        else:
            status = CAP_CHECKED
        capabilities.append(
            CapabilityCoverage(capability.id, label_for(capability.id), status)
        )

    return CoverageReport(
        revisions.mode, revisions.changed_files, files, tuple(capabilities)
    )


def format_coverage_report(report: CoverageReport) -> str:
    if not report.established:
        return (
            "Coverage could not be assessed: the comparison could not be "
            f"established.\n  {report.failure}"
        )

    lines = [f"Changed files: {len(report.changed_files)}"]
    for item in report.files:
        suffix = f" ({item.reason})" if item.reason else ""
        lines.append(f"  {item.path:<40} {item.status}{suffix}")

    shown = [c for c in report.capabilities if c.status != NOT_APPLICABLE]
    if shown:
        lines.append("")
        lines.append("Capabilities on this change:")
        for capability in shown:
            lines.append(f"  {capability.label:<40} {capability.status}")
    return "\n".join(lines)
```

Modify `src/cybergraph/cli.py`. Register the subparser alongside the others (near line 35–295):

```python
    coverage = sub.add_parser(
        "coverage",
        help="Report which changed files were analyzed and which checks are blind",
    )
    coverage.add_argument("--base", default=None, help="Git base ref for comparison")
    coverage.add_argument(
        "--mode", default=None, choices=["worktree", "merge_base", "range"],
        help="Comparison mode; inferred when omitted",
    )
    coverage.add_argument("--repo", default=".", help="Repository root")
```

Add the dispatch branch in the `elif args.command == ...` chain (near line 403–525):

```python
    elif args.command == "coverage":
        from .security.coverage_report import build_coverage_report, format_coverage_report

        report = build_coverage_report(
            Path(args.repo).resolve(), base=args.base, mode=args.mode
        )
        print(format_coverage_report(report))
        if not report.established:
            raise SystemExit(1)
```

**Note for the implementer:** confirm how `main()` returns/propagates exit status for other commands (read the dispatch chain around line 403–525 and the end of `main`). If commands there already return an int, return `1` instead of raising; if they raise `SystemExit`, keep the `raise SystemExit(1)` above. The required behaviour is fixed: a report that could not be established exits non-zero; a successful report — even with unsupported files — exits 0. Do not print the word "clean" on any path. `coverage` must NOT be added to the `read_commands` set that requires a pre-built graph (it builds its own graph).

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_coverage_report.py tests/test_cli_coverage.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/security/coverage_report.py src/cybergraph/cli.py tests/test_coverage_report.py tests/test_cli_coverage.py
git commit -m "feat(coverage): read-only cybergraph coverage surface that fails closed"
```

---

### Task 5: Seed the mutation harness with the fail-open regressions

**Files:**
- Modify: `benchmark/mutation_harness.py` (append to the `MUTATIONS: list[Mutation]` list, before its closing `]`)

**Interfaces:**
- Consumes: the existing `Mutation(id, disaster, file, old, new, tests, note, count)` frozen dataclass and `MUTATIONS` list in `benchmark/mutation_harness.py`.
- Produces: three new caught mutations covering the fail-open bugs this slice removes.

The harness restores a pristine `src/` clone per mutation, requires the mapped tests green on the clean clone, applies the `old → new` edit, and requires them red. A mutation with no test that fails under it reports UNCAUGHT — which is the signal we want. The `old` string must match the shipped source exactly (copy it from the file after Tasks 1–3 land).

- [ ] **Step 1: Add the three mutations**

Append to `MUTATIONS` in `benchmark/mutation_harness.py`:

```python
    # -- D2: "I could not look" must never read as "nothing to see" ----------
    Mutation(
        id="D2-revisions-failure-empty-not-flagged",
        disaster="D2",
        file="cybergraph/security/revisions.py",
        old='    ok, _ = _git(repo_root, "rev-parse", "--git-dir")\n'
        "    if not ok:\n"
        '        return Revisions(MODE_WORKTREE, "", "", (), failure="not a git repository")',
        new='    ok, _ = _git(repo_root, "rev-parse", "--git-dir")\n'
        "    if not ok:\n"
        '        return Revisions(MODE_WORKTREE, "", "", ())',
        tests=("tests/test_revisions.py::test_not_a_git_repository_is_a_failure",),
        note="a git failure must produce a failure string, never a silent empty diff",
    ),
    # -- D1: a file that never parsed must not read as clean -----------------
    Mutation(
        id="D1-coverage-failed-as-analyzed",
        disaster="D1",
        file="cybergraph/security/coverage.py",
        old='            results.append(FileCoverage(file, STATUS_FAILED, '
        '"the file could not be read"))',
        new='            results.append(FileCoverage(file, STATUS_ANALYZED, '
        '"the file could not be read"))',
        tests=("tests/test_coverage.py::test_unparseable_file_is_failed_not_clean",),
        note="a parse failure must be `failed`, not `analyzed`",
    ),
    # -- D1: general language blindness must stay represented ----------------
    Mutation(
        id="D1-capability-drops-source-support",
        disaster="D1",
        file="cybergraph/security/capability.py",
        old='    Capability("source_analysis_support",\n'
        '               "Languages CyberGraph can read", SOURCE_GLOBS, True),\n',
        new="",
        tests=("tests/test_capability.py::test_go_change_is_caught_by_general_source_support",),
        note="removing source_analysis_support makes a Go-only change match nothing",
    ),
```

- [ ] **Step 2: Run the harness to verify all three are caught**

Run: `python benchmark/mutation_harness.py`
Expected: every mutation reports `CAUGHT`, including the three new ids; exit 0. If any of the three reports `UNCAUGHT`, the `old` string did not match the shipped source — copy it verbatim from the file and retry.

- [ ] **Step 3: Run the full suite and gate**

Run:
```
python -m pytest -q
python -m ruff check src tests
python benchmark/run_precision.py
```
Expected: suite green; ruff clean; `GATE PASSED` exit 0. `run_eval.py` unchanged at 1.0/1.0/1.0.

- [ ] **Step 4: Commit**

```bash
git add benchmark/mutation_harness.py
git commit -m "test(harness): seed the coverage-honesty fail-open mutations"
```

---

## Notes for the executor

- Tasks 1, 2, 3 are independent (1 and 2 have no cross-dependency; 3 consumes 1). Task 4 consumes 1–3. Task 5 consumes 1–3 and must run last so the `old` strings match shipped source.
- Follow the parent slice's discipline: a fresh implementer per task, an adversarial review between tasks, and — most important here — verify every new test goes **red** under the mutation it guards before trusting it. The mutation harness in Task 5 makes that check runnable rather than manual.
- Nothing in this slice makes an ACCEPT/REVIEW/BLOCK decision. If a task starts to, it has left scope — stop and confirm.

# Temporal Analysis (persistence + delta) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist a lightweight, line-stable snapshot of findings on every build/scan/analyze and report what is new / fixed / regressed / persisting since the previous scan.

**Architecture:** Three additive history tables (+ a `meta` version table) live in the existing `graph.db` via `CREATE TABLE IF NOT EXISTS` and are never touched by `clear_for_rebuild`, so history survives rebuilds with zero migration code. A new `history.py` fingerprints findings (`sha1(rule|tool|file|message)`, line-independent), records scans, and computes deltas; the CLI records at the `build`/`scan`/`analyze` handlers and adds a `history` command.

**Tech Stack:** Python 3.10+ stdlib only (`sqlite3`, `hashlib`, `datetime`, `subprocess`); pytest.

## Global Constraints

- Branch off `feat/usability-core`; work on `feat/temporal-analysis`.
- No new dependencies. Additive & non-breaking: existing tables, commands, and the suite untouched.
- History tables must survive `clear_for_rebuild` (they are simply never referenced by it).
- Finding identity is line-independent: `fingerprint = sha1("{rule_id}|{tool}|{file_path}|{message}")`.
- Recording happens at the CLI `build`/`scan`/`analyze` handlers ONLY — never inside `build_graph` (so tests and internal rebuilds write no history).
- `record_scan` never re-runs analysis: `analyze` passes the top risk it already computed; `build`/`scan` store 0.
- `record_scan` is best-effort: a failure prints a warning and never changes the command's exit code.
- Timestamps are ISO-8601 UTC (`datetime.now(timezone.utc).isoformat()`); git info is best-effort (non-git → empty SHA, no crash).
- Commits authored as the user only — **no `Co-Authored-By` / Claude trailer**; no `--no-verify`.
- Tests: `PYTHONPATH=src python -m pytest -q`; baseline is **204 passed** on `feat/usability-core`; must stay green.
- Reuse existing symbols: `cybergraph.graph.GraphStore.open_for_repo(repo)` (has `.conn`, `.counts()`, `.clear_for_rebuild()`, `.add_findings()`); `cybergraph.graph.Finding`; `cybergraph.build.build_graph`, `scan_repo`; `cybergraph.security.investigate.collect_top_risks(repo, limit=10)` where `TopRisk(risk_score:int, risk_label:str, ...)`.

## File Structure

- Modify `src/cybergraph/graph/store.py` — add `meta`/`scans`/`scan_findings`/`finding_history` to `SCHEMA`; seed `schema_version`.
- Create `src/cybergraph/history.py` — `fingerprint`, `ScanResult`, `record_scan`, `scan_delta`, `list_scans`, formatters, `_git_head`.
- Modify `src/cybergraph/cli.py` — `history` command; record hooks in `build`/`scan`/`analyze`; `Δ since last scan` line.
- Modify `README.md`, `docs/architecture.md`.
- Tests: `tests/test_history_schema.py`, `tests/test_history_record.py`, `tests/test_history_delta.py`, `tests/test_cli_history.py`.

---

### Task 1: History tables + schema version (`store.py`)

**Files:**
- Modify: `src/cybergraph/graph/store.py` (append tables to `SCHEMA`; seed `meta` in `__init__`)
- Test: `tests/test_history_schema.py`

**Interfaces:**
- Produces: four tables (`meta`, `scans`, `scan_findings`, `finding_history`) present on store open; `meta.schema_version` seeded; tables untouched by `clear_for_rebuild`/`clear`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_history_schema.py
from pathlib import Path

from cybergraph.graph import GraphStore, Finding


def test_history_tables_exist_and_version_seeded(tmp_path: Path):
    store = GraphStore.open_for_repo(tmp_path)
    try:
        names = {r["name"] for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"meta", "scans", "scan_findings", "finding_history"} <= names
        ver = store.conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        assert ver is not None and ver["value"] == "2"
    finally:
        store.close()


def test_history_tables_survive_clear_for_rebuild(tmp_path: Path):
    store = GraphStore.open_for_repo(tmp_path)
    try:
        store.conn.execute("INSERT INTO scans(ts) VALUES ('2026-01-01T00:00:00+00:00')")
        store.conn.commit()
        store.clear_for_rebuild()
        assert store.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
    finally:
        store.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_history_schema.py -v`
Expected: FAIL — `sqlite3.OperationalError: no such table: meta` (or the `<=` assertion fails).

- [ ] **Step 3: Write minimal implementation**

In `store.py`, append the four tables to the end of the `SCHEMA` string (before the closing `"""`), after the existing `CREATE INDEX` lines:

```python
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    git_sha TEXT DEFAULT '',
    git_branch TEXT DEFAULT '',
    node_count INTEGER DEFAULT 0,
    edge_count INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    top_risk_score INTEGER DEFAULT 0,
    top_risk_label TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scan_findings (
    scan_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (scan_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS finding_history (
    fingerprint TEXT PRIMARY KEY,
    rule_id TEXT DEFAULT '',
    tool TEXT DEFAULT '',
    file_path TEXT DEFAULT '',
    severity TEXT DEFAULT '',
    message TEXT DEFAULT '',
    line_start INTEGER DEFAULT 0,
    first_seen_scan INTEGER DEFAULT 0,
    last_seen_scan INTEGER DEFAULT 0,
    first_seen_ts TEXT DEFAULT '',
    last_seen_ts TEXT DEFAULT '',
    fixed_ts TEXT DEFAULT '',
    status TEXT DEFAULT 'open',
    reopened_count INTEGER DEFAULT 0
);
```

In `GraphStore.__init__`, after `self.conn.executescript(SCHEMA)`, seed the version idempotently:

```python
        self.conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '2')"
        )
        self.conn.commit()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_history_schema.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/graph/store.py tests/test_history_schema.py
git commit -m "feat(store): add history tables (scans/scan_findings/finding_history) and schema_version"
```

---

### Task 2: Finding fingerprint (`history.py`)

**Files:**
- Create: `src/cybergraph/history.py`
- Test: `tests/test_history_record.py` (fingerprint portion)

**Interfaces:**
- Produces: `fingerprint(rule_id: str, tool: str, file_path: str, message: str) -> str`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_history_record.py
from cybergraph.history import fingerprint


def test_fingerprint_is_line_independent_and_tool_sensitive():
    a = fingerprint("CG-SINK", "cybergraph", "app.py", "reaches sink `db.execute`")
    b = fingerprint("CG-SINK", "cybergraph", "app.py", "reaches sink `db.execute`")
    assert a == b and len(a) == 40  # sha1 hex, stable regardless of line
    # different tool -> different identity (distinct evidence sources)
    assert fingerprint("CG-SINK", "semgrep", "app.py", "reaches sink `db.execute`") != a
    # different file -> different identity
    assert fingerprint("CG-SINK", "cybergraph", "other.py", "reaches sink `db.execute`") != a
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_history_record.py::test_fingerprint_is_line_independent_and_tool_sensitive -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.history'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/cybergraph/history.py
"""Persist finding snapshots and compute what changed between scans."""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cybergraph.graph import GraphStore


def fingerprint(rule_id: str, tool: str, file_path: str, message: str) -> str:
    """Line-independent identity for a finding across scans."""
    raw = f"{rule_id}|{tool}|{file_path}|{message}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_history_record.py::test_fingerprint_is_line_independent_and_tool_sensitive -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/history.py tests/test_history_record.py
git commit -m "feat(history): add line-independent finding fingerprint"
```

---

### Task 3: Record a scan with new/fixed/regressed transitions (`history.py`)

**Files:**
- Modify: `src/cybergraph/history.py`
- Test: `tests/test_history_record.py`

**Interfaces:**
- Consumes: `fingerprint` (Task 2); `GraphStore`, `collect_top_risks`.
- Produces: `@dataclass ScanResult(scan_id:int, no_change:bool, is_first:bool, new:list[str], fixed:list[str], regressed:list[str], persisting:list[str])`; `record_scan(repo_root, *, top_risk_score: int = 0, top_risk_label: str = "") -> ScanResult`; `_git_head(repo_root) -> tuple[str, str]`.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_history_record.py
from pathlib import Path

from cybergraph.graph import GraphStore, Finding
from cybergraph.history import record_scan


def _add_finding(repo: Path, *, rule="CG-SINK", msg="reaches sink `x`", line=3):
    store = GraphStore.open_for_repo(repo)
    try:
        store.add_findings([Finding(rule_id=rule, severity="high", message=msg,
                                    file_path="app.py", line_start=line)])
    finally:
        store.close()


def _clear_findings(repo: Path):
    store = GraphStore.open_for_repo(repo)
    try:
        store.clear_for_rebuild()  # deletes tool='cybergraph' findings; keeps history tables
    finally:
        store.close()


def test_first_scan_marks_all_new(tmp_path: Path):
    _add_finding(tmp_path)
    r = record_scan(tmp_path)
    assert r.is_first is True and len(r.new) == 1 and r.fixed == [] and r.regressed == []


def test_removed_finding_becomes_fixed(tmp_path: Path):
    _add_finding(tmp_path)
    record_scan(tmp_path)
    _clear_findings(tmp_path)
    r = record_scan(tmp_path)
    assert len(r.fixed) == 1 and r.new == [] and r.is_first is False


def test_reappearing_finding_is_regressed(tmp_path: Path):
    _add_finding(tmp_path)
    record_scan(tmp_path)
    _clear_findings(tmp_path)
    record_scan(tmp_path)          # now fixed
    _add_finding(tmp_path)
    r = record_scan(tmp_path)      # back again
    assert len(r.regressed) == 1 and r.new == []
    store = GraphStore.open_for_repo(tmp_path)
    try:
        row = store.conn.execute(
            "SELECT status, reopened_count, fixed_ts FROM finding_history").fetchone()
        assert row["status"] == "open" and row["reopened_count"] == 1 and row["fixed_ts"] == ""
    finally:
        store.close()


def test_unchanged_rerun_is_no_change_without_new_scan_row(tmp_path: Path):
    _add_finding(tmp_path)
    record_scan(tmp_path)
    r = record_scan(tmp_path)      # identical set, same (empty) sha
    assert r.no_change is True and r.new == [] and r.fixed == []
    store = GraphStore.open_for_repo(tmp_path)
    try:
        assert store.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
    finally:
        store.close()


def test_non_git_repo_records_without_crashing(tmp_path: Path):
    _add_finding(tmp_path)
    r = record_scan(tmp_path)      # tmp_path is not a git repo
    assert r.is_first is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_history_record.py -v`
Expected: FAIL — `cannot import name 'record_scan'`

- [ ] **Step 3: Write minimal implementation**

Append to `src/cybergraph/history.py`:

```python
@dataclass
class ScanResult:
    scan_id: int
    no_change: bool
    is_first: bool
    new: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    regressed: list[str] = field(default_factory=list)
    persisting: list[str] = field(default_factory=list)


def _git_head(repo_root: Path) -> tuple[str, str]:
    def _run(args: list[str]) -> str:
        try:
            out = subprocess.run(
                ["git", "-C", str(repo_root), *args],
                capture_output=True, text=True, timeout=5,
            )
            return out.stdout.strip() if out.returncode == 0 else ""
        except Exception:
            return ""
    sha = _run(["rev-parse", "HEAD"])
    branch = _run(["rev-parse", "--abbrev-ref", "HEAD"]) if sha else ""
    return sha, branch


def record_scan(repo_root: Path, *, top_risk_score: int = 0, top_risk_label: str = "") -> ScanResult:
    repo_root = Path(repo_root).resolve()
    store = GraphStore.open_for_repo(repo_root)
    conn = store.conn
    ts = datetime.now(timezone.utc).isoformat()
    sha, branch = _git_head(repo_root)
    try:
        current: dict[str, dict] = {}
        for r in conn.execute(
            "SELECT rule_id, tool, file_path, message, severity, line_start FROM findings"
        ):
            fp = fingerprint(r["rule_id"], r["tool"], r["file_path"], r["message"])
            current[fp] = dict(r)
        current_set = set(current)

        prev = conn.execute("SELECT id, git_sha FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        is_first = prev is None
        prev_set: set[str] = set()
        if prev is not None:
            prev_set = {row["fingerprint"] for row in conn.execute(
                "SELECT fingerprint FROM scan_findings WHERE scan_id = ?", (prev["id"],))}

        # No-change shortcut: identical set + same SHA -> touch last_seen, no new row.
        if prev is not None and current_set == prev_set and (prev["git_sha"] or "") == sha:
            with conn:
                conn.executemany(
                    "UPDATE finding_history SET last_seen_ts = ? WHERE fingerprint = ?",
                    [(ts, fp) for fp in current_set],
                )
            return ScanResult(prev["id"], no_change=True, is_first=False,
                              persisting=sorted(current_set))

        counts = store.counts()
        new: list[str] = []
        regressed: list[str] = []
        persisting: list[str] = []
        fixed: list[str] = []
        with conn:
            cur = conn.execute(
                "INSERT INTO scans(ts, git_sha, git_branch, node_count, edge_count, "
                "finding_count, top_risk_score, top_risk_label) VALUES (?,?,?,?,?,?,?,?)",
                (ts, sha, branch, counts["nodes"], counts["edges"], counts["findings"],
                 top_risk_score, top_risk_label),
            )
            scan_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO scan_findings(scan_id, fingerprint) VALUES (?, ?)",
                [(scan_id, fp) for fp in current_set],
            )
            for fp in current_set:
                r = current[fp]
                existing = conn.execute(
                    "SELECT status FROM finding_history WHERE fingerprint = ?", (fp,)).fetchone()
                if existing is None:
                    conn.execute(
                        "INSERT INTO finding_history(fingerprint, rule_id, tool, file_path, "
                        "severity, message, line_start, first_seen_scan, last_seen_scan, "
                        "first_seen_ts, last_seen_ts, status, reopened_count) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?, 'open', 0)",
                        (fp, r["rule_id"], r["tool"], r["file_path"], r["severity"],
                         r["message"], r["line_start"], scan_id, scan_id, ts, ts),
                    )
                    new.append(fp)
                elif existing["status"] == "fixed":
                    conn.execute(
                        "UPDATE finding_history SET status='open', fixed_ts='', "
                        "reopened_count = reopened_count + 1, last_seen_scan = ?, "
                        "last_seen_ts = ? WHERE fingerprint = ?", (scan_id, ts, fp))
                    regressed.append(fp)
                else:
                    conn.execute(
                        "UPDATE finding_history SET last_seen_scan = ?, last_seen_ts = ? "
                        "WHERE fingerprint = ?", (scan_id, ts, fp))
                    persisting.append(fp)
            for row in conn.execute(
                "SELECT fingerprint FROM finding_history WHERE status = 'open'").fetchall():
                fp = row["fingerprint"]
                if fp not in current_set:
                    conn.execute(
                        "UPDATE finding_history SET status='fixed', fixed_ts = ? "
                        "WHERE fingerprint = ?", (ts, fp))
                    fixed.append(fp)
        return ScanResult(scan_id, no_change=False, is_first=is_first,
                          new=sorted(new), fixed=sorted(fixed),
                          regressed=sorted(regressed), persisting=sorted(persisting))
    finally:
        store.close()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_history_record.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/history.py tests/test_history_record.py
git commit -m "feat(history): record_scan with new/fixed/regressed transitions"
```

---

### Task 4: Delta, listing, and formatters (`history.py`)

**Files:**
- Modify: `src/cybergraph/history.py`
- Test: `tests/test_history_delta.py`

**Interfaces:**
- Consumes: `record_scan` (Task 3).
- Produces: `@dataclass Delta(is_first:bool, new:list[str], fixed:list[str], regressed:list[str], persisting:list[str])`; `scan_delta(repo_root) -> Delta`; `list_scans(repo_root, limit: int = 20) -> list[dict]`; `format_delta_line(d: Delta) -> str`; `format_history(rows: list[dict], delta: Delta) -> str`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_history_delta.py
from pathlib import Path

from cybergraph.graph import GraphStore, Finding
from cybergraph.history import list_scans, record_scan, scan_delta, format_delta_line


def _set_findings(repo: Path, msgs: list[str]):
    store = GraphStore.open_for_repo(repo)
    try:
        store.clear_for_rebuild()
        store.add_findings([Finding(rule_id="CG-SINK", severity="high", message=m,
                                    file_path="app.py", line_start=1) for m in msgs])
    finally:
        store.close()


def test_scan_delta_between_two_scans(tmp_path: Path):
    _set_findings(tmp_path, ["a", "b"])
    record_scan(tmp_path)
    _set_findings(tmp_path, ["b", "c"])   # a removed, c added, b persists
    record_scan(tmp_path)
    d = scan_delta(tmp_path)
    assert d.is_first is False
    assert len(d.new) == 1 and len(d.fixed) == 1 and len(d.persisting) == 1


def test_delta_on_first_scan_is_all_new(tmp_path: Path):
    _set_findings(tmp_path, ["a"])
    record_scan(tmp_path)
    d = scan_delta(tmp_path)
    assert d.is_first is True and len(d.new) == 1


def test_list_scans_and_format(tmp_path: Path):
    _set_findings(tmp_path, ["a"])
    record_scan(tmp_path)
    rows = list_scans(tmp_path)
    assert len(rows) == 1 and "finding_count" in rows[0]
    line = format_delta_line(scan_delta(tmp_path))
    assert "new" in line
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_history_delta.py -v`
Expected: FAIL — `cannot import name 'scan_delta'`

- [ ] **Step 3: Write minimal implementation**

Append to `src/cybergraph/history.py`:

```python
@dataclass
class Delta:
    is_first: bool
    new: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    regressed: list[str] = field(default_factory=list)
    persisting: list[str] = field(default_factory=list)


def scan_delta(repo_root: Path) -> Delta:
    """Change between the two most recent scans (from stored membership)."""
    store = GraphStore.open_for_repo(Path(repo_root).resolve())
    conn = store.conn
    try:
        scans = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 2").fetchall()
        if not scans:
            return Delta(is_first=True)
        curr = scans[0]["id"]
        curr_set = {r["fingerprint"] for r in conn.execute(
            "SELECT fingerprint FROM scan_findings WHERE scan_id = ?", (curr,))}
        if len(scans) == 1:
            return Delta(is_first=True, new=sorted(curr_set))
        prev = scans[1]["id"]
        prev_set = {r["fingerprint"] for r in conn.execute(
            "SELECT fingerprint FROM scan_findings WHERE scan_id = ?", (prev,))}
        appeared = curr_set - prev_set
        fixed = sorted(prev_set - curr_set)
        persisting = sorted(curr_set & prev_set)
        # appeared before this scan's predecessor -> regression; else genuinely new.
        regressed, new = [], []
        for fp in sorted(appeared):
            row = conn.execute(
                "SELECT first_seen_scan FROM finding_history WHERE fingerprint = ?", (fp,)).fetchone()
            if row is not None and row["first_seen_scan"] < curr:
                regressed.append(fp)
            else:
                new.append(fp)
        return Delta(is_first=False, new=new, fixed=fixed, regressed=regressed, persisting=persisting)
    finally:
        store.close()


def list_scans(repo_root: Path, limit: int = 20) -> list[dict]:
    store = GraphStore.open_for_repo(Path(repo_root).resolve())
    try:
        return [dict(r) for r in store.conn.execute(
            "SELECT id, ts, git_sha, git_branch, node_count, edge_count, finding_count, "
            "top_risk_score, top_risk_label FROM scans ORDER BY id DESC LIMIT ?", (limit,))]
    finally:
        store.close()


def format_delta_line(d: Delta) -> str:
    return f"+{len(d.new)} new, -{len(d.fixed)} fixed, {len(d.regressed)} regressed"


def format_history(rows: list[dict], delta: Delta) -> str:
    if not rows:
        return "No scan history yet. Run 'cybergraph analyze' or 'build' to record one."
    lines = [f"Scan history ({len(rows)} most recent):"]
    for r in rows:
        sha = (r["git_sha"] or "")[:7] or "-"
        lines.append(
            f"  #{r['id']} {r['ts']} [{sha}] "
            f"findings={r['finding_count']} nodes={r['node_count']}"
        )
    if not delta.is_first:
        lines.append(f"Since previous scan: {format_delta_line(delta)}.")
    return "\n".join(lines)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_history_delta.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/history.py tests/test_history_delta.py
git commit -m "feat(history): scan_delta, list_scans, and formatters"
```

---

### Task 5: CLI `history` command + record hooks + analyze delta line (`cli.py`)

**Files:**
- Modify: `src/cybergraph/cli.py`
- Test: `tests/test_cli_history.py`

**Interfaces:**
- Consumes: `record_scan`, `scan_delta`, `list_scans`, `format_history`, `format_delta_line`.
- Produces: CLI command `history [repo] [--limit N]`; recording after `build`/`scan`/`analyze`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli_history.py
from pathlib import Path

from cybergraph.cli import main


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/users')\n"
        "def list_users(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    return repo


def test_history_command_lists_scans(tmp_path, capsys):
    repo = _repo(tmp_path)
    assert main(["build", str(repo)]) == 0     # records scan #1
    capsys.readouterr()
    code = main(["history", str(repo)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Scan history" in out and "#1" in out


def test_analyze_prints_delta_on_second_run(tmp_path, capsys):
    repo = _repo(tmp_path)
    main(["analyze", str(repo), "--no-color", "--no-report"])   # scan #1 (first)
    capsys.readouterr()
    # edit so the finding set changes, forcing a new scan row
    (repo / "app.py").write_text("def safe():\n    return 1\n", encoding="utf-8")
    main(["analyze", str(repo), "--no-color", "--no-report"])   # scan #2
    out = capsys.readouterr().out
    assert "since last scan" in out.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli_history.py -v`
Expected: FAIL — `invalid choice: 'history'` (and the analyze test has no delta line).

- [ ] **Step 3: Write minimal implementation**

In `build_parser`, before `return parser`, add:

```python
    history = sub.add_parser("history", help="Show recorded scan history and changes since last scan")
    history.add_argument("repo", nargs="?", default=".", help="Repository root")
    history.add_argument("--limit", type=int, default=20, help="Maximum scans to list")
```

Add a module-level helper near the other `_*` helpers in `cli.py`:

```python
def _record_history(repo: Path, *, top_risk_score: int = 0, top_risk_label: str = "", quiet: bool = False):
    """Best-effort scan recording; never fails the calling command.

    ``quiet=True`` (used by ``analyze --json``) suppresses the on-error warning so
    it can never corrupt machine-readable stdout."""
    try:
        from .history import record_scan

        return record_scan(repo, top_risk_score=top_risk_score, top_risk_label=top_risk_label)
    except Exception as exc:  # history is a side benefit, not a hard requirement
        if not quiet:
            print(f"(history not recorded: {exc})")
        return None
```

In `main`, in the `build` branch, after its two `print(...)` lines add:

```python
        _record_history(repo)
```

In the `scan` branch, after its `print(...)` lines add the same line:

```python
        _record_history(repo)
```

In the `analyze` branch, record and print the delta. Add this block at the **very end of the `elif args.command == "analyze":` block — OUTSIDE the existing `if args.json: … else: …`** so it runs in both JSON and text modes (recording always happens; the delta line prints only in text mode):

```python
        top = result.top_risks[0] if result.top_risks else None
        hist = _record_history(
            repo,
            top_risk_score=(top.risk_score if top else 0),
            top_risk_label=(top.risk_label if top else ""),
            quiet=args.json,
        )
        if not args.json and hist is not None and not hist.is_first:
            print(f"Δ since last scan: +{len(hist.new)} new, -{len(hist.fixed)} fixed, "
                  f"{len(hist.regressed)} regressed")
```

Place this block at the END of the `analyze` branch (after the report line), so JSON output stays pure JSON (the delta prints only in text mode).

Add the `history` dispatch branch in `main`:

```python
    elif args.command == "history":
        from .history import format_history, list_scans, scan_delta

        rows = list_scans(repo, limit=args.limit)
        print(format_history(rows, scan_delta(repo)))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli_history.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/cli.py tests/test_cli_history.py
git commit -m "feat(cli): record scan history on build/scan/analyze and add 'history' command"
```

---

### Task 6: Full-suite verification + docs

**Files:**
- Modify: `README.md`, `docs/architecture.md`

- [ ] **Step 1: Run the full suite**

Run: `PYTHONPATH=src python -m pytest -q`
Expected: prior tests plus the new ones PASS (target ≈ 220 passed), no regressions.

- [ ] **Step 2: End-to-end smoke**

Run: `python -c "import sys; from cybergraph.cli import main; main(['build','examples/vulnerable-fastapi']); main(['history','examples/vulnerable-fastapi'])"`
Expected: prints a "Scan history (1 most recent):" block with `#1` and a finding count.

- [ ] **Step 3: Update docs**

In `README.md` Quick start, add:
```
cybergraph history .          # what's new / fixed / regressed since the last scan
```
In `docs/architecture.md`, append under "Pipeline": `8. Every build/scan/analyze records a line-stable snapshot of findings; 'history' reports new/fixed/regressed since the previous scan (history tables survive rebuilds).`

- [ ] **Step 4: Commit**

```bash
git add README.md docs/architecture.md
git commit -m "docs: document scan history and the 'history' command"
```

---

## Self-Review

**Spec coverage:**
- New tables (`meta`/`scans`/`scan_findings`/`finding_history`) + schema_version, surviving `clear_for_rebuild` → Task 1. ✓
- Line-independent fingerprint incl. `tool` → Task 2. ✓
- `record_scan` new/fixed/regressed/no-change, timestamps, `fixed_ts`/`reopened_count`, best-effort git → Task 3. ✓
- `scan_delta` (new vs regressed distinguished), `list_scans`, formatters → Task 4. ✓
- CLI-only recording (build/scan/analyze), `Δ since last scan` line (text only), `history` command → Task 5. ✓
- `record_scan` does not re-run analysis (analyze passes top risk; build/scan pass 0) → Task 3 signature + Task 5 wiring. ✓
- Best-effort recording never changes exit code → Task 5 `_record_history` try/except. ✓
- Testing (fingerprint, transitions, delta, survives rebuild, non-git, CLI) → each task + Task 6. ✓

**Placeholder scan:** none — every code step has complete code; every test step has complete assertions.

**Type consistency:** `fingerprint(rule_id, tool, file_path, message)` used identically in Tasks 2/3; `ScanResult` fields (`is_first`, `new`, `fixed`, `regressed`, `no_change`) match Task 5's use (`hist.is_first`, `hist.new`, …); `record_scan(repo, *, top_risk_score, top_risk_label)` signature matches Task 5's call; `Delta`/`scan_delta`/`list_scans`/`format_history` names match Task 5's imports. `schema_version` value `'2'` consistent between Task 1 impl and test. ✓

**Critical-review fixes folded in:** `tool` in the fingerprint; no-change bumps `last_seen_ts` (non-lossy); `fixed_ts`/`reopened_count`/timestamps written now for the future trends slice; `meta` version anchor; regression = reappearance of a `fixed` fingerprint; first-scan and non-git handled; recording is CLI-only and best-effort; `record_scan` never re-runs analysis.

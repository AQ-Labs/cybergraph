# Config Posture (Declarative Trio) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect three declarative-config exposures — an open Firebase rule, a Supabase table with row-level security off, a public storage bucket — and make a change that weakens one return REVIEW from `cybergraph check` (so the client hooks catch it), never a silent ACCEPT and never a false alarm on a config it could not parse.

**Architecture:** Three new lightweight analyzers (`firebase_rules.py`, `supabase_rls.py`, `bucket_policy.py`) modeled on `terraform.py` — regex/`json`, stdlib only, always a File node, findings carry a CWE + verbatim evidence and honor inline suppressions. They register in `analysis/registry.py` and are recognized by scoped path/name heuristics in `analysis/collector.py`. Then the deliberately-placeholder `cloud_configuration` capability is activated: `supported=True`, its `covers` and `assess_coverage` both keyed on a new `CONFIG_GLOBS` (one source of truth), and `_FINDING_RULES` maps it to a *set* of rule ids (the trio + Terraform's existing `CG-IAC-*`) so a posture regression on a changed config file → FAIL → REVIEW.

**Tech Stack:** Python 3.10–3.13, standard library only (`re`, `json`, `pathlib`, `fnmatch`). Existing `graph.Finding/Node/Edge`, `suppressions.is_inline_suppressed`, the analyzer registry, the capability/coverage machinery, `security/checks.py`.

## Global Constraints

- **Zero runtime dependencies** (`dependencies = []`); standard library only. No HCL/YAML/SQL parser dependency — regex/`json` like the existing lightweight analyzers.
- Python 3.10–3.13. `from __future__ import annotations` as the first line of every new `.py` file.
- Ruff line-length 100; run `ruff check` on every touched file; it must be clean (fix unused imports/vars too).
- No network; no API keys on any default path.
- **Precision over recall.** A verification tool's false alarm is worse than a miss: an analyzer emits a finding only on a definite insecure signal, and matches config files *narrowly* — never "every `.sql`/`.json` in the repo."
- **Coverage honesty.** A changed in-scope config file that could not be parsed must read UNKNOWN, never PASS. Malformed JSON must reach the registry's per-file containment (raise, don't swallow).
- Analyzer contract: `analyze_X_file(path, repo_root, ...) -> (nodes, edges, findings)`; always emit a `File` node; never raise except the contained `OSError/ValueError/RecursionError`.
- Commits authored `Laraib <lxh417bham@gmail.com>` only (repo-local git config already carries it — do **not** pass `-c user.email=`); no `Co-Authored-By`, no AI attribution. Many small commits; never squash. Push only to `https://github.com/AQ-Labs/cybergraph`.

---

## File Structure

- `src/cybergraph/analysis/firebase_rules.py` (create) — Firebase security-rules analyzer.
- `src/cybergraph/analysis/supabase_rls.py` (create) — Supabase SQL-migration RLS analyzer.
- `src/cybergraph/analysis/bucket_policy.py` (create) — standalone S3/GCS bucket-policy analyzer.
- `src/cybergraph/analysis/collector.py` (modify) — recognize the new config files (scoped helpers).
- `src/cybergraph/analysis/registry.py` (modify) — dispatch the three analyzers.
- `src/cybergraph/security/capability.py` (modify) — `CONFIG_GLOBS`; `cloud_configuration` → supported, `covers=CONFIG_GLOBS`.
- `src/cybergraph/security/coverage.py` (modify) — track `CONFIG_GLOBS` files as verified sources.
- `src/cybergraph/security/checks.py` (modify) — `_FINDING_RULES` value → set; generic branch matches membership.
- Tests: `tests/test_firebase_rules.py`, `tests/test_supabase_rls.py`, `tests/test_bucket_policy.py`, `tests/test_config_posture_capability.py` (create); edits to `tests/test_capability.py`, `tests/test_checks.py`, `tests/test_coverage_report.py` (flip `cloud_configuration` NOT_SUPPORTED expectations).
- `benchmark/mutation_harness.py` (modify) — two seeded config fail-opens.
- `README.md` (modify) — one line noting config-posture coverage.

---

## Task 1: Firebase rules analyzer

**Files:**
- Create: `src/cybergraph/analysis/firebase_rules.py`
- Modify: `src/cybergraph/analysis/collector.py` (recognize `*.rules` and `firebase.json`)
- Modify: `src/cybergraph/analysis/registry.py` (dispatch)
- Test: `tests/test_firebase_rules.py` (create)

**Interfaces:**
- Produces: `analyze_firebase_rules_file(path: Path, repo_root: Path) -> tuple[list[Node], list[Edge], list[Finding]]`. Rule id **`CG-FIREBASE-RULES-OPEN`**, severity `high`, CWE-732.
- Consumes: `graph.Node/Edge/Finding`, `suppressions.is_inline_suppressed`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_firebase_rules.py`:

```python
from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.firebase_rules import analyze_firebase_rules_file

OPEN = """rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{uid} {
      allow read, write: if true;
    }
  }
}
"""

GUARDED = """rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{uid} {
      allow read, write: if request.auth != null;
    }
  }
}
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_open_rule_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, "firestore.rules", OPEN)
    nodes, _edges, findings = analyze_firebase_rules_file(p, tmp_path)
    assert any(n.kind == "File" for n in nodes)
    assert [f.rule_id for f in findings] == ["CG-FIREBASE-RULES-OPEN"]
    f = findings[0]
    assert f.cwe == "CWE-732"
    assert "if true" in f.evidence


def test_guarded_rule_is_clean(tmp_path: Path) -> None:
    p = _write(tmp_path, "firestore.rules", GUARDED)
    nodes, _edges, findings = analyze_firebase_rules_file(p, tmp_path)
    assert findings == []
    assert any(n.kind == "File" for n in nodes)


def test_inline_suppression_respected(tmp_path: Path) -> None:
    text = OPEN.replace("if true;", "if true; // cybergraph:ignore CG-FIREBASE-RULES-OPEN")
    p = _write(tmp_path, "firestore.rules", text)
    _nodes, _edges, findings = analyze_firebase_rules_file(p, tmp_path)
    assert findings == []
```

> Note: confirm the exact inline-suppression token by reading `src/cybergraph/suppressions.py` before writing the suppression test; use whatever `is_inline_suppressed` actually recognizes.

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_firebase_rules.py -v` — Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement the analyzer**

Create `src/cybergraph/analysis/firebase_rules.py`:

```python
"""Firebase security-rules analyzer (firestore.rules / storage.rules).

Regex-based, no dependency. Flags an ``allow`` whose condition is
unconditionally true -- the classic "open to the whole internet" rule. A rule
guarded by any real condition (``request.auth != null``, a function call, a
comparison) produces no finding. Conservative: only a literal-true condition is
flagged, and the file always yields a File node so the build never crashes.
"""

from __future__ import annotations

import re
from pathlib import Path

from cybergraph.graph import Edge, Finding, Node
from cybergraph.suppressions import is_inline_suppressed

# allow <ops> : if <condition> ;   -- capture the condition up to the semicolon.
ALLOW_RE = re.compile(
    r"allow\s+(?P<ops>[a-z, \t]+?)\s*:\s*if\s+(?P<cond>[^;{]+);",
    re.IGNORECASE,
)
# An unconditionally-true condition: `true`, `(true)`, `true == true`, etc.
_TRUE_RE = re.compile(r"^\(*\s*true\s*\)*$", re.IGNORECASE)


def analyze_firebase_rules_file(
    path: Path, repo_root: Path
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()
    rel = path.relative_to(repo_root).as_posix()
    nodes: list[Node] = [
        Node("File", rel, rel, rel, 1, len(lines), {"language": "firebase-rules"})
    ]
    findings: list[Finding] = []

    for match in ALLOW_RE.finditer(source):
        cond = match.group("cond").strip()
        if not _TRUE_RE.match(cond):
            continue
        line_no = source.count("\n", 0, match.start()) + 1
        if is_inline_suppressed(lines, line_no, "CG-FIREBASE-RULES-OPEN"):
            continue
        ops = " ".join(match.group("ops").split())
        findings.append(
            Finding(
                rule_id="CG-FIREBASE-RULES-OPEN",
                severity="high",
                message=f"Firebase rule grants `{ops}` to everyone (condition is always true)",
                file_path=rel,
                line_start=line_no,
                cwe="CWE-732",
                evidence=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "",
            )
        )
    return nodes, [], findings
```

- [ ] **Step 4: Recognize the files in the collector**

In `src/cybergraph/analysis/collector.py`, add `".rules"` to `SUPPORTED_SUFFIXES` and `"firebase.json"` to `SUPPORTED_FILENAMES`.

- [ ] **Step 5: Dispatch in the registry**

In `src/cybergraph/analysis/registry.py`: import `analyze_firebase_rules_file`; add a `FIREBASE_SUFFIXES = {".rules"}` and, in `_dispatch`, before the fallback:

```python
    if suffix in FIREBASE_SUFFIXES or path.name == "firebase.json":
        return analyze_firebase_rules_file(path, repo_root)
```

Add `".rules"` to `ANALYZED_SUFFIXES`.

- [ ] **Step 6: Run tests + ruff**

Run: `pytest tests/test_firebase_rules.py -v` — Expected: PASS.
Run: `ruff check src/cybergraph/analysis/firebase_rules.py src/cybergraph/analysis/collector.py src/cybergraph/analysis/registry.py tests/test_firebase_rules.py` — Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/cybergraph/analysis/firebase_rules.py src/cybergraph/analysis/collector.py src/cybergraph/analysis/registry.py tests/test_firebase_rules.py
git commit -m "feat(analysis): detect open Firebase security rules"
```

---

## Task 2: Supabase RLS analyzer

**Files:**
- Create: `src/cybergraph/analysis/supabase_rls.py`
- Modify: `src/cybergraph/analysis/collector.py` (recognize `*.sql` under `supabase/`)
- Modify: `src/cybergraph/analysis/registry.py` (dispatch)
- Test: `tests/test_supabase_rls.py` (create)

**Interfaces:**
- Produces: `analyze_supabase_rls_file(path, repo_root) -> (nodes, edges, findings)`; rule id **`CG-SUPABASE-RLS-DISABLED`**, severity `high`, CWE-1230.
- Produces (shared helper in collector, imported by the registry): `is_supabase_sql(path: Path) -> bool` — a `.sql` file with a `supabase` path component.

- [ ] **Step 1: Write the failing test**

Create `tests/test_supabase_rls.py`:

```python
from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.supabase_rls import analyze_supabase_rls_file


def _write(tmp_path: Path, text: str) -> Path:
    d = tmp_path / "supabase" / "migrations"
    d.mkdir(parents=True)
    p = d / "0001_init.sql"
    p.write_text(text, encoding="utf-8")
    return p


def test_disable_rls_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, "ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY;\n")
    _n, _e, findings = analyze_supabase_rls_file(p, tmp_path)
    assert [f.rule_id for f in findings] == ["CG-SUPABASE-RLS-DISABLED"]
    assert findings[0].cwe == "CWE-1230"


def test_policy_using_true_is_flagged(tmp_path: Path) -> None:
    text = (
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\n"
        'CREATE POLICY p ON t FOR SELECT USING (true);\n'
    )
    p = _write(tmp_path, text)
    _n, _e, findings = analyze_supabase_rls_file(p, tmp_path)
    assert [f.rule_id for f in findings] == ["CG-SUPABASE-RLS-DISABLED"]


def test_create_without_enable_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, "CREATE TABLE public.secrets (id int, val text);\n")
    _n, _e, findings = analyze_supabase_rls_file(p, tmp_path)
    assert [f.rule_id for f in findings] == ["CG-SUPABASE-RLS-DISABLED"]


def test_create_then_enable_is_clean(tmp_path: Path) -> None:
    text = (
        "CREATE TABLE public.secrets (id int, val text);\n"
        "ALTER TABLE public.secrets ENABLE ROW LEVEL SECURITY;\n"
    )
    p = _write(tmp_path, text)
    _n, _e, findings = analyze_supabase_rls_file(p, tmp_path)
    assert findings == []


def test_file_node_always_present(tmp_path: Path) -> None:
    p = _write(tmp_path, "-- just a comment\n")
    nodes, _e, findings = analyze_supabase_rls_file(p, tmp_path)
    assert any(n.kind == "File" for n in nodes)
    assert findings == []
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_supabase_rls.py -v` — Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement the analyzer**

Create `src/cybergraph/analysis/supabase_rls.py`:

```python
"""Supabase RLS analyzer for SQL migrations.

Row-level security is Supabase's authorization boundary; a table with RLS off
(or a policy that re-opens it with ``USING (true)``) exposes its rows to the
public API role. Regex-based, per-file. Three definite signals:

* ``DISABLE ROW LEVEL SECURITY`` -- an explicit switch-off;
* ``CREATE POLICY ... USING (true)`` -- a policy that grants everyone access;
* ``CREATE TABLE t`` with no ``ENABLE ROW LEVEL SECURITY`` for ``t`` in the same
  file -- Supabase migrations conventionally enable RLS in the migration that
  creates the table, so a create with no same-file enable is the classic
  "forgot to turn on RLS" bug. Cross-file enable is possible but rare; the
  same-file scope keeps precision high and the finding is a REVIEW, not a block.

Table identity is compared on the bare table name (schema-qualified or not).
"""

from __future__ import annotations

import re
from pathlib import Path

from cybergraph.graph import Edge, Finding, Node
from cybergraph.suppressions import is_inline_suppressed

DISABLE_RE = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?P<tbl>[\w.\"]+)\s+disable\s+row\s+level\s+security",
    re.IGNORECASE,
)
ENABLE_RE = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?P<tbl>[\w.\"]+)\s+enable\s+row\s+level\s+security",
    re.IGNORECASE,
)
CREATE_TABLE_RE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?P<tbl>[\w.\"]+)",
    re.IGNORECASE,
)
POLICY_TRUE_RE = re.compile(
    r"create\s+policy\b[^;]*?\busing\s*\(\s*true\s*\)",
    re.IGNORECASE | re.DOTALL,
)


def _bare(name: str) -> str:
    return name.replace('"', "").split(".")[-1].lower()


def _line_of(source: str, index: int) -> int:
    return source.count("\n", 0, index) + 1


def analyze_supabase_rls_file(
    path: Path, repo_root: Path
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()
    rel = path.relative_to(repo_root).as_posix()
    nodes: list[Node] = [Node("File", rel, rel, rel, 1, len(lines), {"language": "sql"})]
    findings: list[Finding] = []

    def emit(line_no: int, message: str) -> None:
        if is_inline_suppressed(lines, line_no, "CG-SUPABASE-RLS-DISABLED"):
            return
        findings.append(
            Finding(
                rule_id="CG-SUPABASE-RLS-DISABLED",
                severity="high",
                message=message,
                file_path=rel,
                line_start=line_no,
                cwe="CWE-1230",
                evidence=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "",
            )
        )

    for m in DISABLE_RE.finditer(source):
        emit(_line_of(source, m.start()),
             f"row-level security is disabled on `{_bare(m.group('tbl'))}`")
    for m in POLICY_TRUE_RE.finditer(source):
        emit(_line_of(source, m.start()),
             "a policy grants access to everyone (`USING (true)`)")

    enabled = {_bare(m.group("tbl")) for m in ENABLE_RE.finditer(source)}
    for m in CREATE_TABLE_RE.finditer(source):
        tbl = _bare(m.group("tbl"))
        if tbl not in enabled:
            emit(_line_of(source, m.start()),
                 f"table `{tbl}` is created without enabling row-level security")

    return nodes, [], findings
```

- [ ] **Step 4: Recognize the files in the collector**

In `collector.py`, add and export:

```python
def is_supabase_sql(path: Path) -> bool:
    return path.suffix.lower() == ".sql" and any(
        part.lower() == "supabase" for part in path.parts
    )
```

and OR it into `is_supported_source`:

```python
    return (
        path.suffix.lower() in SUPPORTED_SUFFIXES
        or path.name in SUPPORTED_FILENAMES
        or is_supabase_sql(path)
    )
```

- [ ] **Step 5: Dispatch in the registry**

In `registry.py`: `from .supabase_rls import analyze_supabase_rls_file` and `from .collector import is_supabase_sql`; in `_dispatch`, before the fallback:

```python
    if is_supabase_sql(path):
        return analyze_supabase_rls_file(path, repo_root)
```

- [ ] **Step 6: Run tests + ruff**

Run: `pytest tests/test_supabase_rls.py -v` — Expected: PASS.
Run: `ruff check src/cybergraph/analysis/supabase_rls.py src/cybergraph/analysis/collector.py src/cybergraph/analysis/registry.py tests/test_supabase_rls.py` — Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/cybergraph/analysis/supabase_rls.py src/cybergraph/analysis/collector.py src/cybergraph/analysis/registry.py tests/test_supabase_rls.py
git commit -m "feat(analysis): detect Supabase tables with row-level security off"
```

---

## Task 3: Bucket-policy analyzer

**Files:**
- Create: `src/cybergraph/analysis/bucket_policy.py`
- Modify: `src/cybergraph/analysis/collector.py` (recognize bucket-policy JSON by name)
- Modify: `src/cybergraph/analysis/registry.py` (dispatch)
- Test: `tests/test_bucket_policy.py` (create)

**Interfaces:**
- Produces: `analyze_bucket_policy_file(path, repo_root) -> (nodes, edges, findings)`; rule id **`CG-STORAGE-BUCKET-PUBLIC`**, severity `high`, CWE-732.
- Produces (shared helper in collector): `is_bucket_policy(path: Path) -> bool`.
- **Coverage-honesty contract:** on `json.JSONDecodeError` the analyzer does NOT catch — it lets the error propagate to `registry.analyze_source_file`'s per-file containment (`ValueError`), which emits `CG-FILE-UNREADABLE` + a File node → coverage `FAILED` → capability UNKNOWN. A *valid* JSON that is not a policy shape → no finding, bare File node.

- [ ] **Step 1: Write the failing test**

Create `tests/test_bucket_policy.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cybergraph.analysis.bucket_policy import analyze_bucket_policy_file

S3_PUBLIC = {
    "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::b/*"}
    ]
}
S3_SCOPED = {
    "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:role/r"},
         "Action": "s3:GetObject"}
    ]
}
GCS_PUBLIC = {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}


def _write(tmp_path: Path, obj) -> Path:
    p = tmp_path / "bucket-policy.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def test_s3_public_principal_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, S3_PUBLIC)
    _n, _e, findings = analyze_bucket_policy_file(p, tmp_path)
    assert [f.rule_id for f in findings] == ["CG-STORAGE-BUCKET-PUBLIC"]
    assert findings[0].cwe == "CWE-732"


def test_s3_scoped_principal_is_clean(tmp_path: Path) -> None:
    p = _write(tmp_path, S3_SCOPED)
    _n, _e, findings = analyze_bucket_policy_file(p, tmp_path)
    assert findings == []


def test_gcs_all_users_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, GCS_PUBLIC)
    _n, _e, findings = analyze_bucket_policy_file(p, tmp_path)
    assert [f.rule_id for f in findings] == ["CG-STORAGE-BUCKET-PUBLIC"]


def test_non_policy_json_is_clean(tmp_path: Path) -> None:
    p = _write(tmp_path, {"name": "not a policy", "version": 3})
    nodes, _e, findings = analyze_bucket_policy_file(p, tmp_path)
    assert findings == []
    assert any(n.kind == "File" for n in nodes)


def test_malformed_json_propagates_valueerror(tmp_path: Path) -> None:
    p = tmp_path / "bucket-policy.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):  # JSONDecodeError is a ValueError
        analyze_bucket_policy_file(p, tmp_path)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_bucket_policy.py -v` — Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement the analyzer**

Create `src/cybergraph/analysis/bucket_policy.py`:

```python
"""Standalone S3/GCS bucket-policy analyzer (not Terraform -- terraform.py owns HCL).

Parses a JSON policy file and flags a grant of public access:

* S3 bucket policy: a ``Statement`` with ``Effect: Allow`` and a wildcard
  ``Principal`` (``"*"`` or ``{"AWS": "*"}``);
* GCS IAM policy: a ``binding`` whose ``members`` include ``allUsers`` or
  ``allAuthenticatedUsers`` on a storage role.

A valid JSON that is not a policy shape yields no finding (a bare File node).
Malformed JSON is NOT caught here -- it raises ``JSONDecodeError`` (a
``ValueError``) so the registry's per-file containment records the file as
unreadable, which the coverage layer reads as UNKNOWN rather than a clean pass.
"""

from __future__ import annotations

import json
from pathlib import Path

from cybergraph.graph import Edge, Finding, Node
from cybergraph.suppressions import is_inline_suppressed

_PUBLIC_MEMBERS = {"allusers", "allauthenticatedusers"}


def _is_wildcard_principal(principal: object) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(
            v == "*" or (isinstance(v, list) and "*" in v) for v in principal.values()
        )
    return False


def _evidence_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, start=1):
        if needle in line:
            return i
    return 1


def analyze_bucket_policy_file(
    path: Path, repo_root: Path
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()
    rel = path.relative_to(repo_root).as_posix()
    nodes: list[Node] = [Node("File", rel, rel, rel, 1, len(lines), {"language": "json"})]
    findings: list[Finding] = []

    data = json.loads(source)  # JSONDecodeError propagates -> registry containment

    def emit(line_no: int, message: str) -> None:
        if is_inline_suppressed(lines, line_no, "CG-STORAGE-BUCKET-PUBLIC"):
            return
        findings.append(
            Finding(
                rule_id="CG-STORAGE-BUCKET-PUBLIC",
                severity="high",
                message=message,
                file_path=rel,
                line_start=line_no,
                cwe="CWE-732",
                evidence=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "",
            )
        )

    if isinstance(data, dict) and isinstance(data.get("Statement"), list):
        for stmt in data["Statement"]:
            if not isinstance(stmt, dict):
                continue
            if stmt.get("Effect") == "Allow" and _is_wildcard_principal(stmt.get("Principal")):
                emit(_evidence_line(lines, "Principal"),
                     "S3 bucket policy grants access to everyone (Principal \"*\")")
                break

    if isinstance(data, dict) and isinstance(data.get("bindings"), list):
        for binding in data["bindings"]:
            if not isinstance(binding, dict):
                continue
            members = binding.get("members", [])
            if isinstance(members, list) and any(
                isinstance(m, str) and m.lower() in _PUBLIC_MEMBERS for m in members
            ):
                emit(_evidence_line(lines, "allUsers"),
                     "storage IAM binding grants access to all users")
                break

    return nodes, [], findings
```

- [ ] **Step 4: Recognize the files in the collector**

In `collector.py`, add and export:

```python
def is_bucket_policy(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".json") and (
        "bucket-policy" in name or "bucket_policy" in name or name.endswith(".iam.json")
    )
```

and OR it into `is_supported_source` (alongside `is_supabase_sql`).

- [ ] **Step 5: Dispatch in the registry**

In `registry.py`: `from .bucket_policy import analyze_bucket_policy_file` and `from .collector import is_bucket_policy`; in `_dispatch`, before the fallback:

```python
    if is_bucket_policy(path):
        return analyze_bucket_policy_file(path, repo_root)
```

- [ ] **Step 6: Run tests + ruff**

Run: `pytest tests/test_bucket_policy.py -v` — Expected: PASS.
Run: `ruff check src/cybergraph/analysis/bucket_policy.py src/cybergraph/analysis/collector.py src/cybergraph/analysis/registry.py tests/test_bucket_policy.py` — Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/cybergraph/analysis/bucket_policy.py src/cybergraph/analysis/collector.py src/cybergraph/analysis/registry.py tests/test_bucket_policy.py
git commit -m "feat(analysis): detect public S3/GCS bucket policies"
```

---

## Task 4: Activate the `cloud_configuration` capability

**Files:**
- Modify: `src/cybergraph/security/capability.py`
- Modify: `src/cybergraph/security/coverage.py`
- Modify: `src/cybergraph/security/checks.py`
- Modify: `tests/test_capability.py`, `tests/test_checks.py`, `tests/test_coverage_report.py` (flip NOT_SUPPORTED expectations)
- Test: `tests/test_config_posture_capability.py` (create)

**Interfaces:**
- Consumes: the three rule ids from Tasks 1–3 and Terraform's existing `CG-IAC-*`.
- Produces: `CONFIG_GLOBS` in `capability.py`; `cloud_configuration` with `supported=True` and `covers=CONFIG_GLOBS`; `_FINDING_RULES["cloud_configuration"]` as a set; a generic `_evaluate` branch that matches rule-id membership.

- [ ] **Step 1: Write the failing test**

Create `tests/test_config_posture_capability.py`:

```python
from __future__ import annotations

import subprocess
from pathlib import Path

from cybergraph.security.capability import (
    FAIL, NOT_APPLICABLE, PASS, UNKNOWN, CAPABILITIES,
)
from cybergraph.security.check import check_change
from cybergraph.security.verdict import STATE_ACCEPT, STATE_REVIEW


def _cap(cid: str):
    return next(c for c in CAPABILITIES if c.id == cid)


def test_cloud_configuration_is_supported():
    assert _cap("cloud_configuration").supported is True


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@e.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "base"], check=True)
    return repo


def test_disabling_rls_makes_check_review(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    d = repo / "supabase" / "migrations"
    d.mkdir(parents=True)
    (d / "0002_open.sql").write_text(
        "ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY;\n", encoding="utf-8"
    )
    verdict = check_change(repo, mode="worktree")
    assert verdict.state == STATE_REVIEW
    assert any("cloud_configuration" == c.capability_id and c.status == FAIL
               for c in verdict.checks)


def test_clean_readme_change_accepts(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "README.md").write_text("# x\nmore\n", encoding="utf-8")
    verdict = check_change(repo, mode="worktree")
    # cloud_configuration is NOT_APPLICABLE (no config file changed); overall may
    # still accept if nothing else reviews.
    cc = next(c for c in verdict.checks if c.capability_id == "cloud_configuration")
    assert cc.status == NOT_APPLICABLE
```

> Note: confirm `check_change`'s signature and that `Verdict.checks` carries `CheckResult`s with `.capability_id`/`.status` before finalizing asserts (read `security/check.py` and `security/verdict.py`). A README-only change may make other capabilities NOT_APPLICABLE too; assert only on `cloud_configuration` and the overall state as written.

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_config_posture_capability.py -v` — Expected: FAIL (`cloud_configuration` not supported / no FAIL).

- [ ] **Step 3: Add `CONFIG_GLOBS` and activate the capability**

In `capability.py`, after the `*_GLOBS` definitions add:

```python
# Declarative config surfaces with a Phase-2 posture analyzer. Kept narrow so a
# changed config file that is analyzed-and-clean can PASS and an unparsed one
# reads UNKNOWN -- broad globs (e.g. every *.yaml) would make unrelated changes
# review. Single source of truth for the capability's `covers` and coverage.
CONFIG_GLOBS = (
    "*.tf", "*.tfvars",
    "*.rules", "firebase.json",
    "supabase/*.sql",
    "*bucket-policy*.json", "*bucket_policy*.json", "*.iam.json",
)
```

Change the `cloud_configuration` entry from
`Capability("cloud_configuration", "Cloud and database configuration", INFRA_GLOBS, False)`
to:

```python
    Capability("cloud_configuration",
               "Cloud and database configuration", CONFIG_GLOBS, True),
```

> `fnmatch("supabase/migrations/0001.sql", "supabase/*.sql")` is True (`*` spans `/` in fnmatch), so nested migrations match. Verify with a one-off `python -c` if unsure. Leave `INFRA_GLOBS` defined if other code imports it; confirm with a grep and remove only if unused.

- [ ] **Step 4: Track config files in coverage**

In `coverage.py`, import `CONFIG_GLOBS` and include it so config files are treated as verified sources:

```python
from cybergraph.security.capability import CONFIG_GLOBS, SOURCE_GLOBS, VERIFIED_GLOBS
```

Change the `sources` filter to `SOURCE_GLOBS + CONFIG_GLOBS`, and the UNSUPPORTED gate from
`elif not any(fnmatch(file, pattern) for pattern in VERIFIED_GLOBS):`
to
`elif not any(fnmatch(file, pattern) for pattern in VERIFIED_GLOBS + CONFIG_GLOBS):`
so a config file with a File node is `ANALYZED`, an unreadable one is `FAILED`, and neither is mislabeled `UNSUPPORTED`.

- [ ] **Step 5: Make `_FINDING_RULES` a set and match membership**

In `checks.py`, change the `cloud_configuration` mapping (add the entry) so `_FINDING_RULES` reads:

```python
_FINDING_RULES = {
    "sql_construction": "CG-SQL-EXEC",
    "command_execution": "CG-CMD-EXEC",
    "code_execution": "CG-CODE-EXEC",
    "deserialization": "CG-DESERIALIZE",
    "path_access": "CG-PATH-TRAVERSAL",
    "cloud_configuration": {
        "CG-FIREBASE-RULES-OPEN", "CG-SUPABASE-RLS-DISABLED", "CG-STORAGE-BUCKET-PUBLIC",
        "CG-IAC-PUBLIC-BUCKET", "CG-IAC-WILDCARD-IAM", "CG-IAC-OPEN-INGRESS",
        "CG-IAC-HARDCODED-SECRET",
    },
}
```

In the generic branch of `_evaluate` (currently `checks.py:194-218`), normalize to a set and match membership:

```python
    rule = _FINDING_RULES.get(capability_id)
    if rule is None:  # pragma: no cover - guarded by test_every_capability_is_evaluated
        raise AssertionError(f"capability {capability_id} has no evaluator")
    rules = {rule} if isinstance(rule, str) else set(rule)

    relevant_files = _capability_files(capability_id, changed_files)
    missing, failed, analyzed = _coverage_summary(relevant_files, coverage)
    if failed:
        return CheckResult(capability_id, UNKNOWN, failed[0].reason, len(failed))
    if missing:
        return CheckResult(
            capability_id, UNKNOWN,
            f"`{missing[0]}` changed but has no analysis record", len(missing),
        )
    confirmed = [f for f in findings if f.rule_id in rules]
    unverified = [f for f in findings if f.rule_id in {f"{r}-UNVERIFIED" for r in rules}]
    if confirmed:
        return CheckResult(capability_id, FAIL, confirmed[0].message, len(confirmed))
    if unverified:
        return CheckResult(capability_id, UNKNOWN, unverified[0].message, len(unverified))
    if not analyzed:
        return CheckResult(
            capability_id, UNKNOWN,
            "no changed file in this capability's scope was analyzed",
        )
    return CheckResult(capability_id, PASS, evidence_count=len(analyzed))
```

The single-rule capabilities are unchanged in behavior (`{rule}` membership == equality).

- [ ] **Step 6: Update the tests that assumed `cloud_configuration` was NOT_SUPPORTED**

Run `pytest tests/test_capability.py tests/test_checks.py tests/test_coverage_report.py -v` and update every assertion that expected `cloud_configuration` to be `NOT_SUPPORTED` / unsupported to its new supported behavior. Read each failing assertion and change the *expectation*, never the production code, to match the intended activation. (Search: `grep -rn "cloud_configuration\|NOT_SUPPORTED" tests/`.) Do not weaken any unrelated assertion.

- [ ] **Step 7: Run tests + ruff**

Run: `pytest tests/test_config_posture_capability.py tests/test_capability.py tests/test_checks.py tests/test_coverage_report.py -v` — Expected: PASS.
Run: `ruff check src/cybergraph/security/capability.py src/cybergraph/security/coverage.py src/cybergraph/security/checks.py tests/test_config_posture_capability.py` — Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add src/cybergraph/security/capability.py src/cybergraph/security/coverage.py src/cybergraph/security/checks.py tests/
git commit -m "feat(verdict): activate cloud_configuration -- config posture regressions review"
```

---

## Task 5: Mutation harness + docs + full verification

**Files:**
- Modify: `benchmark/mutation_harness.py` (two seeded fail-opens)
- Modify: `README.md` (one line)
- Verification: full suite, ruff, harness, precision/eval.

**Interfaces:**
- Consumes: the finished analyzers (Tasks 1–3) and the wiring (Task 4).

- [ ] **Step 1: Add the mutations**

Append two `Mutation` entries to `MUTATIONS` in `benchmark/mutation_harness.py`. Match every `old` string to the committed source verbatim (open the files and copy exactly; fix the `old` string if it differs — never edit the source to fit the mutation).

Mutation A — a posture finding read as PASS. Target the membership match in `checks.py`:
- `old` = `    confirmed = [f for f in findings if f.rule_id in rules]`
- `new` = `    confirmed = []`
- `tests` = `("tests/test_config_posture_capability.py::test_disabling_rls_makes_check_review",)`
- id `D9-config-posture-finding-ignored`, disaster `D9`, note "a config posture finding must FAIL the capability, not be dropped".

Mutation B — an unparsed config read as PASS instead of UNKNOWN. Target the bucket analyzer's propagation:
- `old` = `    data = json.loads(source)  # JSONDecodeError propagates -> registry containment`
- `new` = `    try:\n        data = json.loads(source)\n    except ValueError:\n        return nodes, [], findings`
- `tests` = a new guard test (add it in Step 2) that a malformed in-scope bucket-policy JSON makes `cybergraph check` report `cloud_configuration` UNKNOWN, not PASS.
- id `D9-unparsed-config-reads-clean`, disaster `D9`, note "an unparseable config must read UNKNOWN, never a clean pass".

> If the multi-line `new` for Mutation B is awkward in the harness's single-edit model, instead target a one-line equivalent that still reproduces the swallow (e.g. wrap the assignment so a decode error yields empty findings). The invariant under test is what matters: malformed in-scope config → UNKNOWN.

- [ ] **Step 2: Add the coverage-honesty guard test**

Append to `tests/test_config_posture_capability.py`:

```python
def test_malformed_bucket_policy_reads_unknown(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "bucket-policy.json").write_text("{not json", encoding="utf-8")
    verdict = check_change(repo, mode="worktree")
    cc = next(c for c in verdict.checks if c.capability_id == "cloud_configuration")
    assert cc.status == UNKNOWN  # never a silent PASS on something we could not parse
```

Run: `pytest tests/test_config_posture_capability.py::test_malformed_bucket_policy_reads_unknown -v` — Expected: PASS (proves the propagation path end-to-end).

- [ ] **Step 3: Run the harness**

Run: `python benchmark/mutation_harness.py` — Expected: every mutation CAUGHT, including the two new ones. (Use `--only <id>` to iterate if supported.)

- [ ] **Step 4: Document in the README**

Add one line to the analyzer/coverage list noting config-posture coverage:

```markdown
- **Config posture** — open Firebase security rules, Supabase tables with row-level
  security off, and public S3/GCS bucket policies. A change that weakens one is a REVIEW.
```

- [ ] **Step 5: Full verification**

Run: `pytest -q` — Expected: all pass (prior count + the new analyzer/capability tests, minus none).
Run: `ruff check .` — Expected: no new errors beyond the repo's pre-existing baseline (the deliberately-vulnerable `benchmark/` fixtures and the one pre-existing `mutation_harness.py:381` E501 exist on `main`; introduce none in the files this branch touches).
Run: `python benchmark/mutation_harness.py` — Expected: every mutation CAUGHT.
Run: `python benchmark/run_precision.py` and `python benchmark/run_eval.py` — Expected: unchanged (these exercise the Python corpus, untouched here).

- [ ] **Step 6: Commit**

```bash
git add benchmark/mutation_harness.py README.md tests/test_config_posture_capability.py
git commit -m "test(config): seed config-posture fail-open mutations; document coverage"
```

---

## Notes for the executor

- **Precision is the product's cardinal value.** If a detection is ambiguous, prefer no finding over a false one; document the recall gap rather than risk a false alarm.
- Confirm dataclass field/constructor names (`Finding`, `Node`, `CheckResult`, `Verdict`) and the exact inline-suppression token against the source before running each task's tests; adapt the *test* to the real names, never the reverse.
- The three analyzer tasks each touch `collector.py` and `registry.py`; they are dispatched sequentially (one implementer at a time), so there is no conflict, but each task must leave those two files ruff-clean and not disturb the other analyzers' clauses.
- Do NOT add a YAML/HCL/SQL parser dependency, a new CLI command, CORS detection, or the Next.js `client_secret_boundary` — those are explicitly out of scope (slice 3).

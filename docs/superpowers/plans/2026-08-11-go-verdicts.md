# Go Verdicts — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Go from inventory-grade `CG-GO-SINK-CALL` into real safe/unsafe/unknown verdicts for SQL, command, and path, reusing Python's rule ids so a Go injection reviews under the same capability as Python — precisely, with only an all-literal/constant construction ever reading SAFE.

**Architecture:** Port the JS slice's proven shape to Go — a `_GO` sink registry in `sinks.py`, a new `go_provenance.py` (construction classifier + fail-safe assessor, reusing the *proven, final* `js_provenance` logic incl. positive-literal-proof, adapted to Go strings and `fmt.Sprintf`), `go.py` routing the three classes through it, and a broadening of three capabilities. No `checks.py` change.

**Tech Stack:** Python 3.10–3.13, standard library only (`re`). Existing `sinks.Sink`/`lookup_sink`, `predicates.VERDICT_*`, `provenance.LITERAL/COMPOSED/OPAQUE`, the capability/coverage machinery, and `go.py`'s existing intra-function taint. `src/cybergraph/analysis/js_provenance.py` is the reference implementation for the shared classifier logic.

## Global Constraints

- **Zero runtime dependencies**; standard library only (`re`) — no Go parser. The classifier is lightweight/structural and fail-safe.
- Python 3.10–3.13. `from __future__ import annotations` first line of any new file.
- Ruff line-length 100; run `ruff check` on every touched file — clean.
- No network; no API keys on any default path.
- **Precision over recall (cardinal):** only an all-literal/constant construction is SAFE. A construction containing a variable is UNSAFE (taint-confirmed) or UNKNOWN (unresolved) — **never SAFE**, never a confident UNSAFE on an unresolved variable. **Never infer "no candidate names ⇒ literal"** — require positive proof every operand/argument is a literal/constant (this is the exact false-SAFE the JS final review caught).
- Findings carry the standard fields and honor `is_inline_suppressed`.
- Commits `Laraib <lxh417bham@gmail.com>` only (repo-local config already carries it — do **not** pass `-c user.email=`); no `Co-Authored-By`, no AI attribution. Many small commits; never squash. Push only to `https://github.com/AQ-Labs/cybergraph`.
- Branch `feat/go-verdicts` is stacked on `feat/js-verdicts-core-four`; do not rebase during implementation.

---

## File Structure

- `src/cybergraph/security/sinks.py` (modify) — add `_GO`; register in `_BY_LANGUAGE`.
- `src/cybergraph/analysis/go_provenance.py` (create) — Go classifier + assessor.
- `src/cybergraph/analysis/go.py` (modify) — route the three sink classes through the assessor.
- `src/cybergraph/security/capability.py` (modify) — `GO_GLOBS`; broaden three capabilities.
- `src/cybergraph/security/coverage.py` (modify) — add `GO_GLOBS` to the verified gate.
- Tests: `tests/test_sinks_go.py`, `tests/test_go_provenance.py`, `tests/test_go_verdicts_e2e.py` (create).
- `benchmark/mutation_harness.py` (modify) — three seeded fail-opens.
- `README.md`, `docs/CRITICAL_AUDIT.md` (modify) — document; extend §4.5 note.

---

## Task 1: Go sink registry in `sinks.py`

**Files:** Modify `src/cybergraph/security/sinks.py`; Test `tests/test_sinks_go.py` (create).

**Interfaces:** `_GO: tuple[Sink, ...]` and `_BY_LANGUAGE["go"] = _GO`, so `lookup_sink(name, "go")` resolves Go sinks (reuse the existing `_SQL`/`_CMD` plain-text constants — do not duplicate them).

- [ ] **Step 1: Write the failing test**

Create `tests/test_sinks_go.py`:

```python
from __future__ import annotations

import pytest

from cybergraph.security.sinks import lookup_sink


@pytest.mark.parametrize("call_name,rule_id,vuln", [
    ("db.Query", "CG-SQL-EXEC", "sql"),
    ("db.QueryRow", "CG-SQL-EXEC", "sql"),
    ("tx.Exec", "CG-SQL-EXEC", "sql"),
    ("db.QueryContext", "CG-SQL-EXEC", "sql"),
    ("exec.Command", "CG-CMD-EXEC", "command"),
    ("exec.CommandContext", "CG-CMD-EXEC", "command"),
    ("os.Open", "CG-PATH-TRAVERSAL", "path"),
    ("os.ReadFile", "CG-PATH-TRAVERSAL", "path"),
    ("ioutil.WriteFile", "CG-PATH-TRAVERSAL", "path"),
    ("os.Create", "CG-PATH-TRAVERSAL", "path"),
])
def test_go_sinks_resolve(call_name, rule_id, vuln):
    sink = lookup_sink(call_name, "go")
    assert sink is not None, call_name
    assert sink.rule_id == rule_id
    assert sink.vuln_class == vuln


def test_go_non_sink_is_none():
    assert lookup_sink("fmt.Sprintf", "go") is None  # construction, not a sink
    assert lookup_sink("log.Println", "go") is None


def test_other_languages_unchanged():
    assert lookup_sink("os.system", "python").rule_id == "CG-CMD-EXEC"
    assert lookup_sink("db.Query", "python") is None
    assert lookup_sink("db.query", "javascript").rule_id == "CG-SQL-EXEC"
```

- [ ] **Step 2: Run to verify it fails**

`pytest tests/test_sinks_go.py -v` — FAIL (Go sinks return None).

- [ ] **Step 3: Implement**

In `sinks.py`, add after `_JAVASCRIPT`:

```python
_GO: tuple[Sink, ...] = (
    # SQL — db/tx receivers unresolvable → bare on the PascalCase method name.
    Sink("Query", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryRow", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryContext", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryRowContext", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("Exec", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecContext", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    # Command — exec.Command(name, args…); shell only when name is sh/bash -c → conditional.
    Sink("exec.Command", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         shell=SHELL_CONDITIONAL),
    Sink("exec.CommandContext", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         shell=SHELL_CONDITIONAL),
    # Path — os/ioutil receivers → bare on the PascalCase method name.
    Sink("Open", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("OpenFile", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("ReadFile", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("WriteFile", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("Create", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
)
```

Change `_BY_LANGUAGE` to include `"go": _GO`.

> `exec.Command` is registered as the full dotted name (non-bare, exact) so it resolves on `lookup_sink("exec.Command","go")`; `Command` alone is not bare (avoids matching unrelated `.Command()`). Confirm `test_go_non_sink_is_none` holds — `fmt.Sprintf`/`log.Println` have no entry.

- [ ] **Step 4: Run + ruff**

`pytest tests/test_sinks_go.py -v` → PASS. `ruff check src/cybergraph/security/sinks.py tests/test_sinks_go.py` → clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/security/sinks.py tests/test_sinks_go.py
git commit -m "feat(sinks): register Go SQL/command/path sinks with Python's rule ids"
```

---

## Task 2: `go_provenance.py` — classifier + assessor

**Files:** Create `src/cybergraph/analysis/go_provenance.py`; Test `tests/test_go_provenance.py` (create).

**Interfaces:** `extract_first_arg(source, open_paren) -> str | None`, `classify(arg_text) -> str`, `variable_names(arg_text) -> list[str]`, `assess(sink, arg_text, tainted_names) -> str`. Same contract and cardinal rule as `js_provenance`.

**Approach:** START from `src/cybergraph/analysis/js_provenance.py` (the final, reviewed version — it already has the correct positive-literal-proof logic: `_is_proven_literal_operand`, `_plus_operand_candidates`, `_split_plus`, and the `assess` that only reads SAFE on proven literals). Port it to Go, changing only:
1. **No `${}` template interpolation** in Go — drop the `_INTERP_RE` path.
2. **`fmt.Sprintf` is Go's interpolation idiom** — add it as a COMPOSED form and extract its non-format arguments as candidate variables.
3. **Go string literals** are interpreted `"…"` and raw `` `…` `` (backtick); no single-quote strings (single quotes are runes). Keep the string-aware matchers; `_STRING_ONLY_RE`/`_is_proven_literal_operand` already accept `"…"` and `` `…` ``.

- [ ] **Step 1: Write the failing test**

Create `tests/test_go_provenance.py`:

```python
from __future__ import annotations

from cybergraph.analysis.go_provenance import assess, classify, extract_first_arg
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE
from cybergraph.security.sinks import lookup_sink


def _sink(name):
    return lookup_sink(name, "go")


def test_extract_first_arg_string_aware():
    src = 'db.Query(fmt.Sprintf("SELECT %s", id), other)'
    assert extract_first_arg(src, src.index("(")) == 'fmt.Sprintf("SELECT %s", id)'
    assert extract_first_arg('db.Query(`raw ) str`)', 8) == '`raw ) str`'
    assert extract_first_arg("db.Query(`oops", 8) is None


def test_classify():
    assert classify('"SELECT 1"') == "literal"
    assert classify("`SELECT 1`") == "literal"
    assert classify('"SELECT " + id') == "composed"
    assert classify('fmt.Sprintf("SELECT %s", id)') == "composed"
    assert classify("userVar") == "opaque"


def test_assess_literal_safe():
    assert assess(_sink("db.Query"), '"SELECT 1"', set()) == VERDICT_SAFE


def test_assess_sprintf_tainted_unsafe():
    assert assess(_sink("db.Query"), 'fmt.Sprintf("SELECT %s", id)', {"id"}) == VERDICT_UNSAFE


def test_assess_sprintf_unresolved_unknown():
    assert assess(_sink("db.Query"), 'fmt.Sprintf("SELECT %s", id)', set()) == VERDICT_UNKNOWN


def test_assess_sprintf_all_literal_safe():
    assert assess(_sink("db.Query"), 'fmt.Sprintf("SELECT %d", 1)', set()) == VERDICT_SAFE


def test_assess_concat_tainted_unsafe():
    assert assess(_sink("db.Query"), '"SELECT " + name', {"name"}) == VERDICT_UNSAFE


def test_assess_non_leading_ident_operand_not_safe():
    # the JS-lesson guard: an operand not led by an identifier must not read SAFE
    assert assess(_sink("db.Query"), '"x = " + (id)', {"id"}) == VERDICT_UNSAFE
    assert assess(_sink("db.Query"), '"x = " + (id)', set()) == VERDICT_UNKNOWN


def test_assess_opaque_unknown():
    assert assess(_sink("db.Query"), "buildQuery()", set()) == VERDICT_UNKNOWN


def test_assess_unreadable_unknown():
    assert assess(_sink("db.Query"), None, set()) == VERDICT_UNKNOWN
```

- [ ] **Step 2: Run to verify it fails**

`pytest tests/test_go_provenance.py -v` — FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

Create `go_provenance.py` by porting `js_provenance.py`. Keep `extract_first_arg`, `_split_plus`, `_is_proven_literal_operand`, `_plus_operand_candidates`, and the `assess` structure verbatim (they are language-agnostic and carry the positive-literal-proof invariant). Changes:

- `classify(arg_text)`:
```python
def classify(arg_text: str) -> str:
    s = arg_text.strip()
    if _STRING_ONLY_RE.match(s):            # "..." or `...`
        return LITERAL
    if s.startswith("fmt.Sprintf(") or len(_split_plus(s)) > 1:
        return COMPOSED
    return OPAQUE
```
- `variable_names(arg_text)` — no `${}` path; instead:
```python
def variable_names(arg_text: str) -> list[str]:
    s = arg_text.strip()
    if s.startswith("fmt.Sprintf(") and s.endswith(")"):
        inner = extract_call_all_args(s)      # args of Sprintf
        names, _unresolved = _args_candidates(inner[1:])  # skip the format literal
        return _dedup(names)
    plus_names, _unresolved = _plus_operand_candidates(arg_text)
    return _dedup(plus_names)
```
  where `extract_call_all_args(sprintf_text)` splits the Sprintf argument list at top level (reuse a comma-split like `extract_first_arg`'s logic, but returning ALL args), and `_args_candidates(args)` applies `_is_proven_literal_operand` per arg (an all-literal Sprintf → no names). `assess` must also honor the "unresolved" flag from Sprintf args (a non-literal arg with no identifier → UNKNOWN, never SAFE), exactly as the `+` path does.
- Drop `_INTERP_RE` and the JS `${}` handling.

Keep `assess` returning: LITERAL → SAFE; else compute candidate names + unresolved; a tainted candidate → UNSAFE; any candidate or unresolved → UNKNOWN; all-proven-literal → SAFE; OPAQUE bare identifier → UNSAFE if tainted else UNKNOWN; `None` → UNKNOWN.

> The exact port must preserve the invariant tested by `test_assess_non_leading_ident_operand_not_safe` and `test_assess_sprintf_unresolved_unknown`. If porting reveals a helper is JS-specific, adapt it; never weaken a test.

- [ ] **Step 4: Run + ruff**

`pytest tests/test_go_provenance.py -v` → PASS. `ruff check src/cybergraph/analysis/go_provenance.py tests/test_go_provenance.py` → clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/analysis/go_provenance.py tests/test_go_provenance.py
git commit -m "feat(analysis): Go construction classifier and fail-safe sink assessor"
```

---

## Task 3: Route Go sink calls through the assessor

**Files:** Modify `src/cybergraph/analysis/go.py`; Test `tests/test_go_verdicts_e2e.py` (create).

**Interfaces:** a Go sink resolving via `lookup_sink(call_name, "go")` (original case) → graded verdict (`sink.rule_id` / `+"-UNVERIFIED"` / none), replacing `CG-GO-SINK-CALL` for those names; non-registry legacy sinks keep `CG-GO-SINK-CALL`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_go_verdicts_e2e.py`:

```python
from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.go import analyze_go_file


def _rules(tmp_path, src):
    p = tmp_path / "main.go"
    p.write_text(src, encoding="utf-8")
    _n, _e, findings = analyze_go_file(p, tmp_path)
    return [f.rule_id for f in findings]


def test_parameterized_query_is_safe(tmp_path):
    src = 'func h(db *sql.DB, id string) { db.Query("SELECT * FROM u WHERE id = $1", id) }\n'
    rules = _rules(tmp_path, src)
    assert "CG-SQL-EXEC" not in rules and "CG-SQL-EXEC-UNVERIFIED" not in rules
    assert "CG-GO-SINK-CALL" not in rules  # a registered sink no longer emits inventory


def test_sprintf_tainted_query_is_unsafe(tmp_path):
    src = (
        'func h(db *sql.DB, r *http.Request) {\n'
        '  id := r.URL.Query().Get("id")\n'
        '  db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %s", id))\n}\n'
    )
    assert "CG-SQL-EXEC" in _rules(tmp_path, src)


def test_sprintf_unresolved_query_is_unverified(tmp_path):
    src = 'func h(db *sql.DB, id string) { db.Query(fmt.Sprintf("SELECT %s", id)) }\n'
    rules = _rules(tmp_path, src)
    assert "CG-SQL-EXEC-UNVERIFIED" in rules and "CG-SQL-EXEC" not in rules
```

> Confirm how a name becomes tainted in `go.py` (the `INPUT_MARKERS` / `r.URL.Query()` path) so `test_sprintf_tainted_query_is_unsafe` genuinely exercises taint (→ UNSAFE), not merely UNKNOWN; adjust the fixture to `go.py`'s actual taint model if needed.

- [ ] **Step 2: Run to verify it fails**

`pytest tests/test_go_verdicts_e2e.py -v` — FAIL (emits `CG-GO-SINK-CALL`).

- [ ] **Step 3: Implement the routing**

In `go.py`, add imports (`from cybergraph.analysis.go_provenance import assess as assess_go_sink, extract_first_arg`; `from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNSAFE`; `from cybergraph.security.sinks import lookup_sink`) and a `_line_start_offsets(source)` helper + `_go_verdict_finding` (port both from `javascript.py` — the offset translation is the JS fix; the finding builder is identical). Replace the `if _is_sink(call_name, custom_sinks):` finding body with registry-first routing:

```python
            sink = lookup_sink(call_name, "go")
            if sink is not None or _is_sink(call_name, custom_sinks):
                edges.append(Edge(EDGE_REACHES_SINK, sink_source, call_name, rel, line_no))
                if sink is not None:
                    abs_off = line_starts[line_no - 1] + call.end() - 1
                    arg = extract_first_arg(source, abs_off)
                    verdict = assess_go_sink(sink, arg, set(tainted))
                    finding = _go_verdict_finding(sink, verdict, rel, line_no, line)
                    if finding is not None and not is_inline_suppressed(
                        lines, line_no, finding.rule_id
                    ):
                        findings.append(finding)
                elif not is_inline_suppressed(lines, line_no, "CG-GO-SINK-CALL"):
                    findings.append(Finding(
                        rule_id="CG-GO-SINK-CALL", severity="medium",
                        message=f"Go file reaches sensitive sink `{call_name}`",
                        file_path=rel, line_start=line_no, cwe="CWE-20",
                        evidence=line.strip(),
                    ))
                taint_source = source_key or _tainted_source_for_line(line, tainted)
                if taint_source:
                    edges.append(Edge(EDGE_TAINTS, taint_source, call_name, rel, line_no,
                                      {"function": sink_source, "reason": "tainted argument"}))
```

Compute `line_starts = _line_start_offsets(source)` once near the top of `analyze_go_file`. Use `set(tainted)` for the tainted-name set (function-local, matching the JS decision).

> `call.end() - 1` is the intra-line index of the `(` (CALL_RE ends in `\(`); `line_starts[line_no-1]` is the absolute start of the line. Confirm `source`/`tainted`/`call` are in scope at the routing point (they are — `source` at the top, `tainted` per-line, `call` from `CALL_RE.finditer(line)`).

- [ ] **Step 4: Run + ruff**

`pytest tests/test_go_verdicts_e2e.py tests/test_go*.py -v` → PASS (update any prior `go` analyzer test expecting `CG-GO-SINK-CALL` for a now-graded sink — change the expectation, not the code). `ruff check src/cybergraph/analysis/go.py tests/test_go_verdicts_e2e.py` → clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/analysis/go.py tests/test_go_verdicts_e2e.py
git commit -m "feat(analysis): grade Go SQL/command/path sinks into real verdicts"
```

---

## Task 4: Broaden three capabilities to Go

**Files:** Modify `src/cybergraph/security/capability.py`, `src/cybergraph/security/coverage.py`; Test `tests/test_go_verdicts_e2e.py` (append).

**Interfaces:** `GO_GLOBS = ("*.go",)`; `sql_construction`, `command_execution`, `path_access` → `covers += GO_GLOBS`; `coverage` verified gate `+ GO_GLOBS`. `code_execution`, `deserialization`, `VERIFIED_GLOBS` unchanged.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_go_verdicts_e2e.py`:

```python
import subprocess

from cybergraph.security.capability import CAPABILITIES, FAIL, NOT_SUPPORTED
from cybergraph.security.check import check_change
from cybergraph.security.verdict import STATE_REVIEW


def _cap(cid):
    return next(c for c in CAPABILITIES if c.id == cid)


def test_three_capabilities_cover_go():
    for cid in ("sql_construction", "command_execution", "path_access"):
        assert "*.go" in _cap(cid).covers, cid
    assert "*.go" not in _cap("code_execution").covers   # no Go code sink
    assert "*.go" not in _cap("deserialization").covers


def _repo(tmp_path):
    repo = tmp_path / "r"; repo.mkdir()
    for a in (["init","-q"],["config","user.email","t@e.com"],["config","user.name","t"]):
        subprocess.run(["git","-C",str(repo),*a], check=True)
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    subprocess.run(["git","-C",str(repo),"add","."], check=True)
    subprocess.run(["git","-C",str(repo),"commit","-q","-m","base"], check=True)
    return repo


def test_go_sqli_reviews_under_sql_construction(tmp_path):
    repo = _repo(tmp_path)
    (repo / "h.go").write_text(
        'package m\nimport ("database/sql"; "fmt"; "net/http")\n'
        'func h(db *sql.DB, r *http.Request) {\n'
        '  id := r.URL.Query().Get("id")\n'
        '  db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %s", id))\n}\n',
        encoding="utf-8",
    )
    verdict = check_change(repo, mode="worktree")
    assert verdict.state == STATE_REVIEW
    assert any(c.capability_id == "sql_construction" and c.status == FAIL
               for c in verdict.checks)


def test_go_still_not_supported_overall(tmp_path):
    repo = _repo(tmp_path)
    (repo / "h.go").write_text("package m\nvar X = 1\n", encoding="utf-8")
    verdict = check_change(repo, mode="worktree")
    assert any(c.capability_id == "source_analysis_support" and c.status == NOT_SUPPORTED
               for c in verdict.checks)
```

- [ ] **Step 2: Run to verify it fails**

`pytest tests/test_go_verdicts_e2e.py -k capabilities or reviews or not_supported -v` — FAIL.

- [ ] **Step 3: Implement**

In `capability.py`: add `GO_GLOBS = ("*.go",)` near the other `*_GLOBS`; change the three capabilities to `PYTHON_GLOBS + WEB_GLOBS + GO_GLOBS`. Leave `code_execution` at `PYTHON_GLOBS + WEB_GLOBS`, `deserialization` at `PYTHON_GLOBS`, `VERIFIED_GLOBS` unchanged.

In `coverage.py`: import `GO_GLOBS` and add it to the verified gate → `VERIFIED_GLOBS + CONFIG_GLOBS + WEB_GLOBS + GO_GLOBS`.

- [ ] **Step 4: Run + ruff**

`pytest tests/test_go_verdicts_e2e.py tests/test_capability.py tests/test_checks.py tests/test_coverage_report.py -v` → PASS (update any stale relevance expectation). `ruff check src/cybergraph/security/capability.py src/cybergraph/security/coverage.py` → clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/security/capability.py src/cybergraph/security/coverage.py tests/test_go_verdicts_e2e.py
git commit -m "feat(verdict): SQL/command/path capabilities now cover Go"
```

---

## Task 5: Mutations + docs + full verification

**Files:** Modify `benchmark/mutation_harness.py`, `README.md`, `docs/CRITICAL_AUDIT.md`.

- [ ] **Step 1: Add three mutations** to `MUTATIONS` (match `old` strings to the CURRENT committed `go_provenance.py` verbatim; each `old` unique):
  - `D9-go-tainted-sink-reads-safe` — flip the assessor's taint→UNSAFE branch to SAFE; test `tests/test_go_provenance.py::test_assess_concat_tainted_unsafe`.
  - `D9-go-unresolved-var-reads-safe` — flip the unresolved→UNKNOWN branch to SAFE; test `test_assess_sprintf_unresolved_unknown`.
  - `D9-go-sprintf-operand-reads-safe` — target the Sprintf/operand positive-literal-proof path so a non-literal Sprintf arg reads SAFE; test `test_assess_sprintf_tainted_unsafe` (or the non-leading-ident guard).
  Run `python benchmark/mutation_harness.py` → all three CAUGHT.

- [ ] **Step 2: Docs.** README: a bullet — Go now earns real SQL/command/path verdicts. `docs/CRITICAL_AUDIT.md` §4.5: extend the note to "resolved for JS (core four) and Go (SQL/command/path); Java/C# and other classes remain inventory-grade." Do NOT mark §4.5 fully closed.

- [ ] **Step 3: Full verification.** `pytest -q` (all pass); `ruff check .` (no new errors beyond baseline); `python benchmark/mutation_harness.py` (all CAUGHT); `python benchmark/run_precision.py` + `python benchmark/run_eval.py` (unchanged 1.0/1.0/1.0; Python/JS corpora unaffected — the Go registry is language-keyed; verify identical).

- [ ] **Step 4: Commit**

```bash
git add benchmark/mutation_harness.py README.md docs/CRITICAL_AUDIT.md
git commit -m "test(go): seed Go verdict fail-open mutations; document the upgrade"
```

---

## Notes for the executor

- **Precision is cardinal.** Only an all-literal/constant construction is SAFE. Port the JS `assess`/positive-literal-proof logic exactly — do NOT re-derive a looser version. A Sprintf arg or `+` operand that is not provably literal must contribute candidates or force UNKNOWN, never SAFE.
- Confirm names/signatures against source before running each task's tests (`provenance.LITERAL/…`, `Sink`, `check_change`/`Verdict.checks`, and how `go.py` taints a name); adapt the test to reality, never the reverse.
- Do NOT add a Go parser dependency, Go-specific rule ids, `*.go` to `VERIFIED_GLOBS`, Go code-exec/template-injection detection, or interprocedural flow — all out of scope.

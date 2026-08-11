# Java Verdicts — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Java from inventory `CG-JAVA-SINK-CALL` into real safe/unsafe/unknown verdicts for SQL, command, path, and unsafe deserialization — reusing Python's rule ids and reviewing under the same capabilities — with only an all-literal/constant construction ever reading SAFE and native deserialization never reading SAFE.

**Architecture:** A `_JAVA` sink registry (`sinks.py`), a new `java_provenance.py` (ported from the final Go/JS provenance — positive-literal-proof + Go's all-argument command assessor — plus Java idioms and a never-SAFE deserialization rule), and Java routing in `java.py` that uses a **dedicated Java sink-call matcher** (because the existing `CALL_RE` misses constructors and chained calls) to locate sinks and their arguments. Then broaden four capabilities to `*.java`. No `checks.py` change.

**Tech Stack:** Python 3.10–3.13, stdlib only (`re`). Existing `sinks.Sink`/`lookup_sink`, `predicates.VERDICT_*`, `provenance.LITERAL/COMPOSED/OPAQUE`, the capability/coverage machinery, `java.py`'s intra-function taint. Reference implementations: `src/cybergraph/analysis/go_provenance.py` and `js_provenance.py`.

## Global Constraints

- **Zero runtime dependencies**; stdlib only (`re`) — no Java parser. Lightweight/structural, fail-safe.
- Python 3.10–3.13. `from __future__ import annotations` first line of any new file.
- Ruff line-length 100; `ruff check` clean on touched files.
- No network; no API keys on any default path.
- **Precision over recall (cardinal):** only an all-literal/constant construction is SAFE; a variable is UNSAFE (taint-confirmed) or UNKNOWN (unresolved), never SAFE; never infer "no candidate names ⇒ literal". **Native deserialization is never SAFE** (UNSAFE if a tainted stream reaches it, else UNKNOWN).
- Commits `Laraib <lxh417bham@gmail.com>` only (repo config already carries it — do **not** pass `-c user.email=`); no `Co-Authored-By`, no AI attribution. Many small commits; never squash. Push only to `https://github.com/AQ-Labs/cybergraph`.
- Branch `feat/java-verdicts` is off `main` (not stacked).

---

## File Structure

- `src/cybergraph/security/sinks.py` (modify) — `_JAVA`; register in `_BY_LANGUAGE`.
- `src/cybergraph/analysis/java_provenance.py` (create) — classifier + assessor + `assess_command` + `assess_deserialization`.
- `src/cybergraph/analysis/java.py` (modify) — dedicated Java sink-call matcher + routing.
- `src/cybergraph/security/capability.py` (modify) — `JAVA_GLOBS`; broaden four capabilities.
- `src/cybergraph/security/coverage.py` (modify) — add `JAVA_GLOBS` to the verified gate.
- Tests: `tests/test_sinks_java.py`, `tests/test_java_provenance.py`, `tests/test_java_verdicts_e2e.py` (create).
- `benchmark/mutation_harness.py` (modify) — seeded fail-opens incl. deserialization.
- `README.md`, `docs/CRITICAL_AUDIT.md` (modify) — document; extend §4.5.

---

## Task 1: Java sink registry in `sinks.py`

**Files:** Modify `src/cybergraph/security/sinks.py`; Test `tests/test_sinks_java.py` (create).

**Interfaces:** `_JAVA: tuple[Sink, ...]` and `_BY_LANGUAGE["java"] = _JAVA`, so `lookup_sink(name, "java")` resolves Java sinks (reuse `_SQL`/`_CMD` constants; add a `_DESERIALIZE` plain string if not already present — Python's deser sinks use one).

- [ ] **Step 1: Write the failing test**

Create `tests/test_sinks_java.py`:

```python
from __future__ import annotations

import pytest

from cybergraph.security.sinks import lookup_sink


@pytest.mark.parametrize("call_name,rule_id,vuln", [
    ("stmt.executeQuery", "CG-SQL-EXEC", "sql"),
    ("stmt.executeUpdate", "CG-SQL-EXEC", "sql"),
    ("em.createNativeQuery", "CG-SQL-EXEC", "sql"),
    ("jdbcTemplate.query", "CG-SQL-EXEC", "sql"),
    ("Runtime.exec", "CG-CMD-EXEC", "command"),
    ("pb.start", "CG-CMD-EXEC", "command"),
    ("File", "CG-PATH-TRAVERSAL", "path"),
    ("Files.readAllBytes", "CG-PATH-TRAVERSAL", "path"),
    ("ois.readObject", "CG-DESERIALIZE", "deserialize"),
    ("ois.readUnshared", "CG-DESERIALIZE", "deserialize"),
])
def test_java_sinks_resolve(call_name, rule_id, vuln):
    sink = lookup_sink(call_name, "java")
    assert sink is not None, call_name
    assert sink.rule_id == rule_id
    assert sink.vuln_class == vuln


def test_java_non_sink_is_none():
    assert lookup_sink("logger.info", "java") is None
    assert lookup_sink("list.add", "java") is None


def test_other_languages_unchanged():
    assert lookup_sink("os.system", "python").rule_id == "CG-CMD-EXEC"
    assert lookup_sink("pickle.loads", "python").rule_id == "CG-DESERIALIZE"
    assert lookup_sink("stmt.executeQuery", "python") is None
    assert lookup_sink("db.query", "javascript").rule_id == "CG-SQL-EXEC"
```

- [ ] **Step 2: Run to verify it fails** — `pytest tests/test_sinks_java.py -v` → FAIL.

- [ ] **Step 3: Implement.** In `sinks.py`, add after `_GO`:

```python
_JAVA: tuple[Sink, ...] = (
    # SQL (bare method names)
    Sink("executeQuery", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("executeUpdate", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("execute", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("query", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("update", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("createNativeQuery", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("createQuery", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    # Command (bare; Runtime.exec / ProcessBuilder / .start)
    Sink("exec", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    Sink("ProcessBuilder", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    Sink("start", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    # Path (bare; incl. constructor sinks File / FileReader / FileWriter / FileInputStream)
    Sink("File", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("FileReader", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("FileWriter", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("FileInputStream", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("readAllBytes", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("write", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    # Deserialization
    Sink("readObject", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         "rebuilds objects from this stream, which can run code", "deserialize", bare=True),
    Sink("readUnshared", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         "rebuilds objects from this stream, which can run code", "deserialize", bare=True),
)
```

Add `"java": _JAVA` to `_BY_LANGUAGE`.

> The `_DESERIALIZE` plain-text constant already exists in `sinks.py` (Python uses it); reuse it instead of the inline string if present. Confirm `test_java_non_sink_is_none` holds — `logger.info`/`list.add` have no bare `info`/`add` entry.

- [ ] **Step 4: Run + ruff.** `pytest tests/test_sinks_java.py -v` PASS; `ruff check` clean.
- [ ] **Step 5: Commit** — `feat(sinks): register Java SQL/command/path/deserialization sinks`.

---

## Task 2: `java_provenance.py` — classifier + assessor + deserialization rule

**Files:** Create `src/cybergraph/analysis/java_provenance.py`; Test `tests/test_java_provenance.py` (create).

**Interfaces:** `extract_first_arg`, `extract_all_args`, `classify`, `variable_names`, `assess`, `assess_command`, `assess_deserialization`. Same contract/cardinal rule as go_provenance.

**Approach:** START from `src/cybergraph/analysis/go_provenance.py` (final, reviewed — positive-literal-proof + `assess_command`). Port verbatim: `extract_first_arg`, `extract_all_args`, `_split_plus`, `_is_proven_literal_operand`, `_operand_candidates`, `assess`, `assess_command`. Adapt to Java:
1. **`String.format(fmt, args…)`** → COMPOSED (assess ALL args incl. the format arg, like Go's `fmt.Sprintf`).
2. **`StringBuilder`/`.append(x)` chains** → COMPOSED; extract each appended operand as a candidate via the positive-literal-proof helpers.
3. Java string literals are `"…"` (no raw/backtick strings; no `${}`). Drop any JS/Go-specific literal forms not valid in Java, keep `"…"`.
4. **New: `assess_deserialization(tainted_present: bool) -> str`** — native deser is never SAFE: `VERDICT_UNSAFE` if a tainted stream/value reaches the call, else `VERDICT_UNKNOWN`. (No argument classification — `readObject()`/`readUnshared()` take no argument.)

- [ ] **Step 1: Write the failing test**

Create `tests/test_java_provenance.py`:

```python
from __future__ import annotations

from cybergraph.analysis.java_provenance import (
    assess, assess_command, assess_deserialization, classify,
)
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE
from cybergraph.security.sinks import lookup_sink


def _sql():
    return lookup_sink("stmt.executeQuery", "java")


def test_classify():
    assert classify('"SELECT 1"') == "literal"
    assert classify('"SELECT " + id') == "composed"
    assert classify('String.format("SELECT %s", id)') == "composed"
    assert classify("sb.append(id).toString()") == "composed" or classify("sb.append(id)") == "composed"
    assert classify("buildQuery()") == "opaque"


def test_assess_sql_literal_safe():
    assert assess(_sql(), '"SELECT 1"', set()) == VERDICT_SAFE


def test_assess_sql_concat_tainted_unsafe():
    assert assess(_sql(), '"SELECT * FROM u WHERE id = " + id', {"id"}) == VERDICT_UNSAFE


def test_assess_sql_format_variable_format_unsafe():
    assert assess(_sql(), "String.format(userFmt, x)", {"userFmt"}) == VERDICT_UNSAFE


def test_assess_sql_unresolved_unknown():
    assert assess(_sql(), '"SELECT " + id', set()) == VERDICT_UNKNOWN


def test_assess_command_shell_tainted_unsafe():
    cmd = lookup_sink("Runtime.exec", "java")
    assert assess_command(['"sh"', '"-c"', "userCmd"], {"userCmd"}) == VERDICT_UNSAFE
    assert assess_command(['"ls"', '"-la"'], set()) == VERDICT_SAFE


def test_deserialization_never_safe():
    assert assess_deserialization(True) == VERDICT_UNSAFE     # tainted stream
    assert assess_deserialization(False) == VERDICT_UNKNOWN   # unresolved -> still not safe
```

- [ ] **Step 2: Run to verify it fails** — FAIL (ModuleNotFoundError).
- [ ] **Step 3: Implement** — port go_provenance + the four adaptations above. `assess_deserialization` is a two-line rule (tainted→UNSAFE else UNKNOWN). Confirm `provenance.LITERAL/…` and `predicates.VERDICT_*` imports; do not redefine.
- [ ] **Step 4: Run + ruff** — `pytest tests/test_java_provenance.py -v` PASS; ruff clean.
- [ ] **Step 5: Commit** — `feat(analysis): Java construction classifier, command + deserialization assessors`.

---

## Task 3: Java routing with a dedicated sink-call matcher

**Files:** Modify `src/cybergraph/analysis/java.py`; Test `tests/test_java_verdicts_e2e.py` (create).

**THE JAVA-SPECIFIC PROBLEM (this task's crux):** `java.py`'s existing `CALL_RE` requires a dotted name before `(`, so it **misses** the most common Java sink forms — verified:
- `Runtime.getRuntime().exec(cmd)` → matches only `Runtime.getRuntime`, NOT `.exec(cmd)`.
- `new File(path)`, `new ObjectInputStream(in).readObject()`, `new ProcessBuilder(args).start()` → match **nothing** (constructor / post-`)` chained call).

So the verdict path cannot use `CALL_RE` to locate these sinks or their arguments. It needs a dedicated matcher.

**Interfaces:** a graded verdict for a resolved Java sink (SQL/path first-arg `assess`; command all-args `assess_command`; deserialization `assess_deserialization`), replacing `CG-JAVA-SINK-CALL` for those sinks; other sinks stay inventory.

- [ ] **Step 1: Write the failing test**

Create `tests/test_java_verdicts_e2e.py`:

```python
from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.java import analyze_java_file


def _rules(tmp_path, src):
    p = tmp_path / "A.java"
    p.write_text(src, encoding="utf-8")
    _n, _e, findings = analyze_java_file(p, tmp_path)
    return [f.rule_id for f in findings]


def test_prepared_statement_is_safe(tmp_path):
    src = ("class A { void h(java.sql.Connection c, String id) throws Exception {\n"
           "  var ps = c.prepareStatement(\"SELECT * FROM u WHERE id = ?\");\n"
           "  ps.setString(1, id); ps.executeQuery(); } }\n")
    rules = _rules(tmp_path, src)
    assert "CG-SQL-EXEC" not in rules  # executeQuery() has no string arg -> not a string-SQL sink


def test_concat_sqli_is_unsafe(tmp_path):
    src = ("class A { void h(java.sql.Statement st, javax.servlet.http.HttpServletRequest req) throws Exception {\n"
           "  String id = req.getParameter(\"id\");\n"
           "  st.executeQuery(\"SELECT * FROM u WHERE id = \" + id); } }\n")
    assert "CG-SQL-EXEC" in _rules(tmp_path, src)


def test_new_file_user_path_is_flagged(tmp_path):
    src = ("class A { void h(javax.servlet.http.HttpServletRequest req) throws Exception {\n"
           "  String p = req.getParameter(\"p\");\n"
           "  new java.io.File(p); } }\n")
    rules = _rules(tmp_path, src)
    assert "CG-PATH-TRAVERSAL" in rules  # new File(...) constructor sink, CALL_RE would miss it


def test_runtime_exec_chained_is_flagged(tmp_path):
    src = ("class A { void h(javax.servlet.http.HttpServletRequest req) throws Exception {\n"
           "  String c = req.getParameter(\"c\");\n"
           "  Runtime.getRuntime().exec(new String[]{\"sh\", \"-c\", c}); } }\n")
    assert "CG-CMD-EXEC" in _rules(tmp_path, src)  # chained .exec(...) after )


def test_readobject_never_safe(tmp_path):
    src = ("class A { Object h(javax.servlet.http.HttpServletRequest req) throws Exception {\n"
           "  var ois = new java.io.ObjectInputStream(req.getInputStream());\n"
           "  return ois.readObject(); } }\n")
    rules = _rules(tmp_path, src)
    assert "CG-DESERIALIZE" in rules or "CG-DESERIALIZE-UNVERIFIED" in rules
```

> Note: confirm how a name enters `java.py`'s per-line `tainted` set (via `INPUT_MARKERS` like `getParameter`/`getInputStream`) so the UNSAFE cases genuinely exercise taint; adjust fixtures to java.py's taint model. For `readObject`, "tainted stream" = the `ObjectInputStream` built from `req.getInputStream()` — if wiring receiver-taint is intricate, it is acceptable for `readObject` to read UNKNOWN (never SAFE) when taint cannot confirm; the test allows either the confirmed or the `-UNVERIFIED` rule id, but NEVER absent.

- [ ] **Step 2: Run to verify it fails** — FAIL (sinks not graded / not detected).

- [ ] **Step 3: Implement the dedicated matcher + routing**

Add a Java sink-call matcher in `java.py` that finds registered sinks regardless of chaining/constructors, over the whole `source` (offset-correct):

```python
# Matches a sink call the general CALL_RE misses: a constructor `new Ctor(` or a
# method call `.method(` (including one that follows a `)` in a chain).
_JAVA_SINK_CALL_RE = re.compile(r"\bnew\s+(?P<ctor>[A-Z]\w*)\s*\(|\.(?P<method>[A-Za-z_]\w*)\s*\(")
```

For each match: `name = m.group("ctor") or m.group("method")`; `sink = lookup_sink(name, "java")`; if `sink is None`, skip (not a verdict sink — leave to the legacy inventory scan). Otherwise:
- `open_paren = m.end() - 1`; `line_no = source.count("\n", 0, m.start()) + 1`.
- Resolve the tainted-name set for that line/function (reuse java.py's `tainted_by_function`; the function owning `line_no`). A conservative function-local `set(tainted)` is acceptable (fail-safe), as in Go/JS.
- **Zero-argument guard (precision — port Go's):** a `sql`/`path`/`command` sink call with an EMPTY argument list is NOT a string-injection sink and is skipped (emit nothing). This is essential for Java: `ps.executeQuery()` (a PreparedStatement execution — the query was set safely via `prepareStatement("…?")`) and `pb.start()` (the command lives in the `new ProcessBuilder(...)` constructor, which is matched and assessed separately) have empty parens; without the guard every PreparedStatement would false-flag. **Deserialization is EXEMPT** — `readObject()`/`readUnshared()` are zero-argument by nature and must still be assessed (never-SAFE). So: skip empty-arg SQL/path/command; always assess deserialization. (Distinguish a genuinely empty `()` from an unreadable/unbalanced arg, which stays UNKNOWN — same as Go's guard.)
- Dispatch by `sink.vuln_class`:
  - `sql`/`path`: `arg = extract_first_arg(source, open_paren)`; `verdict = assess(sink, arg, tainted)`.
  - `command`: `args = extract_all_args(source, open_paren)`; `verdict = assess_command(args, tainted)`.
  - `deserialize`: `verdict = assess_deserialization(tainted_present)` where `tainted_present` reflects whether a tainted value is in scope for that call (fail-safe: if unknown, `False` → UNKNOWN, never SAFE).
- Emit the graded finding (UNSAFE→`sink.rule_id`, UNKNOWN→`+"-UNVERIFIED"`, SAFE→none), honoring `is_inline_suppressed`.

**De-duplication:** a resolved verdict sink must not ALSO emit a legacy `CG-JAVA-SINK-CALL` for the same call. Where the legacy `CALL_RE + _is_sink` scan and the new matcher both fire for one logical sink, suppress the legacy inventory for it (e.g. the legacy scan skips a `call_name` whose bare tail resolves via `lookup_sink(call_name,"java")`). A co-emitted inventory finding on a chain's *intermediate* call (e.g. `Runtime.getRuntime`, which is not itself a registry sink) is SARIF-filtered and a tolerable minor — do not over-engineer, but the SAME sink must never double-emit.

> Integrate the matcher with java.py's existing per-line loop OR run it as a second pass over `source` after the loop populates `tainted_by_function`. A second pass is cleaner (taint is fully known); map each match's `line_no` to its function via the same logic java.py uses to track `current_function`. Pin the exact integration; keep `EDGE_REACHES_SINK`/`EDGE_TAINTS` behavior for detected sinks.

- [ ] **Step 4: Run + ruff** — `pytest tests/test_java_verdicts_e2e.py tests/test_java*.py -v` PASS (update stale inventory expectations if any); ruff clean.
- [ ] **Step 5: Commit** — `feat(analysis): grade Java SQL/command/path/deserialization sinks (dedicated matcher)`.

---

## Task 4: Broaden four capabilities to Java

**Files:** Modify `capability.py`, `coverage.py`; Test `tests/test_java_verdicts_e2e.py` (append).

**Interfaces:** `JAVA_GLOBS = ("*.java",)`; `sql_construction`/`command_execution`/`path_access`/**`deserialization`** covers += `JAVA_GLOBS`; coverage verified gate += `JAVA_GLOBS`. `code_execution`, `VERIFIED_GLOBS` unchanged.

- [ ] **Step 1: Write the failing test** — append to `tests/test_java_verdicts_e2e.py`:

```python
import subprocess
from cybergraph.security.capability import CAPABILITIES, FAIL, NOT_SUPPORTED
from cybergraph.security.check import check_change
from cybergraph.security.verdict import STATE_REVIEW


def _cap(cid):
    return next(c for c in CAPABILITIES if c.id == cid)


def test_four_capabilities_cover_java():
    for cid in ("sql_construction", "command_execution", "path_access", "deserialization"):
        assert "*.java" in _cap(cid).covers, cid
    assert "*.java" not in _cap("code_execution").covers


def _repo(tmp_path):
    repo = tmp_path / "r"; repo.mkdir()
    for a in (["init","-q"],["config","user.email","t@e.com"],["config","user.name","t"]):
        subprocess.run(["git","-C",str(repo),*a], check=True)
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    subprocess.run(["git","-C",str(repo),"add","."], check=True)
    subprocess.run(["git","-C",str(repo),"commit","-q","-m","base"], check=True)
    return repo


def test_java_sqli_reviews(tmp_path):
    repo = _repo(tmp_path)
    (repo / "A.java").write_text(
        "class A { void h(java.sql.Statement st, javax.servlet.http.HttpServletRequest req) throws Exception {\n"
        "  String id = req.getParameter(\"id\");\n"
        "  st.executeQuery(\"SELECT * FROM u WHERE id = \" + id); } }\n", encoding="utf-8")
    v = check_change(repo, mode="worktree")
    assert v.state == STATE_REVIEW
    assert any(c.capability_id == "sql_construction" and c.status == FAIL for c in v.checks)


def test_java_still_not_supported_overall(tmp_path):
    repo = _repo(tmp_path)
    (repo / "A.java").write_text("class A { int x = 1; }\n", encoding="utf-8")
    v = check_change(repo, mode="worktree")
    assert any(c.capability_id == "source_analysis_support" and c.status == NOT_SUPPORTED
               for c in v.checks)
```

- [ ] **Step 2: Run to verify it fails.**
- [ ] **Step 3: Implement** — `capability.py`: add `JAVA_GLOBS = ("*.java",)`; append `+ JAVA_GLOBS` to `sql_construction`/`command_execution`/`path_access` covers; change `deserialization` from `PYTHON_GLOBS` to `PYTHON_GLOBS + JAVA_GLOBS`. `coverage.py`: import `JAVA_GLOBS`, add to the verified gate (`… + WEB_GLOBS + GO_GLOBS + JAVA_GLOBS`).
- [ ] **Step 4: Run + ruff** — target suites PASS (update stale relevance expectations); ruff clean.
- [ ] **Step 5: Commit** — `feat(verdict): SQL/command/path/deserialization capabilities now cover Java`.

---

## Task 5: Mutations + docs + full verification

**Files:** Modify `benchmark/mutation_harness.py`, `README.md`, `docs/CRITICAL_AUDIT.md`.

- [ ] **Step 1: Add mutations** (match `old` to committed `java_provenance.py`/`java.py` verbatim, each unique):
  - `D9-java-tainted-sink-reads-safe` — flip the assessor's taint→UNSAFE to SAFE; map to `test_assess_sql_concat_tainted_unsafe`.
  - `D9-java-unresolved-var-reads-safe` — flip unresolved→UNKNOWN to SAFE; map to `test_assess_sql_unresolved_unknown`.
  - `D9-java-deser-reads-safe` — flip `assess_deserialization` so it returns SAFE; map to `test_deserialization_never_safe`.
  Run `python benchmark/mutation_harness.py` → all CAUGHT.
- [ ] **Step 2: Docs** — README: a bullet that Java now earns real SQL/command/path/deserialization verdicts. `docs/CRITICAL_AUDIT.md` §4.5: "resolved for JS, Go, and Java core classes; C# and other classes remain inventory-grade." NOT fully closed.
- [ ] **Step 3: Full verification** — `pytest -q` all pass; `ruff check .` no new errors; `python benchmark/mutation_harness.py` all CAUGHT; `python benchmark/run_precision.py` gate PASSED; `python benchmark/run_eval.py` precision/recall unchanged (git checkout benchmark/results.json after; do NOT commit it) — confirm Python/JS/Go corpora identical (Java registry is language-keyed).
- [ ] **Step 4: Commit** — `test(java): seed Java verdict fail-open mutations; document the upgrade`.

---

## Notes for the executor

- **Precision is cardinal.** Only all-literal/constant is SAFE; native deserialization is never SAFE. Port the Go positive-literal-proof + `assess_command` exactly — do not re-derive a looser version.
- **Task 3 is the hard one:** the dedicated `_JAVA_SINK_CALL_RE` must catch constructors (`new File(...)`, `new ProcessBuilder(...)`) and chained calls (`Runtime.getRuntime().exec(...)`, `ois.readObject()`) that the existing `CALL_RE` misses — the e2e tests (`test_new_file_user_path_is_flagged`, `test_runtime_exec_chained_is_flagged`, `test_readobject_never_safe`) force this. No SAME-sink double-emission with the legacy inventory path.
- Confirm names/signatures against source before running each task's tests (`provenance.*`, `Sink`, `check_change`/`Verdict.checks`, java.py taint); adapt the test to reality, never the reverse.
- Do NOT add a Java parser dependency, Java code/SpEL/JNDI detection, `*.java` in `VERIFIED_GLOBS`, or interprocedural flow — out of scope.

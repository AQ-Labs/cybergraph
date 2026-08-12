# C# Verdicts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Graduate the C# analyzer from inventory-only `CG-CSHARP-SINK-CALL` findings to real ACCEPT/REVIEW verdicts for SQL, command, path, deserialization, and code-execution.

**Architecture:** Mirror the Java slice (#53). A language-keyed `_CSHARP` sink registry, a fail-safe construction classifier `csharp_provenance.py` ported from the hardened `java_provenance.py` plus C#-specific string-interpolation/verbatim handling, routing in `csharp.py` via a dedicated constructor/chained-call matcher, and capability/coverage broadened to `*.cs` — with `VERIFIED_GLOBS` unchanged so C# stays honestly NOT_SUPPORTED for whole-file source-analysis.

**Tech Stack:** Python 3.10+, stdlib only. Reuses `src/cybergraph/analysis/_source_text.py` (which already models C# comments, verbatim `@"..."`, and interpolation holes) and `src/cybergraph/analysis/java_provenance.py` (the reference classifier).

**Spec:** `docs/superpowers/specs/2026-08-12-csharp-verdicts-design.md`.

## Global Constraints

- stdlib only; `from __future__ import annotations` at the top of every new module.
- Reuse Python's existing rule ids — SQL→`CG-SQL-EXEC`, command→`CG-CMD-EXEC`, path→`CG-PATH-TRAVERSAL`, deserialization→`CG-DESERIALIZE`, code→`CG-CODE-EXEC`. Invent no new rule-id strings.
- Reuse the existing `_SQL` / `_CMD` / `_DESERIALIZE` plain-text constants in `sinks.py` (do not duplicate literals).
- Cardinal rule: only an all-literal/constant construction reads SAFE; any variable/non-literal/unknown/unreadable operand → UNSAFE (taint-confirmed) or UNKNOWN, never SAFE. `assess_deserialization` is never SAFE.
- `VERIFIED_GLOBS` stays Python-only — C# remains `NOT_SUPPORTED` for `source_analysis_support`.
- ruff clean on every touched file (no new errors vs the ~pre-existing baseline).
- Tests assert EXACT verdicts (`== VERDICT_*`), never `!= VERDICT_SAFE` and never assertion-free.
- Commits authored `Laraib <lxh417bham@gmail.com>` with a plain `git commit` — never pass `-c user.email`; no Co-Authored-By / AI attribution; never squash. Do not push during task implementation. Push only to `AQ-Labs/cybergraph`.
- After each task: the full suite (`python -m pytest -q`) stays green; the mutation harness (`python benchmark/mutation_harness.py`) all-caught and the precision gate (`python benchmark/run_precision.py` → `GATE PASSED`) are verified at Task 5.

## File Structure

- `src/cybergraph/security/sinks.py` — add `_CSHARP` tuple + `_BY_LANGUAGE["csharp"]`. (Task 1)
- `src/cybergraph/analysis/csharp_provenance.py` — NEW; the fail-safe classifier. (Task 2)
- `src/cybergraph/analysis/csharp.py` — add verdict routing + `_CSHARP_SINK_CALL_RE`. (Task 3)
- `src/cybergraph/security/capability.py` + `coverage.py` — `CSHARP_GLOBS`, broadened capabilities, verified-gate. (Task 4)
- `benchmark/mutation_harness.py`, `README.md`, `docs/CRITICAL_AUDIT.md` — mutations + docs. (Task 5)
- Tests: `tests/test_sinks_csharp.py`, `tests/test_csharp_provenance.py`, `tests/test_csharp_verdicts_e2e.py`, and additions to `tests/test_coverage.py` / `tests/test_capability.py`.

---

### Task 1: C# sink registry (`_CSHARP`)

**Files:**
- Modify: `src/cybergraph/security/sinks.py` (add `_CSHARP` after `_JAVA`; add `"csharp": _CSHARP` to `_BY_LANGUAGE`)
- Test: `tests/test_sinks_csharp.py` (create)

**Interfaces:**
- Consumes: the existing `Sink` dataclass, `SEVERITY_HIGH`/`SEVERITY_CRITICAL`, `SHELL_CONDITIONAL`, `_SQL`/`_CMD`/`_DESERIALIZE`, `lookup_sink(call_name, language)`.
- Produces: `lookup_sink(name, "csharp")` resolving C# sinks; consumed by Task 3.

- [ ] **Step 1: Write the failing test** — `tests/test_sinks_csharp.py`:

```python
from __future__ import annotations

from cybergraph.security.sinks import lookup_sink


def test_csharp_sql_sinks():
    for name in ("cmd.ExecuteReader", "db.Query", "conn.ExecuteScalarAsync"):
        s = lookup_sink(name, "csharp")
        assert s is not None and s.rule_id == "CG-SQL-EXEC" and s.vuln_class == "sql"


def test_csharp_command_sink_is_shell_conditional():
    from cybergraph.security.sinks import SHELL_CONDITIONAL
    s = lookup_sink("Process.Start", "csharp")
    assert s is not None and s.rule_id == "CG-CMD-EXEC"
    assert s.vuln_class == "command" and s.shell == SHELL_CONDITIONAL


def test_csharp_path_and_deserialization_and_code():
    assert lookup_sink("File.ReadAllText", "csharp").rule_id == "CG-PATH-TRAVERSAL"
    assert lookup_sink("formatter.Deserialize", "csharp").rule_id == "CG-DESERIALIZE"
    assert lookup_sink("reader.ReadObject", "csharp").rule_id == "CG-DESERIALIZE"
    assert lookup_sink("CSharpScript.EvaluateAsync", "csharp").rule_id == "CG-CODE-EXEC"


def test_no_cross_language_leakage():
    assert lookup_sink("cmd.ExecuteReader", "python") is None
    assert lookup_sink("cmd.ExecuteReader", "java") is None
    # existing languages still resolve
    assert lookup_sink("pickle.loads", "python").rule_id == "CG-DESERIALIZE"
    assert lookup_sink("db.Query", "go").rule_id == "CG-SQL-EXEC"
```

- [ ] **Step 2: Run to verify it fails** — `python -m pytest tests/test_sinks_csharp.py -q` → FAIL (`lookup_sink(..., "csharp")` returns None).

- [ ] **Step 3: Implement** — in `sinks.py`, after the `_JAVA` tuple and before `_BY_LANGUAGE`, add (all method-name sinks `bare=True`; reuse `_SQL`/`_CMD`/`_DESERIALIZE`):

```python
_CSHARP: tuple[Sink, ...] = (
    # SQL (bare method names + Dapper); constructor SqlCommand handled by the analyzer's matcher.
    Sink("ExecuteReader", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecuteNonQuery", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecuteScalar", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecuteReaderAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecuteNonQueryAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecuteScalarAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("Query", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("Execute", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("ExecuteAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryFirst", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryFirstAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QuerySingle", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QuerySingleAsync", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QueryFirstOrDefault", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("QuerySingleOrDefault", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    # SQL command constructors (matched by the analyzer on the type name).
    Sink("SqlCommand", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("MySqlCommand", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("NpgsqlCommand", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("OracleCommand", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("SqliteCommand", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    # Command (Process.Start / new ProcessStartInfo); shell only when the program is a shell.
    Sink("Start", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    Sink("ProcessStartInfo", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    # Path (bare methods + constructors StreamReader/StreamWriter/FileStream/FileInfo).
    Sink("ReadAllText", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("WriteAllText", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("ReadAllBytes", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("WriteAllBytes", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("ReadAllLines", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("OpenRead", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("OpenWrite", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("OpenText", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("Delete", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("StreamReader", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("StreamWriter", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("FileStream", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("FileInfo", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    # Deserialization (bare Deserialize/ReadObject -- covers the ysoserial.net formatters).
    Sink("Deserialize", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         _DESERIALIZE, "deserialize", bare=True),
    Sink("ReadObject", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         _DESERIALIZE, "deserialize", bare=True),
    # Code execution (exact dotted names, NOT bare).
    Sink("CSharpScript.EvaluateAsync", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    Sink("CSharpScript.RunAsync", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    Sink("CSharpScript.Create", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    Sink("CSharpCodeProvider.CompileAssemblyFromSource", "CG-CODE-EXEC", "CWE-95",
         SEVERITY_CRITICAL, "runs this value as program code", "code"),
)
```

Then register in `_BY_LANGUAGE`: add the line `"csharp": _CSHARP,` after the `"java": _JAVA,` entry.

- [ ] **Step 4: Run to verify it passes** — `python -m pytest tests/test_sinks_csharp.py -q` → PASS. `python -m ruff check src/cybergraph/security/sinks.py tests/test_sinks_csharp.py` → clean.

- [ ] **Step 5: Commit** — `git add src/cybergraph/security/sinks.py tests/test_sinks_csharp.py && git commit -m "feat(sinks): register C# SQL/command/path/deserialization/code-exec sinks"`

---

### Task 2: C# construction-provenance classifier (`csharp_provenance.py`)

**Files:**
- Create: `src/cybergraph/analysis/csharp_provenance.py`
- Test: `tests/test_csharp_provenance.py` (create)

**Interfaces:**
- Consumes: `provenance` module's `LITERAL`/`COMPOSED`/`OPAQUE`; `VERDICT_SAFE`/`VERDICT_UNSAFE`/`VERDICT_UNKNOWN` from `cybergraph.security.predicates`; `Sink` from `cybergraph.security.sinks`.
- Produces (identical signatures to `java_provenance.py`, so Task 3 consumes them the same way): `assess(sink, arg_text, tainted_names) -> str`, `assess_command(args, tainted_names) -> str`, `assess_deserialization(tainted_present: bool) -> str`, `classify(arg_text) -> str`, `variable_names(arg_text) -> list[str]`.

**Porting instruction:** copy `src/cybergraph/analysis/java_provenance.py` verbatim as the starting point (it is the most hardened classifier — it survived seven fail-open rounds: string-literal `.append(` hijack, unbalanced-quote swallow, trailing-call coverage, tainted/variable receiver, non-allowlisted `new X(...)`, package-qualified spoof, opaque bare-call receiver). Keep ALL of its machinery (`extract_first_arg`, `extract_all_args`, `_split_plus`, `_is_proven_literal_operand`, `_operand_candidates`, `_matching_close_paren`, `_chain_receiver`, `_is_bare_call_receiver`, `_chain_operand_candidates`, `_call_open_parens_generic`, `_dedup`, `classify`, `assess`, `assess_command`, `assess_deserialization`). Then apply the C#-specific deltas below. Do NOT re-derive a looser version.

**C#-specific delta 1 — interpolation-hole extraction.** C# string interpolation `$"...{expr}..."` is the dominant real-world injection shape. Add a helper that returns the hole expressions of an interpolated-string argument, verbatim/`""`-aware, format/alignment-suffix stripped:

- [ ] **Step 1: Write the failing tests** — `tests/test_csharp_provenance.py`:

```python
from __future__ import annotations

from cybergraph.analysis.csharp_provenance import (
    assess, assess_command, assess_deserialization, classify, variable_names,
)
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE
from cybergraph.security.sinks import lookup_sink


def _sql():
    return lookup_sink("cmd.ExecuteReader", "csharp")


# --- interpolation ---------------------------------------------------------
def test_interpolation_tainted_hole_is_unsafe():
    assert assess(_sql(), '$"SELECT * FROM u WHERE id = {id}"', {"id"}) == VERDICT_UNSAFE

def test_interpolation_unresolved_hole_is_unknown_never_safe():
    assert assess(_sql(), '$"SELECT * FROM u WHERE id = {id}"', set()) == VERDICT_UNKNOWN

def test_interpolation_all_literal_holes_is_safe():
    # holes are literals/constants -> the whole interpolation is constant
    assert assess(_sql(), '$"SELECT * FROM u LIMIT {10}"', set()) == VERDICT_SAFE

def test_interpolation_no_holes_is_safe():
    assert assess(_sql(), '$"SELECT * FROM users"', set()) == VERDICT_SAFE

def test_interpolation_format_and_alignment_suffix_stripped():
    # `{total,10:C}` -> operand `total`; still non-literal -> not safe
    assert assess(_sql(), '$"total = {total,10:C}"', {"total"}) == VERDICT_UNSAFE

def test_interpolation_escaped_braces_are_literal():
    assert assess(_sql(), '$"a literal brace {{ and id {id}}}"', {"id"}) == VERDICT_UNSAFE
    assert assess(_sql(), '$"just braces {{no hole}}"', set()) == VERDICT_SAFE

def test_interpolated_verbatim_quote_in_body_does_not_desync():
    # $@"..." : "" is an escaped quote, not the end; the {id} hole is still seen
    assert assess(_sql(), '$@"WHERE name = ""x"" AND id = {id}"', {"id"}) == VERDICT_UNSAFE

def test_verbatim_string_no_hole_is_safe():
    assert assess(_sql(), '@"SELECT * FROM users"', set()) == VERDICT_SAFE

def test_classify_interpolation_with_hole_is_composed():
    assert classify('$"id = {id}"') == "composed"
    assert classify('$"no holes"') == "literal"

def test_variable_names_reports_interpolation_holes():
    assert "id" in variable_names('$"id = {id}"')


# --- inherited (ported from java) ------------------------------------------
def test_concat_tainted_is_unsafe():
    assert assess(_sql(), '"SELECT * WHERE id = " + id', {"id"}) == VERDICT_UNSAFE

def test_string_format_tainted_is_unsafe():
    assert assess(_sql(), 'string.Format("id = {0}", id)', {"id"}) == VERDICT_UNSAFE

def test_stringbuilder_all_literal_variable_receiver_never_safe():
    assert assess(_sql(), 'sb.Append("a").Append("b")', set()) == VERDICT_UNKNOWN

def test_plain_literal_is_safe():
    assert assess(_sql(), '"SELECT 1"', set()) == VERDICT_SAFE


# --- command / deserialization ---------------------------------------------
def test_command_shell_form_all_args_assessed():
    cmd = lookup_sink("Process.Start", "csharp")
    assert assess_command(['"cmd"', '"/c"', "user"], {"user"}) == VERDICT_UNSAFE
    assert assess_command(['"cmd"', '"/c"', '"dir"'], set()) == VERDICT_SAFE

def test_deserialization_is_never_safe():
    assert assess_deserialization(True) == VERDICT_UNSAFE
    assert assess_deserialization(False) == VERDICT_UNKNOWN
```

- [ ] **Step 2: Run to verify they fail** — `python -m pytest tests/test_csharp_provenance.py -q` → FAIL (module missing).

- [ ] **Step 3: Implement** — copy `java_provenance.py` → `csharp_provenance.py`, then apply the deltas:

(a) Add the interpolation-hole scanner. It walks an interpolated string (`$"`, `$@"`, `@$"` openers), collecting the expression inside each `{...}` hole, treating `{{`/`}}` as literal braces, respecting `""` as an escaped quote inside verbatim forms, and stripping a trailing `,alignment` / `:format` from each hole expression (split on the first top-level `,` or `:` not inside brackets/quotes):

```python
_INTERP_OPENERS = ('$@"', '@$"', '$"')  # tried longest-first


def _interp_holes(arg_text: str) -> list[str] | None:
    """Hole expressions of a C# interpolated-string literal, or None if arg_text
    is not a single interpolated string. `{{`/`}}` are literal braces; in the
    verbatim forms `""` is an escaped quote. Each hole's `,align`/`:format`
    suffix is stripped. A returned empty list means an interpolated string with
    no holes (a constant)."""
    s = arg_text.strip()
    verbatim = s.startswith(('$@"', '@$"'))
    opener = next((o for o in _INTERP_OPENERS if s.startswith(o)), None)
    if opener is None:
        return None
    i = len(opener)
    n = len(s)
    holes: list[str] = []
    while i < n:
        c = s[i]
        if c == '"':
            if verbatim and i + 1 < n and s[i + 1] == '"':
                i += 2
                continue
            if not verbatim and c == '"' and s[i - 1] == "\\":
                i += 1
                continue
            return holes  # end of the string literal
        if c == "{":
            if i + 1 < n and s[i + 1] == "{":
                i += 2
                continue
            depth = 1
            j = i + 1
            while j < n and depth:
                if s[j] == "{":
                    depth += 1
                elif s[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            holes.append(_strip_interp_suffix(s[i + 1:j]))
            i = j + 1
            continue
        if c == "}" and i + 1 < n and s[i + 1] == "}":
            i += 2
            continue
        i += 1
    return holes


def _strip_interp_suffix(expr: str) -> str:
    """Drop a C# interpolation `,alignment` / `:format` suffix, ignoring commas/
    colons inside quotes, (), [] or {}."""
    depth = 0
    quote: str | None = None
    for k, ch in enumerate(expr):
        if quote is not None:
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and ch in ",:":
            return expr[:k].strip()
    return expr.strip()
```

(b) Route interpolation through the existing operand machinery. In `classify`, before the final `return OPAQUE`, add:

```python
    holes = _interp_holes(arg_text)
    if holes is not None:
        return COMPOSED if holes else LITERAL
```

In `assess`, in the COMPOSED branch, handle the interpolation case by feeding holes to `_operand_candidates` (same "names or unresolved -> never SAFE" logic the ported code already uses for `+`/format operands):

```python
    holes = _interp_holes(arg_text)
    if holes is not None:
        if not holes:
            return VERDICT_SAFE  # interpolated string with only literal text
        names, unresolved = _operand_candidates(holes)
        if any(n in tainted_names for n in names):
            return VERDICT_UNSAFE
        if names or unresolved:
            return VERDICT_UNKNOWN
        return VERDICT_SAFE
```

In `variable_names`, add near the top: `holes = _interp_holes(arg_text); if holes is not None: return _dedup(_operand_candidates(holes)[0])`.

(c) Verbatim/interpolated-string awareness in the quote scanners: the ported `java_provenance` quote scanners treat `"` with `\"` escaping. For C#, a top-level `+`-concatenation or call-chain argument may contain `@"..."`/`$"..."` operands. The ported `_is_proven_literal_operand` must recognize a C# string literal in all its forms (`"..."`, `@"..."`, `$"..."` with no holes, `$@"..."`/`@$"..."` with no holes) as a proven literal. Extend `_is_proven_literal_operand` so that: if `_interp_holes(operand)` returns `[]` (an interpolated/verbatim string with no holes) it is a proven literal; if it returns a non-empty list it is NOT a proven literal (it is a composition). Plain `@"..."`/`"..."` string literals remain proven literals.

- [ ] **Step 4: Run to verify they pass** — `python -m pytest tests/test_csharp_provenance.py -q` → PASS (all). `python -m ruff check src/cybergraph/analysis/csharp_provenance.py tests/test_csharp_provenance.py` → clean.

- [ ] **Step 5: Commit** — `git add src/cybergraph/analysis/csharp_provenance.py tests/test_csharp_provenance.py && git commit -m "feat(analysis): C# construction classifier (java port + interpolation/verbatim)"`

---

### Task 3: C# verdict routing (`csharp.py`)

**Files:**
- Modify: `src/cybergraph/analysis/csharp.py`
- Test: `tests/test_csharp_verdicts_e2e.py` (create)

**Interfaces:**
- Consumes: `lookup_sink(name, "csharp")` (Task 1); `assess`/`assess_command`/`assess_deserialization` (Task 2); the existing `analyze_csharp_file` entry point, `tainted_by_function`, `_tainted_source_for_line`, `INPUT_MARKERS`, `Finding`; and `strip_code(source, "csharp")` from `cybergraph.analysis._source_text` for comment/string-blanked grading.
- Produces: `analyze_csharp_file` emitting real verdict rule ids (`CG-SQL-EXEC` / `CG-CMD-EXEC` / `CG-PATH-TRAVERSAL` / `CG-DESERIALIZE` / `CG-CODE-EXEC`, with `-UNVERIFIED` suffix for UNKNOWN) instead of the flat `CG-CSHARP-SINK-CALL` for resolved sinks.

**Reference:** `src/cybergraph/analysis/java.py` — mirror its Task-3 wiring exactly (dedicated matcher, dispatch by `vuln_class`, zero-arg guard with deserialization exemption, comment-blanked grading, de-dup vs the legacy inventory row, `-UNVERIFIED` for UNKNOWN). The only differences are the regex type-name casing and using `strip_code(..., "csharp")`.

- [ ] **Step 1: Write the failing tests** — `tests/test_csharp_verdicts_e2e.py`:

```python
from __future__ import annotations

from cybergraph.analysis.csharp import analyze_csharp_file


def _rules(tmp_path, src):
    p = tmp_path / "A.cs"
    p.write_text(src, encoding="utf-8")
    _n, _e, findings = analyze_csharp_file(p, tmp_path)
    return [f.rule_id for f in findings]


def test_interpolated_sql_from_request_is_unsafe(tmp_path):
    src = ('class A { void H(Microsoft.AspNetCore.Http.HttpRequest request) {\n'
           '  var id = request.Query["id"];\n'
           '  var cmd = new SqlCommand($"SELECT * FROM u WHERE id = {id}", conn);\n'
           '  cmd.ExecuteReader(); } }\n')
    assert "CG-SQL-EXEC" in _rules(tmp_path, src)


def test_constructor_stream_reader_tainted_is_flagged(tmp_path):
    src = ('class A { void H(Microsoft.AspNetCore.Http.HttpRequest request) {\n'
           '  var p = request.Query["path"];\n'
           '  var r = new StreamReader(p); } }\n')
    assert "CG-PATH-TRAVERSAL" in _rules(tmp_path, src)


def test_process_start_shell_arg_is_flagged(tmp_path):
    src = ('class A { void H(string user) {\n'
           '  System.Diagnostics.Process.Start("cmd.exe", $"/c {user}"); } }\n')
    assert "CG-CMD-EXEC" in _rules(tmp_path, src)


def test_binaryformatter_deserialize_never_safe(tmp_path):
    src = ('class A { void H(System.IO.Stream s) {\n'
           '  var f = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();\n'
           '  var o = f.Deserialize(s); } }\n')
    # never SAFE: a deserialization sink always emits (confirmed or -UNVERIFIED),
    # never absent-because-safe.
    rules = _rules(tmp_path, src)
    assert "CG-DESERIALIZE" in rules or "CG-DESERIALIZE-UNVERIFIED" in rules


def test_csharp_script_eval_is_code_exec(tmp_path):
    src = ('class A { void H(string code) {\n'
           '  Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript.EvaluateAsync(code); } }\n')
    assert "CG-CODE-EXEC" in _rules(tmp_path, src)


def test_literal_query_is_safe_no_finding(tmp_path):
    src = ('class A { void H() {\n'
           '  var cmd = new SqlCommand("SELECT * FROM users", conn);\n'
           '  cmd.ExecuteReader(); } }\n')
    rules = _rules(tmp_path, src)
    assert "CG-SQL-EXEC" not in rules and "CG-SQL-EXEC-UNVERIFIED" not in rules


def test_zero_arg_execute_reader_is_skipped(tmp_path):
    # ExecuteReader() with no arg: query lives elsewhere; guarded, not a spurious finding.
    src = ('class A { void H(System.Data.SqlClient.SqlCommand cmd) {\n'
           '  cmd.ExecuteReader(); } }\n')
    assert "CG-SQL-EXEC" not in _rules(tmp_path, src)


def test_commented_out_sink_is_not_flagged(tmp_path):
    src = ('class A { void H(string id) {\n'
           '  // var c = new SqlCommand($"SELECT {id}", conn); c.ExecuteReader();\n'
           '} }\n')
    assert "CG-SQL-EXEC" not in _rules(tmp_path, src)
```

- [ ] **Step 2: Run to verify they fail** — `python -m pytest tests/test_csharp_verdicts_e2e.py -q` → FAIL (analyzer still emits only `CG-CSHARP-SINK-CALL`).

- [ ] **Step 3: Implement** — in `csharp.py`:
  - Add `from cybergraph.analysis._source_text import strip_code` and import `lookup_sink` plus the three `assess*` functions and `VERDICT_*`.
  - Add the dedicated matcher near the top:
    ```python
    _CSHARP_SINK_CALL_RE = re.compile(
        r"\bnew\s+(?P<ctor>[A-Z]\w*)\s*\(|\.(?P<method>[A-Za-z_]\w*)\s*\("
    )
    ```
  - Add `_grade_csharp_sinks(...)` mirroring `java.py`'s `_grade_java_sinks`: build the comment/string-blanked view with `strip_code(source, "csharp")`, run `_CSHARP_SINK_CALL_RE` over it (plus the existing dotted `CALL_RE` for the code-exec exact names like `CSharpScript.EvaluateAsync`), resolve each candidate with `lookup_sink(name, "csharp")`, and for a resolved sink dispatch by `sink.vuln_class`:
    - `"sql"` / `"path"` / `"code"` → `assess(sink, first_arg, tainted)`,
    - `"command"` → `assess_command(all_args, tainted)`,
    - `"deserialize"` → `assess_deserialization(tainted_present)`.
    Map SAFE → no finding; UNSAFE → the sink's `rule_id`; UNKNOWN → `rule_id + "-UNVERIFIED"`.
  - Apply the ZERO-ARG guard exactly as `java.py` does: a proven-empty `()` for sql/path/command/code is skipped (not emitted, never SAFE); deserialization is EXEMPT (always graded).
  - De-dup: when `lookup_sink(name, "csharp")` resolves, do not also emit the legacy `CG-CSHARP-SINK-CALL` for that call; unresolved calls keep the inventory row (existing behavior).
  - `tainted_present` for deserialization: the receiver/stream argument is taint-reachable per the existing `tainted_by_function` / `INPUT_MARKERS` machinery.
  - Preserve correct line numbers (the matcher runs over `strip_code` output, which is line-aligned to the source).

- [ ] **Step 4: Run to verify they pass** — `python -m pytest tests/test_csharp_verdicts_e2e.py -q` → PASS. `python -m pytest -q` → full suite green. `python -m ruff check src/cybergraph/analysis/csharp.py tests/test_csharp_verdicts_e2e.py` → clean.

- [ ] **Step 5: Commit** — `git add src/cybergraph/analysis/csharp.py tests/test_csharp_verdicts_e2e.py && git commit -m "feat(analysis): grade C# sinks to real verdicts (dedicated matcher, interpolation)"`

---

### Task 4: Capability & coverage for C#

**Files:**
- Modify: `src/cybergraph/security/capability.py`, `src/cybergraph/security/coverage.py`
- Test: additions to `tests/test_capability.py` and `tests/test_coverage.py`

**Interfaces:**
- Consumes: existing `CAPABILITIES`, `PYTHON_GLOBS`/`WEB_GLOBS`/`GO_GLOBS`/`JAVA_GLOBS`, `VERIFIED_GLOBS`, and coverage's verified-gate.
- Produces: `CSHARP_GLOBS`; `*.cs` recognized as covered for five capabilities and at file-coverage level.

- [ ] **Step 1: Write the failing tests** — add to `tests/test_capability.py`:

```python
def test_five_capabilities_cover_csharp():
    from cybergraph.security.capability import CAPABILITIES
    covers = {c.id: c.covers for c in CAPABILITIES}
    for cid in ("sql_construction", "command_execution", "path_access",
                "deserialization", "code_execution"):
        assert "*.cs" in covers[cid], cid


def test_csharp_not_in_verified_globs():
    from cybergraph.security.capability import VERIFIED_GLOBS
    assert "*.cs" not in VERIFIED_GLOBS  # C# stays NOT_SUPPORTED for source_analysis_support
```

and to `tests/test_coverage.py`:

```python
def test_csharp_is_analyzed_now_it_has_a_partial_analyzer(tmp_path: Path):
    (tmp_path / "A.cs").write_text("class A {}\n", encoding="utf-8")
    assert _status(tmp_path, ("A.cs",)) == {"A.cs": "analyzed"}
```

- [ ] **Step 2: Run to verify they fail** — `python -m pytest tests/test_capability.py tests/test_coverage.py -q` → FAIL.

- [ ] **Step 3: Implement:**
  - `capability.py`: add `CSHARP_GLOBS = ("*.cs",)` beside `JAVA_GLOBS`. Append `+ CSHARP_GLOBS` to the `covers` of `sql_construction`, `command_execution`, `path_access`, `deserialization`, AND `code_execution`. Leave `VERIFIED_GLOBS` unchanged.
  - `coverage.py`: import `CSHARP_GLOBS` and add it to the verified gate: `VERIFIED_GLOBS + CONFIG_GLOBS + WEB_GLOBS + GO_GLOBS + JAVA_GLOBS + CSHARP_GLOBS`.

- [ ] **Step 4: Run to verify they pass** — `python -m pytest tests/test_capability.py tests/test_coverage.py -q` → PASS. `python -m pytest -q` → full suite green (watch for a stale "unsupported language" example test that may need updating if it used `*.cs`). `python -m ruff check src/cybergraph/security/capability.py src/cybergraph/security/coverage.py` → clean.

- [ ] **Step 5: Commit** — `git add src/cybergraph/security/capability.py src/cybergraph/security/coverage.py tests/test_capability.py tests/test_coverage.py && git commit -m "feat(verdict): SQL/command/path/deserialization/code-exec capabilities now cover C#"`

---

### Task 5: Mutations, docs, and full verification

**Files:**
- Modify: `benchmark/mutation_harness.py`, `README.md`, `docs/CRITICAL_AUDIT.md`

- [ ] **Step 1: Add mutations** — append (append only; never reorder/rewrite existing entries) `Mutation` entries matching the current `csharp_provenance.py`/`csharp.py` source verbatim, each mapped to a committed C# test:
  - `D9-csharp-tainted-sink-reads-safe` — flip the assessor's `if any(n in tainted_names ...): return VERDICT_UNSAFE` to `VERDICT_SAFE` in `csharp_provenance.py`; map to `tests/test_csharp_provenance.py::test_concat_tainted_is_unsafe`.
  - `D9-csharp-unresolved-var-reads-safe` — flip the `if names or unresolved: ... return VERDICT_UNKNOWN` to `VERDICT_SAFE`; map to `tests/test_csharp_provenance.py::test_stringbuilder_all_literal_variable_receiver_never_safe`.
  - `D9-csharp-deser-reads-safe` — flip `assess_deserialization` to return `VERDICT_SAFE`; map to `tests/test_csharp_provenance.py::test_deserialization_is_never_safe`.
  - `D9-csharp-interp-hole-reads-safe` — in the interpolation branch of `assess`, drop the hole operands (e.g. change `names, unresolved = _operand_candidates(holes)` to `names, unresolved = [], False`) so a tainted interpolation hole reads SAFE; map to `tests/test_csharp_provenance.py::test_interpolation_tainted_hole_is_unsafe`.
  Verify each `old=` string is verbatim-unique in the current source before finalizing. Run `python benchmark/mutation_harness.py` → all CAUGHT.

- [ ] **Step 2: Docs** — `README.md`: add a bullet mirroring the JS/Go/Java ones that C# now earns real SQL/command/path/deserialization/code-execution verdicts. `docs/CRITICAL_AUDIT.md` §4.5: update to "resolved for JS, Go, Java, and C# core sink classes (C# adds code-execution); other/unlisted classes remain inventory-grade." Decide at write time whether §4.5 can be marked CLOSED (C# is the last planned non-Python language) or stays OPEN for remaining non-core classes — base it on what the audit section actually tracks; if any documented gap remains, keep it OPEN.

- [ ] **Step 3: Full verification** — run and confirm: `python -m pytest -q` all pass; `python -m ruff check .` no new errors vs baseline; `python benchmark/mutation_harness.py` all CAUGHT; `python benchmark/run_precision.py` → `GATE PASSED` (precision/recall/safe_fp_rate unchanged — the C# registry is language-keyed, so Python/JS/Go/Java corpora must be byte-identical); `python benchmark/run_eval.py` precision/recall unchanged, then `git checkout -- benchmark/results.json` (do NOT commit it).

- [ ] **Step 4: Commit** — `git add benchmark/mutation_harness.py README.md docs/CRITICAL_AUDIT.md && git commit -m "test(csharp): seed C# verdict fail-open mutations; document the upgrade"`

---

## Notes for the executor

- **Precision is cardinal.** Only all-literal/constant is SAFE; native deserialization is never SAFE; an interpolation hole that is not a proven literal is never SAFE. Port `java_provenance` exactly — do not re-derive a looser classifier.
- **Task 2 is the hard one:** C# string interpolation `$"...{expr}..."` (and `$@"..."`/`@$"..."`) is the dominant injection shape and the main thing the Java port does not already handle. Get `_interp_holes` right (escaped `{{`/`}}`, verbatim `""`, format/alignment suffix), and make sure a no-hole interpolated/verbatim string reads as a proven literal so all-literal SQL stays SAFE. `_source_text.py` already models these C# string forms — study its `"csharp"` `_Syntax` entry, and reuse `strip_code(..., "csharp")` for the analyzer's comment-blanking in Task 3.
- **Task 3's matcher** must catch constructors (`new SqlCommand(...)`, `new StreamReader(...)`, `new ProcessStartInfo(...)`) and chained calls the old dotted `CALL_RE` misses; keep the code-exec exact dotted names (`CSharpScript.EvaluateAsync`) matched too. Apply the zero-arg guard with deserialization EXEMPT, and no SAME-sink double-emission with the legacy inventory path.
- Confirm names/signatures against source before running each task's tests (`csharp_provenance.*`, `Sink`, `analyze_csharp_file`, `strip_code`, the csharp.py taint helpers); adapt the test to reality, never the reverse.
- Do NOT add a C# parser dependency, `TypeNameHandling`-config detection, reflection-invocation sinks, `*.cs` in `VERIFIED_GLOBS`, or interprocedural flow — out of scope.

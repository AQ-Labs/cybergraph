# Go Verdicts — Design (Non-Python upgrade, slice 2)

**Status:** approved for planning
**Slice:** the second per-language slice of the non-Python verdict upgrade — Go, for the injection
classes Go actually has (SQL, command, path). Replicates the shape proven in slice 1 (JS/TS).
**Predecessors:** the non-Python slice 1 (JS/TS core four, PR #46). This branch is **stacked on
`feat/js-verdicts-core-four`** (it edits `sinks.py`, `capability.py`, `coverage.py` — the same
files) and rebases down the stack as parents merge. Stack depth is now 5 (main ← #44 ← #45 ← #46
← this).

## The sentence this slice is judged against

> Go graduates from inventory `CG-GO-SINK-CALL` to real safe/unsafe/unknown verdicts for the
> injection classes Go actually has — SQL, command, path — reusing Python's rule ids and
> reviewing under the same capabilities, with only an all-literal/constant construction ever
> reading SAFE and no real injection ever reading safe.

## Why this is the right slice

- It is a near-direct port of the JS shape: `go.py` (259 lines) already tracks intra-function
  taint (`tainted_by_function`, `_tainted_source_for_line`, `EDGE_TAINTS`, `DataFlow` nodes,
  Go `INPUT_MARKERS` such as `url.query`/`formvalue`/`r.URL`) and emits flat `CG-GO-SINK-CALL`
  inventory — the same scaffolding `javascript.py` had. The verdict engine's *concept* (the
  construction lattice + `VERDICT_*` + the language-keyed `sinks.py`) is reused; only the
  Go-specific construction extraction is new.
- It validates the "replicate the proven shape" thesis for the remaining languages (Java, C#).

## Decisions already made (do not re-litigate in planning)

1. **Three classes: SQL, command, path.** Code-exec is excluded — Go has no `eval`/`Function`
   equivalent, so there is no Go code sink (the same justified exclusion as JS-`deserialization`).
   Go server-side template injection (`text/template` misused for HTML output) is a distinct class
   like Python's `CG-TEMPLATE-INJECT` and is out of scope (matches JS not doing XSS this early).
2. **Reuse Python's rule ids and broaden the existing capabilities** — `CG-SQL-EXEC`,
   `CG-CMD-EXEC`, `CG-PATH-TRAVERSAL`; broaden `sql_construction`, `command_execution`,
   `path_access` to include `GO_GLOBS`. Do NOT broaden `code_execution` (no Go code sink).
   `VERIFIED_GLOBS` stays Python-only → `source_analysis_support` stays honestly NOT_SUPPORTED
   for Go (the tool claims exactly the three classes it verifies, not "Go is fully verified").
3. **Cardinal rule, with positive-literal-proof from the start.** Only an all-literal/constant
   construction is SAFE. A construction containing a variable is UNSAFE (taint-confirmed user
   input) or UNKNOWN (unresolved) — never SAFE, and never a confident UNSAFE on an unresolved
   variable. **Never infer "no candidate names found ⇒ all-literal ⇒ SAFE"** — this is the exact
   false-SAFE the JS final review caught (`'…' + (id)`); the Go classifier requires positive proof
   that every operand/argument is a literal or constant, and any operand it cannot prove literal
   contributes its identifiers as candidate variables plus an "unresolved" flag.

## Architecture — port the JS shape to Go

```
src/cybergraph/security/sinks.py        (modify)  add _GO registry; _BY_LANGUAGE["go"]
src/cybergraph/analysis/go_provenance.py(create)  Go construction classifier + assessor
src/cybergraph/analysis/go.py           (modify)  route the three sink classes through the assessor
src/cybergraph/security/capability.py   (modify)  GO_GLOBS; broaden 3 capabilities' covers
src/cybergraph/security/coverage.py     (modify)  add GO_GLOBS to the verified gate
```

`checks.py` needs **no change** (the three capabilities already map to the rule ids).

### The Go sink registry (`sinks.py`)

Add `_GO: tuple[Sink, ...]` and `_BY_LANGUAGE["go"] = _GO`, reusing `Sink(name, rule_id, cwe,
severity, plain, vuln_class, bare, shell)` and Python's rule ids. **Go identifiers are PascalCase
and exported methods are unqualified-receiver**, so entries are `bare=True` on the PascalCase
method name, and the routing passes the *original-case* call name to `lookup_sink` (NOT the
lowercased form `go.py` uses for its legacy substring `_is_sink`):

- **SQL** (`CG-SQL-EXEC`, CWE-89): `Query`, `QueryRow`, `QueryContext`, `QueryRowContext`, `Exec`,
  `ExecContext` (bare — `db`/`tx` receivers).
- **Command** (`CG-CMD-EXEC`, CWE-78): `exec.Command`, `exec.CommandContext` (`shell` conditional
  — Go's `exec.Command(name, args…)` runs no shell unless `name` is `sh`/`bash` with `-c`; the
  shell case is `exec.Command("sh","-c", cmd)`).
- **Path** (`CG-PATH-TRAVERSAL`, CWE-22): `Open`, `OpenFile`, `ReadFile`, `WriteFile`, `Create`
  (bare — `os`/`ioutil` receivers).

**`fmt.Sprintf` is NOT a sink here** — it is a *construction* mechanism. When a sink's argument
is a `fmt.Sprintf(…)` call, the classifier treats it as COMPOSED (below). (The legacy
`fmt.sprintf` entry in `go.py`'s `SINK_CALLS` may remain for inventory of other flows, but it does
not produce a verdict.)

### The Go construction classifier + assessor (`go_provenance.py`)

Statement-local, operating on the sink's first argument text (extracted with the string-aware
paren matcher ported from `js_provenance.extract_first_arg`, adapted to Go string literals:
interpreted `"…"` and raw `` `…` `` strings). Reuse `provenance.LITERAL/COMPOSED/OPAQUE` and
`predicates.VERDICT_*`.

- **Construction:**
  - an interpreted or raw string literal → **LITERAL**;
  - a `"…" + x` concatenation, OR a `fmt.Sprintf(fmtLiteral, args…)` call → **COMPOSED**;
  - a bare identifier or other call → **OPAQUE**;
  - unreadable/unbalanced → **OPAQUE** (fail-safe).
- **Candidate variables (positive-literal-proof):** for a `+` concatenation, every operand that is
  not a *proven* literal (string/raw-string/numeric/`true`/`false`/`nil`) contributes all its
  identifiers as candidates, plus an "unresolved" flag if it has none; for `fmt.Sprintf`, the
  format-string literal is skipped and every subsequent argument is assessed the same way.
- **Taint refinement:** reuse `go.py`'s function-local taint (a candidate name known
  user-controlled).
- **Assessment (per class, same as JS):** LITERAL / all-proven-literal → SAFE; a candidate that
  taint confirms → UNSAFE; a candidate of unknown provenance or an unresolved operand → UNKNOWN;
  OPAQUE bare identifier → UNSAFE if tainted else UNKNOWN. **Command:** the shell case
  (`exec.Command("sh"/"bash", "-c", <non-literal>)`) → UNSAFE when tainted; an argv form with a
  literal program name and per-arg assessment otherwise; unresolved → UNKNOWN.
- **Verdict → finding:** UNSAFE → `sink.rule_id`; UNKNOWN → `sink.rule_id + "-UNVERIFIED"`; SAFE →
  none. (Same mapping as JS/Python `_finding_for`.)

### `go.py` routing

Gate on **registry OR legacy** (as in JS): `sink = lookup_sink(call_name, "go"); if sink is not
None or _is_sink(call_name):`. A registry hit → graded verdict via the assessor (extract arg from
`source` at the call's `(`, offset-translated from the per-line match, as the JS offset fix does);
else → the existing `CG-GO-SINK-CALL` inventory. Preserve the `EDGE_REACHES_SINK`/`EDGE_TAINTS`
edges. A registered sink emits EITHER a verdict OR inventory, never both.

### Capability & coverage

- `capability.py`: add `GO_GLOBS = ("*.go",)`; change `sql_construction`, `command_execution`,
  `path_access` covers to `PYTHON_GLOBS + WEB_GLOBS + GO_GLOBS`. Leave `code_execution`
  (`PYTHON_GLOBS + WEB_GLOBS`), `deserialization`, and `VERIFIED_GLOBS` unchanged.
- `coverage.py`: add `GO_GLOBS` to the verified gate (`VERIFIED_GLOBS + CONFIG_GLOBS + WEB_GLOBS +
  GO_GLOBS`) so a clean, analyzed `.go` file reaches PASS instead of perpetual UNKNOWN — without
  changing `source_analysis_support` (which decides NOT_SUPPORTED via `unverified_source_files`
  and pre-filters, unchanged).

## Precision & the SARIF filter

The three classes now emit real `CG-*` rules (uploadable); the filter still drops the remaining
`*-SINK-CALL` inventory for Go sink names outside the registry. Audit §4.5 note extended to "JS +
Go core classes." A parameterized `db.Query("… WHERE id = $1", id)` → LITERAL query → SAFE; a
`fmt.Sprintf`/`+` with a tainted arg → UNSAFE; an unresolved arg → UNKNOWN.

## Error handling

- A `.go` file the analyzer cannot read → its containment path → coverage FAILED → UNKNOWN.
- An argument the paren matcher cannot balance → OPAQUE → UNKNOWN, never SAFE.
- A `fmt.Sprintf` with no arguments beyond the format string → all-literal → SAFE (a constant).

## Testing

- **`go_provenance` units** per class: literal → SAFE; `"…" + tainted` → UNSAFE; `fmt.Sprintf`
  with a tainted arg → UNSAFE; `fmt.Sprintf` all-literal → SAFE; unresolved variable → UNKNOWN;
  `"…" + (nonLeadingIdentOperand)` → not SAFE (the JS-lesson guard); opaque → UNKNOWN; `exec.Command`
  shell-vs-argv.
- **`sinks.py`**: `lookup_sink` resolves the Go PascalCase names to the right rule ids; other
  languages unchanged.
- **Capability five-state** on a `.go` change for the three capabilities; `source_analysis_support`
  still NOT_SUPPORTED for Go; `code_execution` NOT_APPLICABLE/PASS on a Go change (no Go code sink).
- **End-to-end:** `cybergraph check` → REVIEW on a Go SQLi (`db.Query(fmt.Sprintf("… %s", userID))`
  with tainted `userID`) and a `exec.Command("sh","-c", userCmd)`; ACCEPT on a parameterized query.
- **Mutation harness:** three seeded fail-opens (a tainted Go sink arg read SAFE; an unresolved
  variable read SAFE; a `+`/`Sprintf` non-literal operand read SAFE), each red under its guard test.
- Full suite green; ruff clean; `run_precision.py`/`run_eval.py` unchanged (Python corpus — the Go
  registry is language-keyed, so Python is unaffected; verify identical).

## Global constraints (inherited, unchanged)

- Python 3.10–3.13. **Zero runtime dependencies**; standard library only (`re`) — no Go parser.
  The classifier is lightweight/structural and fail-safe.
- Ruff line-length 100; `from __future__ import annotations` in every file.
- No network; no API keys on any default path.
- **Precision over recall:** only an all-literal/constant construction is SAFE; a variable is
  UNSAFE (taint-confirmed) or UNKNOWN; uncertainty → UNKNOWN.
- Commits `Laraib <lxh417bham@gmail.com>` only; no `Co-Authored-By`, no AI attribution. Many small
  commits; never squash. Push only to `https://github.com/AQ-Labs/cybergraph`.

## Roadmap alignment — what this does NOT touch

Builds Go verdicts for SQL/command/path and broadens three capabilities. Deliberately excluded:
Go template injection, code-exec (no Go eval), interprocedural/cross-file flow, adding `*.go` to
`VERIFIED_GLOBS` (Go is not fully verified), and Java/C# (later slices replicating this shape).
`CG-GO-SINK-CALL` inventory remains for Go sink names outside the registry.

## Success criteria

1. `sinks.py` resolves the Go PascalCase SQL/command/path sink names to Python's rule ids (bare,
   original-case); other languages unchanged.
2. The Go classifier maps an all-literal/constant construction (incl. an all-literal `fmt.Sprintf`)
   → SAFE, a taint-confirmed variable (in a `+`, a `Sprintf` arg, a non-leading-identifier operand,
   or a bare identifier) → UNSAFE, an unresolved variable/unreadable arg → UNKNOWN. No variable is
   ever SAFE.
3. A Go injection on a changed `.go` → the matching capability FAIL → `cybergraph check` REVIEW; a
   parameterized/all-literal change → SAFE → ACCEPT (end-to-end).
4. `source_analysis_support` still reports Go NOT_SUPPORTED; the three capabilities cover Go;
   `code_execution` does not.
5. The three classes emit real `CG-*` rules, not `CG-GO-SINK-CALL`; other Go sinks stay inventory.
6. Full suite green; ruff clean; the mutation harness catches all three seeded Go fail-opens;
   `run_precision.py`/`run_eval.py` unchanged.

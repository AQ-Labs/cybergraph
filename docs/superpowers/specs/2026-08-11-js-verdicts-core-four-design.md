# JS/TS Verdicts — the Core Four — Design (Phase 2, non-Python upgrade slice 1)

**Status:** approved for planning
**Slice:** the first of four per-language slices of the "non-Python verdict upgrade" — JavaScript/
TypeScript, for the four sink classes CyberGraph already verifies in Python (SQL, command,
code-exec, path). Go / Java / C# are later slices that replicate this proven shape.
**Predecessors:** verdict-core (merged), client hooks (#43, merged), config-posture (#44, open),
CORS + client boundary (#45, open). This branch is **stacked on `feat/cors-client-boundary`**
(#45) because it broadens capabilities in `capability.py` and relies on the `WEB_GLOBS`
coverage-verified change that #45 introduced. It rebases down the stack as each parent merges.

## The sentence this slice is judged against

> For the four sink classes CyberGraph already verifies in Python, a JavaScript/TypeScript sink
> whose argument is a string literal earns SAFE (the finding is suppressed), one built from an
> interpolated or concatenated variable earns UNSAFE (or UNKNOWN when the build cannot be read),
> and JS graduates from inventory-grade `CG-JS-SINK-CALL` to the same real ACCEPT/REVIEW verdict
> as Python — without a false alarm on a safe query and without a real injection ever reading safe.

## Why this is the right first non-Python slice

- JS/TS is the most common language in AI-generated code, and `javascript.py` already carries the
  most infrastructure to build on: intra-function taint (`tainted_by_function`), `DataFlow`
  nodes, `EDGE_TAINTS`/`EDGE_REACHES_SINK`, and a comments/strings-blanked `code_lines` view.
- It proves the reusable shape — **register per-language sinks → extract the sink argument's
  construction → map through the shared lattice → emit a graded verdict** — that Go/Java/C#
  replicate, while reusing the engine's *concept* (the LITERAL/COMPOSED/OPAQUE lattice and the
  `VERDICT_SAFE/UNSAFE/UNKNOWN` vocabulary) rather than duplicating its AST-bound implementation.

## Decisions already made (do not re-litigate in planning)

1. **Core four in one slice:** SQL, command, code-exec, path — parity with Python's verified
   classes. XSS / SSRF / deserialization and interprocedural flow are later JS slices.
2. **Unify, don't fork (confirmed).** JS emits the *same rule ids* as Python (`CG-SQL-EXEC`,
   `CG-CMD-EXEC`, `CG-CODE-EXEC`, `CG-PATH-TRAVERSAL`, `-UNVERIFIED` for UNKNOWN), and the four
   capabilities (`sql_construction`, `command_execution`, `code_execution`, `path_access`) have
   their `covers` broadened from `PYTHON_GLOBS` to `PYTHON_GLOBS + WEB_GLOBS`. A JS SQL injection
   then reviews under the *same* capability as Python. **`VERIFIED_GLOBS` is NOT changed** — JS
   still lacks verdicts for other classes, so `source_analysis_support` stays honestly
   NOT_SUPPORTED for JS; the tool claims exactly the four classes it now checks, not "JS is fully
   verified." No JS-specific rule ids or parallel capabilities.
3. **Fail-safe precision.** JS has no stdlib parser; the classifier assesses only when it can
   confidently extract the argument. A confidently-literal argument → SAFE (suppress). Anything
   it cannot read with confidence → **UNKNOWN** (`-UNVERIFIED` → REVIEW) — never SAFE, never a
   confident-but-wrong UNSAFE. The failure mode is "flag for a human," never a silent pass.

## Architecture

```
src/cybergraph/security/sinks.py        (modify)  add _JAVASCRIPT registry; _BY_LANGUAGE["javascript"]
src/cybergraph/analysis/js_provenance.py(create)  JS construction classifier + per-class assessor
src/cybergraph/analysis/javascript.py   (modify)  route the four sink classes through the assessor
src/cybergraph/security/capability.py   (modify)  broaden the four capabilities' covers to +WEB_GLOBS
```

`checks.py` needs **no change**: `_FINDING_RULES` already maps the four capabilities to their rule
ids, and coverage already treats web files as analyzed (`WEB_GLOBS` in the verified gate, from
#45), so a JS finding on a changed `.ts` flows through the existing generic evaluator to FAIL/PASS.

### The JS sink registry (`sinks.py`)

Add `_JAVASCRIPT: tuple[Sink, ...]` and `_BY_LANGUAGE["javascript"] = _JAVASCRIPT`, reusing the
`Sink(name, rule_id, cwe, severity, plain, vuln_class, bare, shell)` shape and Python's rule ids:

- **SQL** (`CG-SQL-EXEC`, CWE-89): `query`, `execute`, `raw` (`bare=True` — receivers like
  `db`/`knex`/`pool` can't be resolved without type inference, matching how Python treats
  `cursor.execute`).
- **Command** (`CG-CMD-EXEC`, CWE-78): `exec`, `execSync` (`shell` inherent — they spawn a shell),
  `spawn`/`execFile`/`spawnSync` (`shell` conditional — array argv is safer).
- **Code** (`CG-CODE-EXEC`, CWE-95): `eval`, `Function` (`new Function(...)`).
- **Path** (`CG-PATH-TRAVERSAL`, CWE-22): `readFile`, `readFileSync`, `createReadStream`,
  `writeFile`, `writeFileSync`, `unlink`, `readdir` (`bare=True` — `fs.`/`fsp.` receivers).

`lookup_sink(call_name, "javascript")` then resolves these; the flat `SINK_CALLS`/`CG-JS-SINK-CALL`
path in `javascript.py` is superseded for these names and retained only for sinks *not* in the
registry (still inventory-grade).

### The JS construction classifier + assessor (`js_provenance.py`)

Statement-local, operating on the sink call's argument text (extracted with a string-aware
paren matcher — the technique from #45's `_brace_object`, adapted to `(`/`)`):

- **Construction:** a pure string literal, or a template literal with no `${}` → **LITERAL**; a
  template with `${…}` interpolation or a `+` concatenation involving a non-literal → **COMPOSED**;
  a bare identifier or a call result → **OPAQUE**; an argument that cannot be confidently
  extracted → **OPAQUE** (fail-safe).
- **Taint refinement:** reuse the function-local taint `javascript.py` already computes — whether
  an interpolated/concatenated identifier is a known user-controlled value.
- **Per-class assessment** (the *concept* mirrors `predicates`, but the safe/unknown split is
  deliberately MORE conservative than Python's, because JS taint is weaker — intra-function and
  line-based — so "untainted therefore safe" is not trustworthy here). Python trusts its strong
  AST taint to clear an untainted-but-composed query; JS must not, or a real injection whose flow
  the weaker taint missed would read SAFE. Therefore:
  - **SQL / path:** an argument that is a literal, or a template/concatenation whose every part is
    a literal or a resolvable constant → **SAFE**. A construction containing a variable that taint
    confirms is user-controlled → **UNSAFE**. A construction containing a variable of *unknown*
    provenance (taint neither confirms nor refutes) → **UNKNOWN** — never SAFE (JS can't vouch for
    it) and never a confident UNSAFE (it might be an allowlisted constant). Opaque / unreadable →
    **UNKNOWN**.
  - **command:** an inherent-shell sink whose argument is anything but an all-literal/constant
    string → UNSAFE when taint confirms user input, else UNKNOWN; a conditional-shell sink with an
    array argv and no `shell: true` → SAFE for the shell mechanism (then assess the elements as
    above); a string command with no resolvable shell status → UNKNOWN (platform-dependent, as in
    Python's `_assess_command`).
  - **code:** `eval` / `new Function` with an all-literal argument → SAFE; with a taint-confirmed
    user value → UNSAFE; with a variable of unknown provenance → UNKNOWN.

  The invariant across all four: **only an all-literal/constant construction is SAFE; any variable
  is UNSAFE (taint-confirmed) or UNKNOWN (unresolved), never SAFE.** This is the concrete
  expression of the judged-against sentence and the cardinal precision rule.
- **Verdict → finding:** UNSAFE → the sink's `rule_id` at its severity; UNKNOWN → `rule_id` +
  `-UNVERIFIED` at reduced severity; SAFE → no finding. (Same mapping as Python's `_finding_for`.)

### Capability broadening (`capability.py`)

Change the `covers` of `sql_construction`, `command_execution`, `code_execution`, `path_access`
from `PYTHON_GLOBS` to `PYTHON_GLOBS + WEB_GLOBS`. Nothing else in `capability.py` changes;
`deserialization` stays Python-only (not in the JS core four). `VERIFIED_GLOBS` unchanged.

## Verdict flow (end to end)

```
changed foo.ts  →  analyze_javascript_file  →  lookup_sink("db.query","javascript")
   →  js_provenance: extract arg, classify construction × taint  →  VERDICT
   →  UNSAFE: Finding(CG-SQL-EXEC, high, CWE-89, …)   UNKNOWN: CG-SQL-EXEC-UNVERIFIED   SAFE: none
   →  check_change: sql_construction covers *.ts, coverage=ANALYZED, finding rule_id in {CG-SQL-EXEC}
   →  FAIL  →  REVIEW   (and the client hooks surface it)
```

## Precision & the SARIF filter

- The four classes now emit real `CG-*` rules (not `CG-JS-SINK-CALL`), so they upload to code
  scanning; the CI filter still drops the remaining `*-SINK-CALL` inventory for JS sink names not
  in the registry. Audit §4.5 is **partially** retired (four classes for JS); the note is updated,
  not deleted.
- A safe parameterized query (`db.query("SELECT … WHERE id = ?", [id])`) → LITERAL query arg →
  SAFE → no finding. A confidently-unreadable argument → UNKNOWN → REVIEW.

## Error handling

- A `.js`/`.ts` that the analyzer cannot read → its existing containment path → coverage
  FAILED → UNKNOWN (never a silent PASS).
- An argument the paren matcher cannot balance (truncated/odd source) → OPAQUE → UNKNOWN, never
  SAFE.
- A sink call with no extractable argument → UNKNOWN.

## Testing

- **`js_provenance` units** per class: literal → SAFE; template/`+` with a variable → UNSAFE;
  template with only-literal interpolations → SAFE; bare variable/opaque → UNKNOWN; tainted vs
  untainted variable distinction; command shell-vs-argv; `eval`/`Function` literal-vs-not; path
  join-of-literals vs user path. A parameterized query → SAFE.
- **`sinks.py`**: `lookup_sink` resolves the JS names to the right rule ids/vuln classes; Python
  lookups unchanged.
- **Capability five-state** on a `.ts` change for the four capabilities (FAIL on a JS injection,
  PASS on a clean analyzed JS file, NOT_APPLICABLE off-scope, UNKNOWN on an unreadable JS file);
  `source_analysis_support` still NOT_SUPPORTED for JS (unchanged — the honesty check).
- **End-to-end:** `cybergraph check` → REVIEW on a JS SQLi diff and on a JS `child_process.exec`
  with an interpolated command; ACCEPT on a parameterized-query / array-argv diff.
- **Mutation harness:** two seeded fail-opens — an interpolated-variable SQLi read as SAFE, and an
  unreadable/opaque argument read as SAFE instead of UNKNOWN — each red under its guard test.
- Full suite green; ruff clean; `run_precision.py`/`run_eval.py` unchanged (Python corpus), and
  the new JS rules confirmed not to fire on any Python precision-corpus fixture.

## Global constraints (inherited, unchanged)

- Python 3.10–3.13. **Zero runtime dependencies**; standard library only (`re`) — no JS parser
  (tree-sitter, esprima, etc.). The classifier is lightweight/structural, fail-safe on anything
  it cannot read.
- Ruff line-length 100; `from __future__ import annotations` in every file.
- No network; no API keys on any default path.
- **Precision over recall:** uncertainty resolves to UNKNOWN (REVIEW), never SAFE and never a
  confident false UNSAFE.
- Commits `Laraib <lxh417bham@gmail.com>` only; no `Co-Authored-By`, no AI attribution. Many small
  commits; never squash. Push only to `https://github.com/AQ-Labs/cybergraph`.

## Roadmap alignment — what this does NOT touch

Builds JS verdicts for the four classes and broadens the four capabilities. Deliberately excluded:
JS XSS/output-encoding, SSRF, deserialization; interprocedural/cross-file flow; adding `*.js` to
`VERIFIED_GLOBS` (JS is not fully verified); Go/Java/C# (each a later slice replicating this
shape); and `deserialization` for JS. The flat `CG-JS-SINK-CALL` inventory remains for JS sink
names outside the registry.

## Success criteria

1. `sinks.py` resolves the JS SQL/command/code/path sink names to Python's rule ids; Python
   lookups unchanged.
2. The JS classifier maps an all-literal/constant construction → SAFE, a variable that taint
   confirms is user-controlled → UNSAFE, a variable of unknown provenance or an unreadable
   argument → UNKNOWN, per class (SQL/command/code/path), with the shell/argv and
   only-literal-interpolation nuances correct. No variable is ever SAFE.
3. A JS injection on a changed `.ts`/`.js` → the matching capability FAIL → `cybergraph check`
   REVIEW; a parameterized/array-argv/literal change → SAFE → ACCEPT (end-to-end).
4. `source_analysis_support` still reports JS NOT_SUPPORTED (the tool does not overclaim full JS
   verification); the four capabilities now cover web globs.
5. The four classes emit real `CG-*` rules (uploadable), not `CG-JS-SINK-CALL`; other JS sinks
   stay inventory.
6. Full suite green; ruff clean; the mutation harness catches both seeded JS fail-opens;
   `run_precision.py`/`run_eval.py` unchanged.

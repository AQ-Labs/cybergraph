# Java Verdicts — Design (Non-Python upgrade, slice 3)

**Status:** approved for planning
**Slice:** the third per-language slice of the non-Python verdict upgrade — Java, for SQL,
command, path, and unsafe **deserialization**. Replicates the shape proven in the JS and Go
slices, plus one new vulnerability class.
**Predecessors:** JS verdicts (#46, merged), Go verdicts (#50, merged), the JS command fix
(#49, merged). Branches off `main` (the stack has fully drained — everything is landed);
**not stacked.**

## The sentence this slice is judged against

> Java graduates from inventory `CG-JAVA-SINK-CALL` to real safe/unsafe/unknown verdicts for
> SQL, command, path, and — the marquee Java class — unsafe deserialization, reusing Python's
> rule ids and reviewing under the same capabilities, with only an all-literal/constant
> construction ever reading SAFE and native Java deserialization never reading SAFE.

## Why this is the right slice

- `java.py` (293 lines) already tracks intra-function taint (`tainted_by_function`,
  `_tainted_source_for_line`, `EDGE_TAINTS`, `INPUT_MARKERS` such as `getParameter`,
  `@RequestParam`, `@PathVariable`, `request.getHeader`) and emits flat `CG-JAVA-SINK-CALL`
  inventory for SQL/command/path — the same scaffolding JS and Go had.
- Java adds a *new* verdict class the earlier slices didn't: native **deserialization**
  (`ObjectInputStream.readObject`), the ysoserial/gadget-chain RCE family — high real-world value.

## Decisions already made (do not re-litigate in planning)

1. **Four classes: SQL, command, path, deserialization.** Java code/expression injection
   (`ScriptEngine.eval`, SpEL, OGNL) and JNDI injection (Log4Shell `ctx.lookup`) are distinct
   nuances, deferred. `code_execution` is NOT broadened to Java here.
2. **Reuse Python's rule ids and broaden the existing capabilities** — `CG-SQL-EXEC`,
   `CG-CMD-EXEC`, `CG-PATH-TRAVERSAL`, `CG-DESERIALIZE`. Broaden `sql_construction`,
   `command_execution`, `path_access`, and — unlike Go/JS — **`deserialization`** (Python-only
   today; Java genuinely has it) to include `JAVA_GLOBS`. `VERIFIED_GLOBS` unchanged →
   `source_analysis_support` stays honestly NOT_SUPPORTED for Java (the tool claims exactly the
   four classes it verifies).
3. **Cardinal rule + positive-literal-proof from the start.** Only an all-literal/constant
   construction is SAFE; a variable is UNSAFE (taint-confirmed) or UNKNOWN (unresolved), never
   SAFE; never infer "no candidate names ⇒ literal" (the JS/Go final-review lesson).
4. **Native deserialization is never SAFE (confirmed §2 below).**

## Architecture — port the proven shape + one new class

```
src/cybergraph/security/sinks.py          (modify)  add _JAVA registry; _BY_LANGUAGE["java"]
src/cybergraph/analysis/java_provenance.py(create)  Java construction classifier + assessor + deser rule
src/cybergraph/analysis/java.py           (modify)  route the four sink classes through the assessor
src/cybergraph/security/capability.py     (modify)  JAVA_GLOBS; broaden four capabilities
src/cybergraph/security/coverage.py       (modify)  add JAVA_GLOBS to the verified gate
```

`checks.py` needs **no change** (the four capabilities are already in `_FINDING_RULES`, including
`deserialization → CG-DESERIALIZE`).

### The Java sink registry (`sinks.py`)

Add `_JAVA` reusing `Sink(name, rule_id, cwe, severity, plain, vuln_class, bare, shell)` and
Python's rule ids. Java methods are called on unresolvable receivers → `bare=True` on the method
name (matching how Python treats `cursor.execute`):

- **SQL** (`CG-SQL-EXEC`, CWE-89): `executeQuery`, `executeUpdate`, `execute`, `query`, `update`,
  `createNativeQuery`, `createQuery` (bare). PreparedStatement with `?` placeholders is the safe
  form (a literal query → SAFE).
- **Command** (`CG-CMD-EXEC`, CWE-78): `exec` (`Runtime.exec`), `ProcessBuilder`, `start`
  (bare; shell conditional — `exec`/`ProcessBuilder` run no shell unless the argv is `sh -c`/
  `cmd /c`).
- **Path** (`CG-PATH-TRAVERSAL`, CWE-22): `write`, `readAllBytes`, `newInputStream`,
  `FileReader`, `FileWriter`, `FileInputStream`, and `File` (`new File(path)`) (bare).
- **Deserialization** (`CG-DESERIALIZE`, CWE-502): `readObject`, `readUnshared` (bare).

### The Java construction classifier + assessor (`java_provenance.py`)

Ported from the final Go/JS provenance (positive-literal-proof intact: `extract_first_arg`,
`extract_all_args`, `_split_plus`, `_is_proven_literal_operand`, `_operand_candidates`), adapted
to Java:

- **Construction idioms:** a Java string literal → LITERAL; `"…" + var` concatenation,
  `String.format(fmt, args…)`, or a `StringBuilder`/`.append(...)` chain involving a non-literal
  → COMPOSED; a bare identifier or call → OPAQUE; unreadable → OPAQUE (fail-safe). `String.format`
  is treated like Go's `fmt.Sprintf` (assess **all** args, incl. the format arg — a variable
  format is not a literal). A `StringBuilder.append(x)` chain contributes each appended operand.
- **Taint refinement:** reuse `java.py`'s function-local taint.
- **Per-class assessment:**
  - **SQL / path:** all-literal/constant → SAFE; a candidate variable taint-confirms → UNSAFE;
    unresolved variable / opaque / unreadable → UNKNOWN. (PreparedStatement `?` query is a literal
    → SAFE.)
  - **command:** the Go all-argument `assess_command` — any non-literal command argument →
    UNSAFE (taint-confirmed) / UNKNOWN (unresolved); all-literal argv → SAFE. Shell form
    (`sh`/`bash`/`cmd` + `-c`/`/c`) with a non-literal → UNSAFE/UNKNOWN.
  - **deserialization (the new, distinct rule):** `readObject`/`readUnshared` take **no argument**
    to classify — the danger is the stream the `ObjectInputStream` was built from. Native Java
    deserialization is **never SAFE**: → **UNSAFE** when `java.py`'s taint shows an untrusted
    value/stream reaching the call, else **UNKNOWN** (`CG-DESERIALIZE-UNVERIFIED` → REVIEW:
    "verify this stream is trusted"). This is honest (static analysis cannot prove a native-deser
    source safe) and fail-safe. The routing recognizes the deser class and applies this rule
    instead of argument classification.
- **Verdict → finding:** UNSAFE → `sink.rule_id`; UNKNOWN → `sink.rule_id + "-UNVERIFIED"`;
  SAFE → none (never emitted for deserialization).

### `java.py` routing

Gate on **registry OR legacy** (as in JS/Go): `sink = lookup_sink(call_name, "java"); if sink is
not None or _is_sink(call_name, custom_sinks):`. Registry hit → the assessor (SQL/path first-arg;
command all-args; deserialization the never-SAFE rule); else → existing `CG-JAVA-SINK-CALL`
inventory. Preserve `EDGE_REACHES_SINK`/`EDGE_TAINTS`; graded XOR inventory, never both. Use the
whole-file offset translation (`_line_start_offsets`, the JS/Go fix) for argument extraction.

> **Java-specific risk to pin in the plan:** method chaining — `Runtime.getRuntime().exec(cmd)`
> puts the sink call's `(` after a `)`, and `new File(path)` has the `new` keyword. Confirm that
> `CALL_RE`/`call.group("name")` yields a `call_name` whose bare tail resolves the sink
> (`exec`/`File`), and that `call.end()-1` lands on the correct `(` for argument extraction.
> Where a constructor (`new File(...)`, `new ProcessBuilder(...)`) is the sink, the plan pins how
> the name is recognized (bare `File`/`ProcessBuilder`).

### Capability & coverage

- `capability.py`: add `JAVA_GLOBS = ("*.java",)`; broaden `sql_construction`,
  `command_execution`, `path_access` to `… + JAVA_GLOBS`, and `deserialization` from
  `PYTHON_GLOBS` to `PYTHON_GLOBS + JAVA_GLOBS`. `code_execution` unchanged; `VERIFIED_GLOBS`
  unchanged.
- `coverage.py`: add `JAVA_GLOBS` to the verified gate so a clean analyzed `.java` file reaches
  PASS (not perpetual UNKNOWN), without changing `source_analysis_support`.

## Precision & the SARIF filter

The four classes emit real `CG-*` rules (uploadable); the filter still drops the remaining
`*-SINK-CALL` inventory for Java sink names outside the registry. Audit §4.5 note extended to
"JS + Go + Java core classes." A PreparedStatement query → SAFE; a `"…" + userInput` /
`String.format` with a tainted arg → UNSAFE; a `readObject` on an untrusted stream → UNSAFE, on
an unresolved stream → UNKNOWN.

## Error handling

- A `.java` the analyzer cannot read → containment → coverage FAILED → UNKNOWN.
- An argument the paren matcher cannot balance → OPAQUE → UNKNOWN, never SAFE.
- A `readObject`/`readUnshared` call → never SAFE (UNSAFE if tainted, else UNKNOWN).

## Testing

- **`java_provenance` units:** SQL literal → SAFE; `"…" + tainted` → UNSAFE; `String.format`
  tainted arg (incl. variable format) → UNSAFE; `StringBuilder.append(tainted)` → UNSAFE;
  unresolved → UNKNOWN; PreparedStatement `?` → SAFE. Command: `Runtime.exec(new String[]{"sh","-c",userCmd})`
  / `exec("sh","-c",userCmd)` tainted → UNSAFE, all-literal → SAFE. Deserialization: tainted
  stream → UNSAFE, untainted/unresolved → UNKNOWN, and **never SAFE** for any input.
- **`sinks.py`:** `lookup_sink` resolves the Java names to the right rule ids/classes; other
  languages unchanged.
- **Capability five-state** on a `.java` change for the four capabilities; `source_analysis_support`
  still NOT_SUPPORTED for Java; `code_execution` NOT_APPLICABLE on a Java change.
- **End-to-end:** `cybergraph check` → REVIEW on a Java SQLi (`stmt.executeQuery("… " + req.getParameter("id"))`)
  and on a `new ObjectInputStream(request.getInputStream()).readObject()`; ACCEPT on a
  PreparedStatement change.
- **Mutation harness:** seeded fail-opens incl. a tainted-SQLi-reads-safe, an unresolved-reads-safe,
  and a **deserialization-reads-safe** (the never-SAFE rule flipped) — each red under its guard test.
- Full suite green; ruff clean; `run_precision.py`/`run_eval.py` unchanged (Python corpus — the
  Java registry is language-keyed; verify identical).

## Global constraints (inherited, unchanged)

- Python 3.10–3.13. **Zero runtime dependencies**; standard library only (`re`) — no Java parser.
  Lightweight/structural, fail-safe.
- Ruff line-length 100; `from __future__ import annotations` in every file.
- No network; no API keys on any default path.
- **Precision over recall:** only an all-literal/constant construction is SAFE; native
  deserialization is never SAFE; uncertainty → UNKNOWN.
- Commits `Laraib <lxh417bham@gmail.com>` only; no `Co-Authored-By`, no AI attribution. Many small
  commits; never squash. Push only to `https://github.com/AQ-Labs/cybergraph`.

## Roadmap alignment — what this does NOT touch

Builds Java verdicts for SQL/command/path/deserialization and broadens four capabilities.
Deliberately excluded: Java code/expression injection (`ScriptEngine`/SpEL/OGNL), JNDI injection
(Log4Shell), interprocedural/cross-file flow, `*.java` in `VERIFIED_GLOBS`, and C# (the final
non-Python slice). `CG-JAVA-SINK-CALL` inventory remains for Java sink names outside the registry.

## Success criteria

1. `sinks.py` resolves the Java SQL/command/path/deserialization sink names to Python's rule ids
   (bare); other languages unchanged.
2. The Java classifier maps all-literal/constant → SAFE, a taint-confirmed variable → UNSAFE, an
   unresolved variable/unreadable arg → UNKNOWN, per class (SQL/command/path); and native
   deserialization → UNSAFE (tainted) / UNKNOWN (else), **never SAFE**. No variable is ever SAFE.
3. A Java injection or unsafe deserialization on a changed `.java` → the matching capability FAIL
   → `cybergraph check` REVIEW; a PreparedStatement/all-literal change → SAFE → ACCEPT (end-to-end).
4. `source_analysis_support` still reports Java NOT_SUPPORTED; `sql_construction`/`command_execution`/
   `path_access`/`deserialization` cover Java; `code_execution` does not.
5. The four classes emit real `CG-*` rules, not `CG-JAVA-SINK-CALL`; other Java sinks stay inventory.
6. Full suite green; ruff clean; the mutation harness catches every seeded Java fail-open incl.
   the deserialization one; `run_precision.py`/`run_eval.py` unchanged.

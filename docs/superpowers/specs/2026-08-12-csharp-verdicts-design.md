# C# Verdicts — SQL / command / path / deserialization / code-execution (non-Python upgrade, slice 4)

**Date:** 2026-08-12
**Status:** design approved, ready for implementation plan
**Precedent:** JS (slice 1, #46/#49), Go (slice 2, #52), Java (slice 3, #53). C# is the fourth and final non-Python language in the verdict upgrade.

## Goal

Graduate the C# analyzer from inventory-only `CG-CSHARP-SINK-CALL` findings to real ACCEPT/REVIEW verdicts for five vulnerability classes: **SQL, command, path, deserialization, and code-execution**. C# is the first non-Python language in this upgrade to add a code-execution class (Go had none; JS has it via `eval`/`Function`; Java deliberately excluded it).

## Context (current C# state)

`src/cybergraph/analysis/csharp.py` already exists and is inventory-grade — identical in shape to where Java started before slice 3:

- Emits the flat `CG-CSHARP-SINK-CALL` inventory row (behind the CI SARIF filter, §4.1).
- Has intra-function taint (`tainted_by_function`, `_tainted_source_for_line`, `INPUT_MARKERS = {request.query, request.form, request.headers, request.body, fromquery, frombody, fromroute}`).
- `SINK_CALLS` is a lowercased-substring set: `executereader/executenonquery/executescalar`, `process.start`, `file.writealltext/readalltext/delete/open`, `streamwriter/streamreader`.
- `CALL_RE = re.compile(r"(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*\(")` — the SAME limitation Java had: it MISSES constructors (`new SqlCommand(sql, conn)` → no dotted name) and chained calls.
- There is no `_CSHARP` in `sinks.py` and no `"csharp"` key in `_BY_LANGUAGE`.

The upgrade mirrors the Java slice exactly, with C#-specific handling for string interpolation and verbatim strings.

## Cardinal rule (governs every verdict decision)

Precision is paramount. A construction reads **SAFE only if it is provably an all-literal / constant construction**. Any variable, non-literal operand, unknown construct, or unreadable input → UNSAFE (when line-based intra-function taint confirms a tainted operand) or UNKNOWN — **never SAFE**. Native deserialization is never provably SAFE from construction alone. "Uncertainty never becomes safety." A single tainted/variable operand that reads SAFE is a fail-open.

## Architecture

Five components, mirroring the Java slice:

1. **Sink registry** — `_CSHARP` tuple in `src/cybergraph/security/sinks.py`, registered as `_BY_LANGUAGE["csharp"] = _CSHARP`. Reuses Python's existing rule ids.
2. **Fail-safe classifier** — new `src/cybergraph/analysis/csharp_provenance.py`, **ported from `java_provenance.py`** (the most hardened classifier, after seven fail-open rounds), plus C#-specific string-interpolation and verbatim-string handling.
3. **Routing** — `src/cybergraph/analysis/csharp.py` grades each detected sink to a real verdict via a dedicated `_CSHARP_SINK_CALL_RE` (constructors + chained calls), a zero-arg guard, and comment-aware grading.
4. **Capability / coverage** — `CSHARP_GLOBS = ("*.cs",)`; the five capabilities + the coverage verified-gate broaden to `*.cs`; `VERIFIED_GLOBS` unchanged.
5. **Mutation harness** — `D9-csharp` fail-open mutations proving the verdicts can go red.

Each unit has one responsibility and a stable interface: the registry says *where* sinks are and their metadata; the classifier decides SAFE/UNSAFE/UNKNOWN for an argument string; the analyzer wires detection → classifier → finding; capability/coverage report honestly what is and is not covered.

## Component 1 — Sink registry (`_CSHARP`)

Reuse the existing `Sink` dataclass and the `_SQL` / `_CMD` / `_DESERIALIZE` plain-text constants and the Python rule ids. All method-name sinks are `bare=True` (C# receivers — `cmd`, `formatter`, `db` — cannot be resolved without type inference). Constructor sinks are matched by the analyzer's dedicated regex (Component 3), keyed on the type name.

**SQL** — `CG-SQL-EXEC`, `CWE-89`, HIGH, `_SQL`, `vuln_class="sql"`, `bare=True`:
`ExecuteReader`, `ExecuteNonQuery`, `ExecuteScalar`, `ExecuteReaderAsync`, `ExecuteNonQueryAsync`, `ExecuteScalarAsync`, and the Dapper set `Query`, `QueryAsync`, `Execute`, `ExecuteAsync`, `QueryFirst`, `QueryFirstAsync`, `QuerySingle`, `QuerySingleAsync`, `QueryFirstOrDefault`, `QuerySingleOrDefault`. Plus the constructor `SqlCommand` (its argument 0 is the query; also `MySqlCommand`, `NpgsqlCommand`, `OracleCommand`, `SqliteCommand`).

**Command** — `CG-CMD-EXEC`, `CWE-78`, CRITICAL, `_CMD`, `vuln_class="command"`, `bare=True`, `shell=SHELL_CONDITIONAL`:
`Start` (covers `Process.Start`). Plus the constructor `ProcessStartInfo` (its `FileName`/`Arguments` carry the command). `SHELL_CONDITIONAL` because a shell runs only when the program is `cmd /c` / `bash -c` / `powershell`.

**Path** — `CG-PATH-TRAVERSAL`, `CWE-22`, HIGH, `"opens a file whose path comes from this value"`, `vuln_class="path"`, `bare=True`:
`ReadAllText`, `WriteAllText`, `ReadAllBytes`, `WriteAllBytes`, `ReadAllLines`, `Open`, `OpenRead`, `OpenWrite`, `OpenText`, `Delete`. Plus the constructors `StreamReader`, `StreamWriter`, `FileStream`, `FileInfo` (their argument 0 is the path). (`Path.Combine` is deliberately excluded — it is a path *builder*, not a filesystem sink, and flagging it floods REVIEW; a taint that flows from `Path.Combine` into a real sink is still caught at that sink.)

**Deserialization** — `CG-DESERIALIZE`, `CWE-502`, CRITICAL, `_DESERIALIZE`, `vuln_class="deserialize"`, `bare=True`:
`Deserialize`, `ReadObject`. Bare `Deserialize` intentionally covers the whole ysoserial.net RCE family (`BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`, `XmlSerializer`, `DataContractSerializer`, `JavaScriptSerializer`). `ReadObject` covers `DataContractSerializer`/`NetDataContractSerializer`.
**Accepted fail-safe over-flag (design decision):** bare `Deserialize` also matches the safe-by-default `System.Text.Json` `JsonSerializer.Deserialize` and Newtonsoft `JsonConvert.Deserialize`. Those will read REVIEW (UNKNOWN/UNSAFE), never SAFE and never a false ACCEPT — consistent with the cardinal rule (over-flag, never miss). Narrowing by receiver-type once type hints are available is a documented follow-up, not part of this slice.

**Code-execution** — `CG-CODE-EXEC`, `CWE-95`, CRITICAL, `"runs this value as program code"`, `vuln_class="code"`:
Exact dotted names (NOT bare, to avoid matching unrelated `EvaluateAsync`/`RunAsync`): `CSharpScript.EvaluateAsync`, `CSharpScript.RunAsync`, `CSharpScript.Create`, `CSharpCodeProvider.CompileAssemblyFromSource`.

`lookup_sink(name, "csharp")` uses the existing exact-then-bare-tail matching. Other languages must be unaffected (`lookup_sink("cmd.ExecuteReader", "python")` → None; existing Python/JS/Go/Java lookups unchanged).

## Component 2 — Classifier (`csharp_provenance.py`)

Port `java_provenance.py` verbatim in structure and public interface, then add C#-specific composition forms. Public functions (same signatures/return shapes as Java so the analyzer consumes them identically):

- `assess(sink, arg_text, tainted_names) -> VERDICT_SAFE | VERDICT_UNSAFE | VERDICT_UNKNOWN`
- `assess_command(args, tainted_names) -> verdict` (assesses ALL args — command injection hides in non-first args, e.g. `cmd /c {user}`)
- `assess_deserialization(tainted_present: bool) -> verdict` (UNSAFE if tainted else UNKNOWN — **never SAFE**)
- `classify(arg_text) -> LITERAL | COMPOSED | OPAQUE`
- `variable_names(arg_text) -> list[str]`
- plus the ported internals: `extract_first_arg`, `extract_all_args`, `_split_plus`, `_is_proven_literal_operand`, `_operand_candidates`, `_chain_operand_candidates`, `_chain_receiver`, `_is_bare_call_receiver`, the quote-aware call/paren scanners, and the whole-text coverage guard (all inherited from Java's seven hardening rounds).

**C#-specific additions (the reason C# needs its own classifier, not just Java reused):**

1. **String interpolation `$"...{expr}..."` → COMPOSED.** Each `{expr}` hole is an operand. Strip an interpolation format/alignment suffix (`{expr:D2}`, `{expr,10}`, `{expr,-10:C}`) down to `expr` before classifying. Escaped braces `{{`/`}}` are literal text, not holes. A construction whose holes are ALL proven literals (`$"page {1}"`) reads SAFE; any hole that is a variable/non-literal → UNSAFE (if taint-confirmed) or UNKNOWN — never SAFE. Interpolated SQL/commands (`$"SELECT * FROM u WHERE id = {id}"`, `$"cmd /c {arg}"`) are the dominant real-world C# injection shape and MUST be graded.
2. **Verbatim strings `@"..."`** — inside a verbatim string, `""` (a doubled quote) is an escaped quote and `\` is a literal backslash (no `\"` escaping). The quote-aware scanner must recognize the `@"` opener and the `""` escape so a `"` inside a verbatim literal does not desync quote tracking (the same failure class the Java text-block round fixed).
3. **Interpolated-verbatim `$@"..."` and `@$"..."`** — both forms; combine rules 1 and 2 (holes + `""` escape).
4. Inherited unchanged from the Java port: `+` concatenation, `string.Format(...)` → COMPOSED, `StringBuilder.Append(...)` chains → COMPOSED, call-chain receiver taint-checking, non-allowlisted-`new` handling, trailing-chained-call coverage, and `assess_deserialization` never SAFE.

The cardinal rule is enforced by the same positive-literal-proof machinery: SAFE is reachable only when the entire argument text is accounted for by proven-literal operands / benign navigation.

## Component 3 — Routing (`csharp.py`)

Graduate from inventory to verdicts, mirroring `java.py`'s Task-3 wiring:

- **Dedicated sink matcher** `_CSHARP_SINK_CALL_RE` to catch what `CALL_RE` misses: constructors (`new SqlCommand(...)`, `new StreamReader(...)`, `new ProcessStartInfo(...)`) and chained calls (`db.Query(...)`, `formatter.Deserialize(...)`). Pattern shape: `\bnew\s+(?P<ctor>[A-Z]\w*)\s*\(|\.(?P<method>[A-Za-z_]\w*)\s*\(`, with line/column offset translation via line-start offsets.
- **Dispatch by `vuln_class`**: sql/path → `assess` (first arg / relevant arg); command → `assess_command` (ALL args); deserialization → `assess_deserialization(tainted_present)`; code → `assess`.
- **Zero-arg guard**: skip a sink call with proven-empty `()` for sql/path/command/code (e.g. `reader.ExecuteReader()` where the query lives elsewhere) — SKIP emission, never emit SAFE. **Exempt deserialization** (`.Deserialize(stream)` is the normal form and must always be graded; and a genuinely zero-arg deser call is still graded).
- **Comment-aware grading**: grade over comment-blanked source (reuse the shared `_source_text` tokenizer if it models C#; otherwise blank `//` line comments and `/* */` block comments in a quote/verbatim/interpolation-aware way, preserving line numbers). Commented-out sinks must not be graded.
- **De-duplication**: when `lookup_sink(name, "csharp")` resolves, emit the real verdict rule id and suppress the legacy `CG-CSHARP-SINK-CALL` inventory row for the same sink; unresolved calls keep the inventory row (behind the SARIF filter).
- **Taint for deserialization** `tainted_present`: whether the receiver/stream argument is taint-reachable per the existing `tainted_by_function` / `INPUT_MARKERS` machinery.

## Component 4 — Capability / coverage

`src/cybergraph/security/capability.py`:
- Add `CSHARP_GLOBS = ("*.cs",)`.
- Broaden `covers` to include `CSHARP_GLOBS` for FIVE capabilities: `sql_construction`, `command_execution`, `path_access`, `deserialization`, **and `code_execution`** (C# is the first non-Python language to add code-exec). Keep the existing globs (Python/web/Go/Java) intact.
- **`VERIFIED_GLOBS` unchanged** (Python-only). C# stays `NOT_SUPPORTED` for `source_analysis_support` — the honesty invariant: a structural line-based classifier is not a full verified analyzer.

`src/cybergraph/security/coverage.py`:
- Add `CSHARP_GLOBS` to the verified-coverage gate (`VERIFIED_GLOBS + CONFIG_GLOBS + WEB_GLOBS + GO_GLOBS + JAVA_GLOBS + CSHARP_GLOBS`) so an in-scope `*.cs` file with a sink reads PASS/verdict rather than a blanket UNKNOWN.
- **Honesty gate intact**: an unparseable/unreadable `*.cs` file must still read UNKNOWN/FAILED (via the pre-existing `CG-FILE-UNREADABLE` / parse-failure path, which is language-agnostic), never PASS.

## Component 5 — Mutation harness

Append `D9-csharp` fail-open mutations to `benchmark/mutation_harness.py` (append only — never reorder/rewrite existing entries). Each patches `csharp_provenance.py` / `csharp.py` to reintroduce a specific fail-open and maps to an existing committed C# test that catches it:

- `D9-csharp-tainted-sink-reads-safe` — flip taint→UNSAFE to SAFE.
- `D9-csharp-unresolved-var-reads-safe` — flip unresolved→UNKNOWN to SAFE.
- `D9-csharp-deser-reads-safe` — flip `assess_deserialization` to return SAFE.
- `D9-csharp-interpolation-hole-reads-safe` — C#-specific: make an interpolation hole's operand read SAFE (drop the hole from the operand set).

Every `old=` find-string must exist verbatim-unique in the current source; all mutations (existing + new) must be CAUGHT.

## Component 6 — Docs

- `README.md`: a bullet that C# now earns real SQL/command/path/deserialization/code-execution verdicts (mirroring the JS/Go/Java bullets).
- `docs/CRITICAL_AUDIT.md` §4.5: update to "resolved for JS, Go, Java, and C# core sink classes" (C# adds code-execution). Note that other/unlisted sink classes still fall back to inventory. Judge whether §4.5 can now be marked CLOSED (C# is the last planned non-Python language) or stays OPEN for the remaining non-core classes — decide at write time based on what the audit tracks.

## Testing strategy

TDD, stdlib only, `from __future__ import annotations`, ruff clean. Per-component tests:
- `tests/test_sinks_csharp.py` — registry resolves; rule_id/shell/bare/vuln_class values; no cross-language leakage.
- `tests/test_csharp_provenance.py` — the classifier's SAFE surface, adversarial: interpolation holes (literal→SAFE, variable→UNSAFE/UNKNOWN), verbatim `@"..."` / `$@"..."` quote handling, `+`/`string.Format`/`StringBuilder` composition, command all-args, deserialization never SAFE, receiver/chain/coverage cases inherited from Java. Assert EXACT verdicts (`==`), never `!= SAFE`.
- `tests/test_csharp_verdicts_e2e.py` — end-to-end `analyze_csharp_file` on real C# snippets: constructor sinks, chained calls, interpolated SQL, `Process.Start` command, `BinaryFormatter.Deserialize`, `CSharpScript.EvaluateAsync`, zero-arg guard, commented-out sinks, SAFE (all-literal) → no finding.
- `tests/test_coverage.py` / `tests/test_capability.py` — `*.cs` is analyzed at file-coverage level; C# stays NOT_SUPPORTED at capability level; unparseable `*.cs` → UNKNOWN.

## Global constraints

- stdlib only; `from __future__ import annotations` in every new module.
- ruff clean on all touched files (no new errors vs baseline).
- Full suite green; `python benchmark/mutation_harness.py` all CAUGHT; `python benchmark/run_precision.py` GATE PASSED (precision/recall/safe_fp_rate unchanged — C# registry is language-keyed, so Python/JS/Go/Java corpora must be byte-identical); `python benchmark/run_eval.py` unchanged (do not commit `results.json`).
- Commits authored `Laraib <lxh417bham@gmail.com>`; never pass `-c user.email`; no Co-Authored-By / AI attribution; never squash; push only to `AQ-Labs/cybergraph`.

## Decisions and deferrals

- **Five classes** including code-execution (SQL/command/path/deserialization/code-exec) — user-chosen.
- **Deserialization over-flag accepted** — bare `Deserialize` over-flags safe JSON deserializers to REVIEW; fail-safe (never a missed vuln / false ACCEPT). Narrowing by receiver-type is a follow-up.
- **`Path.Combine` excluded** — path builder, not a sink; taint is caught at the real sink.
- **Out of scope** (documented deferrals, not lost): a C# parser dependency, `*.cs` in `VERIFIED_GLOBS`, interprocedural flow, `TypeNameHandling`-config detection for JSON deserializers, reflection-based invocation (`Assembly.Load`, `MethodInfo.Invoke`), and non-core sink classes.

## Merge / sequencing

Off current `main` (which has JS/Go/Java). Touches the same shared files as prior slices (`sinks.py`, `capability.py`, `coverage.py`, `mutation_harness.py`, `README.md`, `CRITICAL_AUDIT.md`); additive. If another slice merges first, rebase onto the new `main` and re-resolve additively. C# is the last planned non-Python language.

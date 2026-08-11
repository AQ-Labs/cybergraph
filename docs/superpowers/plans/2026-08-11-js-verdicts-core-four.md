# JS/TS Verdicts — the Core Four — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn JavaScript/TypeScript from inventory-grade `CG-JS-SINK-CALL` into real safe/unsafe/unknown verdicts for the four sink classes CyberGraph already verifies in Python (SQL, command, code-exec, path), so a JS injection reviews under the same capability as Python — precisely, with only an all-literal/constant argument ever reading SAFE.

**Architecture:** A per-language sink registry in `sinks.py`, a new lightweight `js_provenance.py` (argument extraction + construction classification + per-class assessment, reusing the LITERAL/COMPOSED/OPAQUE vocabulary and `VERDICT_*`), `javascript.py` routing the four classes through it to emit graded findings, and a one-line broadening of the four capabilities' `covers`. No `checks.py` change (the rule ids are already mapped; coverage already treats web files as analyzed via `WEB_GLOBS` from #45).

**Tech Stack:** Python 3.10–3.13, standard library only (`re`). Existing `sinks.Sink`/`lookup_sink`, `predicates.VERDICT_*`, `provenance.LITERAL/COMPOSED/OPAQUE`, the capability/coverage/checks machinery, the taint `javascript.py` already computes.

## Global Constraints

- **Zero runtime dependencies**; standard library only — **no JS parser** (tree-sitter/esprima). The classifier is lightweight/structural and fail-safe.
- Python 3.10–3.13. `from __future__ import annotations` first line of any new file.
- Ruff line-length 100; run `ruff check` on every touched file — clean.
- No network; no API keys on any default path.
- **Precision over recall (cardinal):** only an all-literal/constant construction is SAFE. A construction containing a variable is UNSAFE (taint-confirmed user input) or UNKNOWN (unresolved) — **never SAFE**, and never a confident UNSAFE on an unresolved variable. Anything the classifier cannot read → UNKNOWN.
- Findings carry `rule_id`, `severity`, `message`, `file_path`, `line_start`, `cwe`, `evidence`; honor `is_inline_suppressed`.
- Commits `Laraib <lxh417bham@gmail.com>` only (repo-local config already carries it — do **not** pass `-c user.email=`); no `Co-Authored-By`, no AI attribution. Many small commits; never squash. Push only to `https://github.com/AQ-Labs/cybergraph`.
- Branch `feat/js-verdicts-core-four` is stacked on `feat/cors-client-boundary` (#45); do not rebase during implementation.

---

## File Structure

- `src/cybergraph/security/sinks.py` (modify) — add `_JAVASCRIPT`; register in `_BY_LANGUAGE`.
- `src/cybergraph/analysis/js_provenance.py` (create) — arg extraction, construction classifier, per-class assessor.
- `src/cybergraph/analysis/javascript.py` (modify) — route the four sink classes through the assessor.
- `src/cybergraph/security/capability.py` (modify) — broaden four capabilities' `covers` to `+WEB_GLOBS`.
- Tests: `tests/test_sinks_javascript.py`, `tests/test_js_provenance.py`, `tests/test_js_verdicts_e2e.py` (create).
- `benchmark/mutation_harness.py` (modify) — two seeded fail-opens.
- `README.md`, `docs/CRITICAL_AUDIT.md` (modify) — document; update §4.5 note.

---

## Task 1: JS sink registry in `sinks.py`

**Files:**
- Modify: `src/cybergraph/security/sinks.py`
- Test: `tests/test_sinks_javascript.py` (create)

**Interfaces:**
- Produces: `_JAVASCRIPT: tuple[Sink, ...]` and `_BY_LANGUAGE["javascript"] = _JAVASCRIPT`, so `lookup_sink(name, "javascript")` resolves JS sinks to Python's rule ids.

- [ ] **Step 1: Write the failing test**

Create `tests/test_sinks_javascript.py`:

```python
from __future__ import annotations

import pytest

from cybergraph.security.sinks import lookup_sink


@pytest.mark.parametrize("call_name,rule_id,vuln", [
    ("db.query", "CG-SQL-EXEC", "sql"),
    ("pool.query", "CG-SQL-EXEC", "sql"),
    ("knex.raw", "CG-SQL-EXEC", "sql"),
    ("connection.execute", "CG-SQL-EXEC", "sql"),
    ("child_process.exec", "CG-CMD-EXEC", "command"),
    ("execSync", "CG-CMD-EXEC", "command"),
    ("eval", "CG-CODE-EXEC", "code"),
    ("Function", "CG-CODE-EXEC", "code"),
    ("fs.readFile", "CG-PATH-TRAVERSAL", "path"),
    ("fsp.writeFile", "CG-PATH-TRAVERSAL", "path"),
])
def test_javascript_sinks_resolve(call_name, rule_id, vuln):
    sink = lookup_sink(call_name, "javascript")
    assert sink is not None, call_name
    assert sink.rule_id == rule_id
    assert sink.vuln_class == vuln


def test_non_sink_js_name_is_none():
    assert lookup_sink("res.render", "javascript") is None
    assert lookup_sink("console.log", "javascript") is None


def test_python_lookups_unchanged():
    assert lookup_sink("os.system", "python").rule_id == "CG-CMD-EXEC"
    assert lookup_sink("db.query", "python") is None  # JS sink not registered for python
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_sinks_javascript.py -v` — Expected: FAIL (JS sinks return None).

- [ ] **Step 3: Implement the registry**

In `sinks.py`, add after `_PYTHON`:

```python
_JS_SQL = "sends this value to the database as part of a query"
_JS_CMD = "runs a system command built from this value"

_JAVASCRIPT: tuple[Sink, ...] = (
    # SQL — receivers (db/pool/knex/connection) are unresolvable → bare on the method name.
    Sink("query", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _JS_SQL, "sql", bare=True),
    Sink("execute", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _JS_SQL, "sql", bare=True),
    Sink("raw", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _JS_SQL, "sql", bare=True),
    # Command — exec/execSync spawn a shell (inherent); spawn/execFile take argv (conditional).
    Sink("child_process.exec", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _JS_CMD,
         "command", shell=SHELL_INHERENT),
    Sink("exec", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _JS_CMD, "command",
         bare=True, shell=SHELL_INHERENT),
    Sink("execSync", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _JS_CMD, "command",
         bare=True, shell=SHELL_INHERENT),
    Sink("spawn", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _JS_CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    Sink("execFile", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _JS_CMD, "command",
         bare=True, shell=SHELL_CONDITIONAL),
    # Code
    Sink("eval", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    Sink("Function", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    # Path — fs / fs.promises receivers unresolvable → bare on the method name.
    Sink("readFile", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("readFileSync", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("writeFile", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("writeFileSync", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
    Sink("createReadStream", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
)
```

Change `_BY_LANGUAGE` to `{"python": _PYTHON, "javascript": _JAVASCRIPT}`.

> `bare=True` matches on the final dotted segment (per `lookup_sink`), so `db.query`/`pool.query` → `query`, `fs.readFile`/`fsp.readFile` → `readFile`. `eval`/`Function` are unqualified builtins (non-bare, exact). Confirm `test_non_sink_js_name_is_none` still holds — `res.render`/`console.log` have no matching entry.

- [ ] **Step 4: Run tests + ruff**

Run: `pytest tests/test_sinks_javascript.py -v` — Expected: PASS. Run: `ruff check src/cybergraph/security/sinks.py tests/test_sinks_javascript.py` — clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/security/sinks.py tests/test_sinks_javascript.py
git commit -m "feat(sinks): register JS/TS core-four sinks with Python's rule ids"
```

---

## Task 2: `js_provenance.py` — argument extraction, classifier, assessor

**Files:**
- Create: `src/cybergraph/analysis/js_provenance.py`
- Test: `tests/test_js_provenance.py` (create)

**Interfaces:**
- Consumes: `sinks.Sink`/`SHELL_INHERENT`/`SHELL_CONDITIONAL`, `predicates.VERDICT_SAFE/UNSAFE/UNKNOWN`, `provenance.LITERAL/COMPOSED/OPAQUE`.
- Produces:
  - `extract_first_arg(source: str, open_paren: int) -> str | None` — balanced, string-aware first-argument text; `None` if unbalanced/unreadable.
  - `classify(arg_text: str) -> str` — `LITERAL` / `COMPOSED` / `OPAQUE`.
  - `variable_names(arg_text: str) -> list[str]` — identifiers introduced by `${…}` interpolation or `+` concatenation (excluding string-literal parts).
  - `assess(sink: Sink, arg_text: str | None, tainted_names: set[str]) -> str` — the `VERDICT_*`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_js_provenance.py`:

```python
from __future__ import annotations

from cybergraph.analysis.js_provenance import (
    assess, classify, extract_first_arg, variable_names,
)
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE
from cybergraph.security.sinks import lookup_sink


def _sink(name):
    return lookup_sink(name, "javascript")


def test_extract_first_arg_balanced_and_string_aware():
    src = "db.query(`SELECT ${x}`, [y])"
    open_paren = src.index("(")
    assert extract_first_arg(src, open_paren) == "`SELECT ${x}`"
    # a ')' inside a string must not end the arg early
    src2 = "exec('echo )')"
    assert extract_first_arg(src2, src2.index("(")) == "'echo )'"
    # unbalanced -> None
    assert extract_first_arg("db.query(`oops", 8) is None


def test_classify():
    assert classify("'SELECT 1'") == "literal"
    assert classify('"static"') == "literal"
    assert classify("`no interpolation`") == "literal"
    assert classify("`SELECT ${x}`") == "composed"
    assert classify("'SELECT ' + name") == "composed"
    assert classify("someVar") == "opaque"
    assert classify("build()") == "opaque"


def test_variable_names():
    assert variable_names("`SELECT ${name} FROM t`") == ["name"]
    assert variable_names("'a' + b + 'c'") == ["b"]
    assert variable_names("`only literals`") == []


def test_assess_sql_literal_is_safe():
    assert assess(_sink("db.query"), "'SELECT 1'", set()) == VERDICT_SAFE


def test_assess_sql_tainted_variable_is_unsafe():
    assert assess(_sink("db.query"), "`SELECT ${id}`", {"id"}) == VERDICT_UNSAFE


def test_assess_sql_unresolved_variable_is_unknown_not_safe():
    # a variable taint can't confirm must NOT read safe (JS taint is weaker than Python's)
    assert assess(_sink("db.query"), "`SELECT ${id}`", set()) == VERDICT_UNKNOWN


def test_assess_sql_all_literal_template_is_safe():
    assert assess(_sink("db.query"), "`SELECT 1 FROM t`", set()) == VERDICT_SAFE


def test_assess_opaque_is_unknown():
    assert assess(_sink("db.query"), "buildQuery()", set()) == VERDICT_UNKNOWN


def test_assess_unreadable_arg_is_unknown():
    assert assess(_sink("db.query"), None, set()) == VERDICT_UNKNOWN


def test_assess_code_eval_literal_safe_variable_unsafe():
    assert assess(_sink("eval"), "'1 + 1'", set()) == VERDICT_SAFE
    assert assess(_sink("eval"), "userCode", {"userCode"}) == VERDICT_UNSAFE
    assert assess(_sink("eval"), "userCode", set()) == VERDICT_UNKNOWN


def test_assess_command_inherent_shell_tainted_unsafe():
    assert assess(_sink("child_process.exec"), "`ls ${dir}`", {"dir"}) == VERDICT_UNSAFE
    assert assess(_sink("child_process.exec"), "`ls ${dir}`", set()) == VERDICT_UNKNOWN
    assert assess(_sink("child_process.exec"), "'ls -la'", set()) == VERDICT_SAFE
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_js_provenance.py -v` — Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `js_provenance.py`**

Create `src/cybergraph/analysis/js_provenance.py`:

```python
"""Lightweight construction provenance for JavaScript/TypeScript sink arguments.

No JS parser: a structural, statement-local classifier over the argument text,
fail-safe on anything it cannot read. It reuses the engine's vocabulary
(LITERAL/COMPOSED/OPAQUE and VERDICT_*) but is deliberately more conservative
than the Python predicates: because JS taint is weaker (intra-function,
line-based), only an all-literal/constant construction is SAFE. A construction
that contains a variable is UNSAFE when taint confirms it is user-controlled and
UNKNOWN otherwise -- never SAFE, and never a confident UNSAFE on an unresolved
variable.
"""

from __future__ import annotations

import re

from cybergraph.analysis.provenance import COMPOSED, LITERAL, OPAQUE
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE
from cybergraph.security.sinks import Sink

_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_STRING_ONLY_RE = re.compile(r"""^\s*(?:'[^']*'|"[^"]*"|`[^`]*`)\s*$""")
# a template literal with no interpolation hole
_TEMPLATE_NO_INTERP_RE = re.compile(r"^\s*`[^`]*`\s*$")
_INTERP_RE = re.compile(r"\$\{([^}]*)\}")
_JS_KEYWORDS = {"true", "false", "null", "undefined", "this"}


def extract_first_arg(source: str, open_paren: int) -> str | None:
    """Return the first top-level argument's source text, or None if unbalanced.

    String-aware (skips ()/,/quotes inside string and template literals) so a
    ')' or ',' inside a literal does not end the argument early.
    """
    depth = 0
    quote: str | None = None
    start = -1
    i = open_paren
    while i < len(source):
        c = source[i]
        if quote is not None:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c == "(":
            depth += 1
            if depth == 1:
                start = i + 1
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return source[start:i].strip() or None
        elif c == "," and depth == 1:
            return source[start:i].strip() or None
        i += 1
    return None  # unbalanced -> caller treats as UNKNOWN


def classify(arg_text: str) -> str:
    s = arg_text.strip()
    if _STRING_ONLY_RE.match(s) and "${" not in s:
        return LITERAL
    if s.startswith("`") and "${" in s:
        return COMPOSED
    if "+" in s and ("'" in s or '"' in s or "`" in s):
        return COMPOSED
    return OPAQUE


def variable_names(arg_text: str) -> list[str]:
    """Identifiers introduced by ${...} interpolation or a + operand, minus literals."""
    names: list[str] = []
    for hole in _INTERP_RE.findall(arg_text):
        m = _IDENT_RE.search(hole)
        if m and m.group(0) not in _JS_KEYWORDS:
            names.append(m.group(0))
    if "+" in arg_text:
        # operands that are not string literals
        for part in _split_plus(arg_text):
            p = part.strip()
            if p and not (p[0] in "'\"`"):
                m = _IDENT_RE.match(p)
                if m and m.group(0) not in _JS_KEYWORDS and not p[0].isdigit():
                    names.append(m.group(0))
    # de-dup, preserve order
    seen: set[str] = set()
    out = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _split_plus(text: str) -> list[str]:
    """Split on top-level '+', string/paren-aware."""
    parts, depth, quote, buf = [], 0, None, []
    i = 0
    while i < len(text):
        c = text[i]
        if quote is not None:
            buf.append(c)
            if c == "\\":
                if i + 1 < len(text):
                    buf.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
            buf.append(c)
        elif c in "([{":
            depth += 1
            buf.append(c)
        elif c in ")]}":
            depth -= 1
            buf.append(c)
        elif c == "+" and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    parts.append("".join(buf))
    return parts


def assess(sink: Sink, arg_text: str | None, tainted_names: set[str]) -> str:
    """Verdict for a JS sink call. Only an all-literal/constant construction is SAFE."""
    if arg_text is None:
        return VERDICT_UNKNOWN
    construction = classify(arg_text)
    if construction == LITERAL:
        return VERDICT_SAFE
    names = variable_names(arg_text)
    if not names:
        # composed of only literals (e.g. `'a' + 'b'`) -> safe
        return VERDICT_SAFE
    tainted = any(n in tainted_names for n in names)
    if tainted:
        return VERDICT_UNSAFE
    return VERDICT_UNKNOWN
```

> Confirm the `LITERAL`/`COMPOSED`/`OPAQUE` string values imported from `provenance` (they are the lowercase strings `"literal"`/`"composed"`/`"opaque"` per the test). If the import names differ, adapt the import — do not redefine the constants. The command/shell nuance is intentionally simplified to the fail-safe rule (tainted → UNSAFE, unresolved variable → UNKNOWN, all-literal → SAFE); array-argv refinement is deferred (documented in the spec).

- [ ] **Step 4: Run tests + ruff**

Run: `pytest tests/test_js_provenance.py -v` — Expected: PASS. Run: `ruff check src/cybergraph/analysis/js_provenance.py tests/test_js_provenance.py` — clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/analysis/js_provenance.py tests/test_js_provenance.py
git commit -m "feat(analysis): JS construction classifier and fail-safe sink assessor"
```

---

## Task 3: Route JS sink calls through the assessor

**Files:**
- Modify: `src/cybergraph/analysis/javascript.py`
- Test: `tests/test_js_verdicts_e2e.py` (create — analyzer-level)

**Interfaces:**
- Consumes: `lookup_sink`, `js_provenance.extract_first_arg`/`assess`, `predicates.VERDICT_*`, the existing per-call `tainted` map + `_tainted_source_for_line`.
- Produces: for a sink call whose name resolves via `lookup_sink(call_name, "javascript")`, a graded finding — `sink.rule_id` (UNSAFE) / `sink.rule_id + "-UNVERIFIED"` (UNKNOWN) / none (SAFE) — **instead of** `CG-JS-SINK-CALL`. Names not in the registry keep emitting `CG-JS-SINK-CALL`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_js_verdicts_e2e.py`:

```python
from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.javascript import analyze_javascript_file


def _rules(tmp_path: Path, name: str, src: str):
    p = tmp_path / name
    p.write_text(src, encoding="utf-8")
    _n, _e, findings = analyze_javascript_file(p, tmp_path)
    return [f.rule_id for f in findings]


def test_parameterized_query_is_safe(tmp_path):
    src = "function h(db,id){ return db.query('SELECT * FROM u WHERE id = ?', [id]); }\n"
    rules = _rules(tmp_path, "a.js", src)
    assert "CG-SQL-EXEC" not in rules
    assert "CG-SQL-EXEC-UNVERIFIED" not in rules
    assert "CG-JS-SINK-CALL" not in rules  # a registered sink no longer emits inventory


def test_tainted_template_query_is_unsafe(tmp_path):
    src = (
        "function h(db, req){ const id = req.query.id;\n"
        "  return db.query(`SELECT * FROM u WHERE id = ${id}`); }\n"
    )
    assert "CG-SQL-EXEC" in _rules(tmp_path, "a.js", src)


def test_unresolved_variable_query_is_unverified(tmp_path):
    src = "function h(db, id){ return db.query(`SELECT * FROM u WHERE id = ${id}`); }\n"
    rules = _rules(tmp_path, "a.js", src)
    assert "CG-SQL-EXEC-UNVERIFIED" in rules
    assert "CG-SQL-EXEC" not in rules  # not a confident unsafe on an unproven variable


def test_non_registry_sink_stays_inventory(tmp_path):
    # res.render is in the legacy SINK_CALLS but not the verdict registry -> inventory-grade
    rules = _rules(tmp_path, "a.js", "function h(res, x){ return res.render(x); }\n")
    assert "CG-JS-SINK-CALL" in rules
    assert "CG-SQL-EXEC" not in rules
```

> Note: the taint fixture uses `req.query.id` (an `INPUT_MARKERS` source) so `id` is tracked as user-controlled. Confirm against `javascript.py`'s taint how a name becomes tainted; adjust the fixture so `id` is genuinely in the per-line `tainted` set. If wiring the exact tainted-name set to the assessor proves intricate, pass the names the analyzer already resolves as user-controlled for that line.

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_js_verdicts_e2e.py -v` — Expected: FAIL (still emits `CG-JS-SINK-CALL`).

- [ ] **Step 3: Implement the routing**

In `javascript.py`, add imports:

```python
from cybergraph.analysis.js_provenance import assess as assess_js_sink
from cybergraph.analysis.js_provenance import extract_first_arg
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE
from cybergraph.security.sinks import lookup_sink
```

Replace the sink-finding block (the `if _is_sink(call_name, custom_sinks):` body that appends `CG-JS-SINK-CALL`) with registry-first routing. Keep the `EDGE_REACHES_SINK`/`EDGE_TAINTS` edges as they are; change only the finding:

```python
            sink = lookup_sink(call_name, "javascript")
            if sink is not None or _is_sink(call_name, custom_sinks):
                edges.append(Edge(EDGE_REACHES_SINK, sink_source, call_name, rel, line_no))
                if sink is not None:
                    arg = extract_first_arg(source, call.end() - 1)
                    tainted_names = set(tainted) | _line_tainted_names(line, tainted)
                    verdict = assess_js_sink(sink, arg, tainted_names)
                    finding = _js_verdict_finding(sink, verdict, rel, line_no, line)
                    if finding is not None and not is_inline_suppressed(
                        lines, line_no, finding.rule_id
                    ):
                        findings.append(finding)
                elif not is_inline_suppressed(lines, line_no, "CG-JS-SINK-CALL"):
                    findings.append(
                        Finding(
                            rule_id="CG-JS-SINK-CALL",
                            severity="medium",
                            message="JavaScript/TypeScript file reaches sensitive sink "
                                    f"`{call_name}`",
                            file_path=rel,
                            line_start=line_no,
                            cwe="CWE-20",
                            evidence=line.strip(),
                        )
                    )
                taint_source = source_key or _tainted_source_for_line(line, tainted)
                if taint_source:
                    edges.append(Edge(EDGE_TAINTS, taint_source, call_name, rel, line_no,
                                      {"function": sink_source, "reason": "tainted argument"}))
```

Add helpers at module scope:

```python
def _line_tainted_names(line: str, tainted: dict) -> set[str]:
    """Names on this line that the analyzer tracks as user-controlled."""
    return {name for name in tainted if re.search(rf"\b{re.escape(name)}\b", line)}


def _js_verdict_finding(sink, verdict, rel, line_no, line):
    if verdict == VERDICT_SAFE:
        return None
    unsafe = verdict == VERDICT_UNSAFE
    return Finding(
        rule_id=sink.rule_id if unsafe else f"{sink.rule_id}-UNVERIFIED",
        severity=sink.severity if unsafe else "medium",
        message=(f"`{sink.name}` {sink.plain}" if unsafe
                 else f"`{sink.name}` {sink.plain}, and CyberGraph could not confirm "
                      "the value is safe"),
        file_path=rel,
        line_start=line_no,
        cwe=sink.cwe,
        evidence=line.strip(),
    )
```

> `call.end() - 1` points at the `(` of the matched `name(`. `extract_first_arg` reads from `source` (multi-line safe). `set(tainted)` are the function-local tainted names; `_line_tainted_names` narrows to names literally present on the sink line (a cheap, conservative approximation — a name tainted elsewhere but not on this line is treated as unresolved → UNKNOWN, which is fail-safe). Confirm `source` and `tainted` are in scope at this point in `analyze_javascript_file` (they are: `source` at the top, `tainted` per-line above the call loop).

- [ ] **Step 4: Run tests + ruff**

Run: `pytest tests/test_js_verdicts_e2e.py tests/test_javascript.py -v` — Expected: PASS (adjust any prior `test_javascript.py` assertion that expected `CG-JS-SINK-CALL` for one of the now-graded sinks — a registered sink now emits the verdict rule; change the expectation, not the code). Run: `ruff check src/cybergraph/analysis/javascript.py tests/test_js_verdicts_e2e.py` — clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/analysis/javascript.py tests/test_js_verdicts_e2e.py
git commit -m "feat(analysis): grade JS core-four sinks into real verdicts"
```

---

## Task 4: Broaden the four capabilities to web globs

**Files:**
- Modify: `src/cybergraph/security/capability.py`
- Test: `tests/test_js_verdicts_e2e.py` (append capability + end-to-end cases)

**Interfaces:**
- Produces: `sql_construction`, `command_execution`, `code_execution`, `path_access` with `covers = PYTHON_GLOBS + WEB_GLOBS`. `deserialization` stays `PYTHON_GLOBS`. `VERIFIED_GLOBS` unchanged.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_js_verdicts_e2e.py`:

```python
import subprocess

from cybergraph.security.capability import CAPABILITIES, FAIL, NOT_SUPPORTED
from cybergraph.security.check import check_change
from cybergraph.security.verdict import STATE_REVIEW


def _cap(cid):
    return next(c for c in CAPABILITIES if c.id == cid)


def test_four_capabilities_cover_web():
    for cid in ("sql_construction", "command_execution", "code_execution", "path_access"):
        assert any(g in _cap(cid).covers for g in ("*.ts", "*.js")), cid
    assert "*.ts" not in _cap("deserialization").covers  # unchanged


def _repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    for a in (["init", "-q"], ["config", "user.email", "t@e.com"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *a], check=True)
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "base"], check=True)
    return repo


def test_js_sqli_reviews_under_sql_construction(tmp_path):
    repo = _repo(tmp_path)
    (repo / "h.ts").write_text(
        "export function h(db, req){ const id = req.query.id;\n"
        "  return db.query(`SELECT * FROM u WHERE id = ${id}`); }\n",
        encoding="utf-8",
    )
    verdict = check_change(repo, mode="worktree")
    assert verdict.state == STATE_REVIEW
    assert any(c.capability_id == "sql_construction" and c.status == FAIL
               for c in verdict.checks)


def test_js_still_not_supported_overall(tmp_path):
    # source_analysis_support stays NOT_SUPPORTED for JS (the tool doesn't overclaim)
    repo = _repo(tmp_path)
    (repo / "h.ts").write_text("export const x = 1;\n", encoding="utf-8")
    verdict = check_change(repo, mode="worktree")
    assert any(c.capability_id == "source_analysis_support" and c.status == NOT_SUPPORTED
               for c in verdict.checks)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_js_verdicts_e2e.py -k capabilities or reviews or not_supported -v` — Expected: FAIL (covers still Python-only).

- [ ] **Step 3: Broaden the covers**

In `capability.py`, change the four entries from `PYTHON_GLOBS` to `PYTHON_GLOBS + WEB_GLOBS`:

```python
    Capability("sql_construction", "Unsafe database queries", PYTHON_GLOBS + WEB_GLOBS, True),
    Capability("command_execution", "Unsafe system commands", PYTHON_GLOBS + WEB_GLOBS, True),
    Capability("code_execution", "Code run from user input", PYTHON_GLOBS + WEB_GLOBS, True),
    Capability("path_access", "Files opened from user input", PYTHON_GLOBS + WEB_GLOBS, True),
```

Leave `deserialization`, `declared_login_rules`, `reachable_data_paths` on `PYTHON_GLOBS`, and `VERIFIED_GLOBS` unchanged.

- [ ] **Step 4: Run tests + ruff**

Run: `pytest tests/test_js_verdicts_e2e.py tests/test_capability.py tests/test_checks.py -v` — Expected: PASS (update any prior test asserting these four capabilities are Python-only relevance; change the expectation only). Run: `ruff check src/cybergraph/security/capability.py` — clean.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/security/capability.py tests/test_js_verdicts_e2e.py
git commit -m "feat(verdict): the four injection capabilities now cover JS/TS"
```

---

## Task 5: Mutation harness + docs + full verification

**Files:**
- Modify: `benchmark/mutation_harness.py`, `README.md`, `docs/CRITICAL_AUDIT.md`
- Verification: full suite, ruff, harness, precision/eval.

- [ ] **Step 1: Add the mutations**

Append two `Mutation` entries to `MUTATIONS`. Match `old` strings to committed source verbatim.

Mutation A — an interpolated-variable SQLi read as SAFE. Target `js_provenance.assess`'s tainted branch:
- `old` = `    tainted = any(n in tainted_names for n in names)\n    if tainted:\n        return VERDICT_UNSAFE`
- `new` = `    tainted = any(n in tainted_names for n in names)\n    if tainted:\n        return VERDICT_SAFE`
- `tests` = `("tests/test_js_provenance.py::test_assess_sql_tainted_variable_is_unsafe",)`
- id `D9-js-tainted-sqli-reads-safe`, disaster `D9`, note "a tainted JS sink argument must not read safe".

Mutation B — an unresolved variable read as SAFE instead of UNKNOWN. Target the fall-through:
- `old` = `    if tainted:\n        return VERDICT_UNSAFE\n    return VERDICT_UNKNOWN`
- `new` = `    if tainted:\n        return VERDICT_UNSAFE\n    return VERDICT_SAFE`
- `tests` = `("tests/test_js_provenance.py::test_assess_sql_unresolved_variable_is_unknown_not_safe",)`
- id `D9-js-unresolved-var-reads-safe`, disaster `D9`, note "a JS variable CyberGraph cannot resolve must read UNKNOWN, never SAFE".

Verify each `old` occurs exactly once. Run `python benchmark/mutation_harness.py` → both CAUGHT.

- [ ] **Step 2: Docs**

README: add a bullet noting JS/TS now earns real SQL/command/code/path verdicts (not just inventory). `docs/CRITICAL_AUDIT.md` §4.5: update the note to "resolved for JS SQL/command/code/path (slice 1 of the non-Python upgrade); Go/Java/C# and other JS classes remain inventory-grade" — do not mark §4.5 fully closed.

- [ ] **Step 3: Full verification**

Run: `pytest -q` — all pass. Run: `ruff check .` — no new errors beyond the pre-existing baseline. Run: `python benchmark/mutation_harness.py` — every mutation CAUGHT. Run: `python benchmark/run_precision.py` and `python benchmark/run_eval.py` — unchanged (1.0/1.0/1.0); **confirm the new JS handling did not change any Python-corpus result** (the JS registry is language-keyed, so Python lookups are unaffected — verify the numbers are identical).

- [ ] **Step 4: Commit**

```bash
git add benchmark/mutation_harness.py README.md docs/CRITICAL_AUDIT.md
git commit -m "test(js): seed JS verdict fail-open mutations; document the upgrade"
```

---

## Notes for the executor

- **Precision is cardinal.** Only an all-literal/constant construction is SAFE. A variable is UNSAFE (taint-confirmed) or UNKNOWN — never SAFE. When in doubt, UNKNOWN.
- Confirm names/signatures against source before running each task's tests: `provenance.LITERAL/COMPOSED/OPAQUE` string values, `Sink` fields, `check_change`/`Verdict.checks`, and exactly how a name enters `javascript.py`'s per-line `tainted` map; adapt the test to reality, never the reverse.
- The JS classifier is intentionally simple and fail-safe — resist adding clever resolution that could turn a variable SAFE. Array-argv/command-shell refinement and interprocedural taint are out of scope (later slices).
- Do NOT add a JS parser dependency, JS-specific rule ids, or `*.js` to `VERIFIED_GLOBS`.

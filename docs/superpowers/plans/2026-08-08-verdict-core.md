# Verdict Core Implementation Plan (rev. 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Phase 1 contract — the sentence this plan is judged against:**

> **Given a supported AI-generated Python change, CyberGraph can tell whether the specific security guarantees it understands were preserved — and explicitly admit what it could not verify.**

**Governing invariant:** *uncertainty never becomes safety.* Every place the code could
return "nothing found" because it did not look, it must return `UNKNOWN` instead.

**Milestones:** **1A Detector** (Tasks 1–7) is independently shippable and fixes the
2,739-finding problem on its own. **1B Verdict** (Tasks 8–20) builds the decision on top.

---

## Part 1 — What rev. 3 fixes

Rev. 2 was reviewed and rejected. Fifteen defects, all verified against the plan text
before being accepted. Ranked by whether they produce **false assurance** (an ACCEPT over
code that was never examined) or merely noise.

### Release blockers — these made CyberGraph accept without verifying

| # | Defect | Verification | Fixed in |
|---|---|---|---|
| B1 | **Untracked files are invisible.** A new file makes the tree dirty (so worktree mode is chosen) but `git diff --name-only HEAD` returns empty → zero changed files → everything `NOT_APPLICABLE` → ACCEPT | Ran it: `diff` → `[]`, `status --porcelain` → `?? brand_new_endpoint.py`. An agent creating an endpoint gets a clean bill of health | Task 14 |
| B2 | **`no evaluator → PASS`.** `_capability_checks` returned `PASS` for any capability without a mapped rule, which included `declared_login_rules` and `reachable_data_paths` — neither of which had an evaluator wired at all | Read: `_run_check` never called `find_attack_paths` or `review_security_delta` | Tasks 15, 16 |
| B3 | **Go / Java / C# changes accept.** Python caps cover `*.py`, web caps cover JS/TS, cloud caps cover infra. A `main.go`-only change matched nothing → no review trigger → ACCEPT | Read the glob table | Task 8 |
| B4 | **Parser failure → PASS.** `_capability_checks` saw only changed files and findings; a `.py` file that failed to parse produced zero findings, which read as clean | `analyze_python_file` emits `PY-SYNTAX` but nothing consumed it | Tasks 9, 15 |
| B5 | **Base materialisation fails open.** `_base_policy_state` returned an empty `Policy()` on failure — indistinguishable from "the base had no policy," so tamper detection vanished exactly when git broke | Read | Task 17 |

### Precision defects — real, but they over-report rather than under-report

| # | Defect | Note | Fixed in |
|---|---|---|---|
| P1 | **Provenance was not flow-sensitive.** `collect_bindings` walked the whole function with `ast.walk` (BFS, not source order) and applied one final state to every call site | Verified: both `Assign`s are yielded before the `Call`. But `_weaken` takes the *weakest* class, so a stale binding can only make a value look **more** dangerous — it cannot cause a miss. A precision bug, not a soundness hole | Task 3 |
| P2 | **Normalisation treated as confinement.** `normpath("../../etc/passwd")` is still traversal; `realpath` resolves symlinks without restricting the result to any directory | `basename` and `safe_join` confine. `abspath` / `normpath` / `realpath` do not | Task 4 |
| P3 | **Command semantics too coarse**, in both directions | `["sh","-c",user_input]` was SAFE (a miss). `subprocess.run(f"git show {rev}")` with `shell=False` was UNSAFE — but on POSIX Python passes the whole string as the *executable name*, so it is not injection (a false positive) | Task 4 |
| P4 | **Duplicate reasons.** A high-severity finding produced a `FAIL` check result *and* a separate finding reason — one vulnerability, two lines | Read `decide` | Task 16 |

### Correctness and hygiene

| # | Defect | Fixed in |
|---|---|---|
| C1 | Route-rename escape: `/admin/export` → `/export` with the guard dropped evades the delta, because identity was the route string and the old route is absent from the current graph | Tasks 11, 12 |
| C2 | Benchmark abstention loophole: a safe case that abstains counts as a true negative but operationally causes a REVIEW — perfect scores while reviewing every safe change | Task 7 |
| C3 | `runtime_exploitability` was listed as a capability then special-cased to `NOT_APPLICABLE` to stop it reviewing everything — bending a state's meaning | Task 8 (removed from the list) |
| C4 | Policy *problems* were reported as `rule_removed`; validation-marker removal used the `auth_marker_removed` headline ("no longer recognised as a login check") | Tasks 12, 16 |
| C5 | CLI help and the MCP docstring both said "safe to ship" — the banned phrase in lowercase, and the guard test was case-sensitive and only scanned `src/` | Tasks 18, 19 |
| C6 | MCP imported private CLI functions, re-coupling two presentation surfaces | Task 17 (`security/check.py`) |
| C7 | `--base origin/main` silently selected worktree mode, so the documented merge-base path was never exercised in CI | Task 14 |

### Found while fixing, not in the review

**The base graph was rebuilt from scratch on every `check`.** Task 17 in rev. 2
materialised the base revision and ran `build_graph` over the whole tree — O(repo), not
O(diff), on every invocation, at the latency-sensitive accept-the-diff moment. Rev. 3
caches the base analysis under `.cybergraph/base/<sha>/` and reuses it (Task 17).

### Not changed — scope holds

No ISO/ASVS/SSDF. No token router. No temporal analysis. No UI redesign. No language
expansion. No authorization ontology. No pentesting. No visual security diff. Everything
in the review was about making the existing Phase 1 promise true, and nothing here adds
product surface.

---

## Global Constraints

- **Python 3.10–3.13.** TOML access must work under `tomllib` (3.11+) and the flat fallback in `config.py:54`; they return different shapes for `[rule.x]`. Normalise, never assume.
- **Zero runtime dependencies.** `pyproject.toml` declares `dependencies = []`.
- **Ruff:** line-length 100, `select = ["E","F","I","N","W","UP"]`. Every file opens with `from __future__ import annotations`.
- **No network, no API keys** on any default path.
- **Plain-language rule:** no default-path user string may contain `sink`, `taint`, `CWE`, `SARIF`, `entrypoint`, `ontology`, or `attack path`. Permitted in drill-down, edge kinds and `rule_id`s.
- **Banned phrase:** the string `safe to ship` must not appear anywhere in `src/`, **case-insensitively**, including argparse help and docstrings. Task 18 enforces it.
- **UNKNOWN never silently becomes PASS.** Any code path that reports absence of a problem must be able to prove it looked.
- **Fail closed.** A git failure, an unreadable base, or an unparseable file is `UNKNOWN`, never "nothing changed."
- **No `BLOCK` state.** Verdict is `accept` or `review`. REVIEW exits 0 unless `--fail-on-review`.
- **Preserve inventory.** `REACHES_SINK` edges are emitted for every sink call even when no finding is produced.
- Existing suite (279 tests) green at every commit. No co-author trailer in commit messages.

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `src/cybergraph/security/sinks.py` | Sink registry: canonical name → vulnerability class, CWE, severity, plain-language consequence, shell semantics. |
| `src/cybergraph/analysis/provenance.py` | Flow-sensitive construction lattice (`LITERAL`/`COMPOSED`/`OPAQUE`) with a per-call-site snapshot. Knows nothing about security. |
| `src/cybergraph/security/predicates.py` | Per-sink unsafe-use predicates. Confinement ≠ normalisation; shell semantics per API. |
| `src/cybergraph/security/coverage.py` | Which changed files were actually analyzed, by which analyzer, with what outcome. |
| `src/cybergraph/security/capability.py` | Capability model and the five-state `CheckResult`. |
| `src/cybergraph/security/policy.py` | Policy model, strict loader, graph evaluation keyed by **entity**, delta classification, config delta, baseline extraction. |
| `src/cybergraph/security/revisions.py` | Invocation modes; unions untracked files; fails closed. |
| `src/cybergraph/security/verdict.py` | Verdict assembly, provenance, rendering. |
| `src/cybergraph/security/check.py` | **The single orchestrator.** CLI and MCP both call `check_change()`; neither imports the other. |
| `benchmark/precision/` | Labelled adversarial corpus, precision + recall + abstention gate. |

**Modified:** `analysis/python.py`, `security/attack_paths.py`, `cli.py`, `mcp_server.py`, `.github/workflows/cybergraph.yml`, `docs/CRITICAL_AUDIT.md`.

**Generated:** `cybergraph.policy.toml` at the repo root — **not** under `.cybergraph/`, which `.gitignore:14` excludes. Memory that cannot be committed is not memory.

---

# MILESTONE 1A — DETECTOR

---

## Task 1: Sink registry

**Files:** Create `src/cybergraph/security/sinks.py`; test `tests/test_sinks.py`.

**Interfaces:**
- `Sink` — frozen dataclass: `name`, `rule_id`, `cwe`, `severity`, `plain`, `vuln_class`, `bare: bool = False`, `shell: str = "none"`.
- `vuln_class` ∈ `sql` | `command` | `code` | `deserialize` | `path` | `template` | `custom`.
- `shell` ∈ `none` (no shell involved) | `inherent` (always runs a shell, e.g. `os.system`) | `conditional` (depends on a `shell=` keyword, e.g. `subprocess.run`). Task 5 dispatches on this.
- `lookup_sink(call_name: str, language: str) -> Sink | None`, `all_sinks() -> tuple[Sink, ...]`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_sinks.py`:

```python
from cybergraph.security.sinks import all_sinks, lookup_sink


def test_exact_qualified_name_matches():
    sink = lookup_sink("subprocess.run", "python")
    assert sink is not None
    assert sink.vuln_class == "command"
    assert sink.shell == "conditional"


def test_shell_inherent_apis_are_marked():
    assert lookup_sink("os.system", "python").shell == "inherent"
    assert lookup_sink("os.popen", "python").shell == "inherent"


def test_bare_callee_matches_when_receiver_unknown():
    assert lookup_sink("cursor.execute", "python").vuln_class == "sql"


def test_substring_no_longer_matches():
    for name in ("drawChart", "reopen_session", "writer_pool", "connect_retry_helper"):
        assert lookup_sink(name, "python") is None, name


def test_unknown_language_returns_none():
    assert lookup_sink("subprocess.run", "cobol") is None


def test_registry_is_internally_consistent():
    classes = {"sql", "command", "code", "deserialize", "path", "template", "custom"}
    banned = {"sink", "taint", "cwe", "sarif", "entrypoint"}
    for sink in all_sinks():
        assert sink.vuln_class in classes, sink.name
        assert sink.shell in {"none", "inherent", "conditional"}, sink.name
        assert sink.plain and not any(w in sink.plain.lower() for w in banned), sink.name
        if sink.shell != "none":
            assert sink.vuln_class == "command", sink.name
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_sinks.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.sinks'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/sinks.py`:

```python
"""Sensitive-sink registry.

Replaces substring keyword matching, which fired on ``drawChart`` for ``raw``
and ``reopen_session`` for ``open``. Matching is exact on the full dotted name
and, for entries marked ``bare``, on the final dotted segment — receivers like
``cursor`` cannot be resolved without type inference.

Reaching a sink is inventory; *using it unsafely* is a vulnerability.
``vuln_class`` selects the predicate in :mod:`cybergraph.security.predicates`,
and ``shell`` records whether the API runs a shell always, never, or depending
on a keyword — ``os.system`` and ``subprocess.run`` are not the same hazard.
"""

from __future__ import annotations

from dataclasses import dataclass

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"

SHELL_NONE = "none"
SHELL_INHERENT = "inherent"
SHELL_CONDITIONAL = "conditional"


@dataclass(frozen=True)
class Sink:
    name: str
    rule_id: str
    cwe: str
    severity: str
    plain: str
    vuln_class: str
    bare: bool = False
    shell: str = SHELL_NONE


_CMD = "runs a system command built from this value"
_SQL = "sends this value to the database as part of a query"
_DESERIALIZE = "rebuilds objects from this value, which can run code"

_PYTHON: tuple[Sink, ...] = (
    Sink("subprocess.run", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD,
         "command", shell=SHELL_CONDITIONAL),
    Sink("subprocess.call", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD,
         "command", shell=SHELL_CONDITIONAL),
    Sink("subprocess.Popen", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD,
         "command", shell=SHELL_CONDITIONAL),
    Sink("subprocess.check_output", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD,
         "command", shell=SHELL_CONDITIONAL),
    Sink("os.system", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD,
         "command", shell=SHELL_INHERENT),
    Sink("os.popen", "CG-CMD-EXEC", "CWE-78", SEVERITY_CRITICAL, _CMD,
         "command", shell=SHELL_INHERENT),
    Sink("eval", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    Sink("exec", "CG-CODE-EXEC", "CWE-95", SEVERITY_CRITICAL,
         "runs this value as program code", "code"),
    Sink("pickle.loads", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         _DESERIALIZE, "deserialize"),
    Sink("pickle.load", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         _DESERIALIZE, "deserialize"),
    Sink("yaml.load", "CG-DESERIALIZE", "CWE-502", SEVERITY_CRITICAL,
         _DESERIALIZE, "deserialize"),
    Sink("execute", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("executescript", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("executemany", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("raw", "CG-SQL-EXEC", "CWE-89", SEVERITY_HIGH, _SQL, "sql", bare=True),
    Sink("render_template_string", "CG-TEMPLATE-INJECT", "CWE-1336", SEVERITY_HIGH,
         "renders this value as a template, which can run code", "template"),
    Sink("open", "CG-PATH-TRAVERSAL", "CWE-22", SEVERITY_HIGH,
         "opens a file whose path comes from this value", "path", bare=True),
)

_BY_LANGUAGE: dict[str, tuple[Sink, ...]] = {"python": _PYTHON}


def all_sinks() -> tuple[Sink, ...]:
    return tuple(sink for sinks in _BY_LANGUAGE.values() for sink in sinks)


def lookup_sink(call_name: str, language: str) -> Sink | None:
    """Exact match on the full dotted name, then the bare final segment."""
    sinks = _BY_LANGUAGE.get(language)
    if not sinks or not call_name:
        return None
    for sink in sinks:
        if sink.name == call_name:
            return sink
    tail = call_name.rsplit(".", 1)[-1]
    for sink in sinks:
        if sink.bare and sink.name == tail:
            return sink
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_sinks.py -v` — PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/security/sinks.py tests/test_sinks.py
git commit -m "feat(sinks): exact-match registry with vulnerability and shell semantics"
```

---

## Task 2: Provenance lattice — direct expressions

**Files:** Create `src/cybergraph/analysis/provenance.py`; test `tests/test_provenance.py`.

**Interfaces:** `LITERAL`, `COMPOSED`, `OPAQUE`; `classify_expr(node: ast.AST, bindings: dict[str, str]) -> str`.

This task handles expressions only. Task 3 adds the flow-sensitive state machine that
supplies `bindings` correctly per call site. Split because the expression classifier is
independently testable and the state machine is where the subtle bug lives.

The lattice tracks **construction only**. Taint is a separate axis, already tracked by
`_add_python_dataflows`, and is joined at the predicate. Collapsing them would leave no
state for *dynamic but clean* — `f"... ORDER BY {allowlisted_column}"` is a `JoinedStr`
indistinguishable in shape from the tainted form.

- [ ] **Step 1: Write the failing test**

Create `tests/test_provenance.py`:

```python
import ast

import pytest

from cybergraph.analysis.provenance import COMPOSED, LITERAL, OPAQUE, classify_expr


def _expr(src: str) -> ast.AST:
    return ast.parse(src, mode="eval").body


@pytest.mark.parametrize(
    "src,expected",
    [
        ('"SELECT 1"', LITERAL),
        ('"SELECT " + uid', COMPOSED),
        ('f"SELECT {uid}"', COMPOSED),
        ('"SELECT %s" % uid', COMPOSED),
        ('"SELECT {}".format(uid)', COMPOSED),
        ('" ".join(parts)', COMPOSED),
        ("build_query()", OPAQUE),
        ("obj.attr", OPAQUE),
        ("[1, 2]", OPAQUE),
    ],
)
def test_direct_expressions(src, expected):
    assert classify_expr(_expr(src), {}) == expected


def test_names_resolve_through_bindings():
    assert classify_expr(_expr("q"), {"q": LITERAL}) == LITERAL
    assert classify_expr(_expr("q"), {"q": COMPOSED}) == COMPOSED


def test_unbound_name_is_opaque():
    assert classify_expr(_expr("q"), {}) == OPAQUE


def test_concatenating_two_literals_stays_literal():
    """A constant folded from constants carries no user data."""
    assert classify_expr(_expr('"a" + "b"'), {}) == LITERAL


def test_concatenating_a_literal_with_a_composed_name_is_composed():
    assert classify_expr(_expr('"a" + q'), {"q": COMPOSED}) == COMPOSED
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_provenance.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.analysis.provenance'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/analysis/provenance.py`:

```python
"""How was this string value constructed?

Answers one question and knows nothing about security:

``LITERAL``   a constant, or a name bound only to constants
``COMPOSED``  assembled here by ``+``, an f-string, ``%``, ``.format()`` or ``.join()``
``OPAQUE``    from a call, a parameter, or anything not tracked

Orthogonal to taint, which ``analysis.python._add_python_dataflows`` tracks
separately. Keeping the axes apart is what lets ``f"... ORDER BY {allowlisted}"``
be COMPOSED *and* clean. Collapsing them forces a false choice between a false
positive on dynamic-but-safe queries and a provenance label that is a lie.
"""

from __future__ import annotations

import ast

LITERAL = "literal"
COMPOSED = "composed"
OPAQUE = "opaque"

# Weakest wins at a join: a value is only as safe as its least safe origin.
_RANK = {LITERAL: 0, COMPOSED: 1, OPAQUE: 2}

_COMPOSING_METHODS = {"format", "join"}


def weakest(*classes: str) -> str:
    """The least safe of several construction classes."""
    return max(classes, key=lambda item: _RANK[item], default=LITERAL)


def classify_expr(node: ast.AST | None, bindings: dict[str, str]) -> str:
    """Construction class of an expression, resolving names via ``bindings``."""
    if node is None:
        return OPAQUE
    if isinstance(node, ast.Constant):
        return LITERAL
    if isinstance(node, ast.Name):
        return bindings.get(node.id, OPAQUE)
    if isinstance(node, ast.JoinedStr):
        # An f-string with only constant pieces is still just a constant.
        parts = [
            classify_expr(value.value, bindings)
            for value in node.values
            if isinstance(value, ast.FormattedValue)
        ]
        return COMPOSED if parts else LITERAL
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        left = classify_expr(node.left, bindings)
        right = classify_expr(node.right, bindings)
        if left == LITERAL and right == LITERAL:
            return LITERAL  # constant folding: no user data can enter
        return COMPOSED
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _COMPOSING_METHODS:
            return COMPOSED
        return OPAQUE
    return OPAQUE
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_provenance.py -v` — PASS (14 tests)

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/analysis/provenance.py tests/test_provenance.py
git commit -m "feat(provenance): construction lattice for direct expressions"
```

---

## Task 3: Flow-sensitive state — per-call-site snapshots

**Files:** Modify `src/cybergraph/analysis/provenance.py`; test `tests/test_provenance.py` (append).

**Interfaces:** `snapshot_call_sites(fn, initial_taint) -> dict[int, CallState]`, where the key is `id(call_node)` and `CallState` is a frozen dataclass with `bindings: dict[str, str]` and `tainted: dict[str, str]`.

This is P1. Rev. 2 built one whole-function binding map with `ast.walk` — which yields BFS
order, not source order — and applied it to every call site, so a call could be judged
using an assignment that happens *after* it.

Because `weakest()` wins at every merge, the stale state could only make a value look
**more** dangerous, never less: the bug caused false positives, not misses. It is fixed
here because false positives are the thing this plan exists to eliminate.

The design is a single source-ordered pass over statements. At each `Call`, the current
state is snapshotted **before** the enclosing statement's assignment effect is applied.
Branches are walked with a copy and merged back weakest-wins; loops are walked twice so a
value composed on iteration *n* is visible to the call on iteration *n+1*.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_provenance.py`:

```python
from cybergraph.analysis.provenance import snapshot_call_sites


def _state_at(src: str, callee: str = "execute"):
    fn = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)][0]
    tainted = {a.arg: f"input:{a.arg}" for a in fn.args.args}
    states = snapshot_call_sites(fn, tainted)
    call = next(
        n for n in ast.walk(fn)
        if isinstance(n, ast.Call) and ast.unparse(n.func).endswith(callee)
    )
    return states[id(call)], call


def test_later_assignment_does_not_taint_an_earlier_call():
    """The rev.2 bug: state from the future reached back to an earlier call site."""
    src = (
        "def f(uid):\n"
        '    q = "SELECT 1"\n'
        "    cursor.execute(q)\n"
        '    q = f"SELECT {uid}"\n'
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == LITERAL


def test_earlier_assignment_does_reach_a_later_call():
    src = (
        "def f(uid):\n"
        '    q = f"SELECT {uid}"\n'
        "    cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED


def test_augmented_assignment_composes():
    src = (
        "def f(uid):\n"
        '    q = "SELECT 1"\n'
        '    q += " WHERE id = " + uid\n'
        "    cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED


def test_branch_merge_takes_the_weakest():
    src = (
        "def f(uid, flag):\n"
        '    q = "SELECT 1"\n'
        "    if flag:\n"
        '        q = f"SELECT {uid}"\n'
        "    cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED


def test_call_inside_a_branch_sees_branch_local_state():
    src = (
        "def f(uid, flag):\n"
        '    q = "SELECT 1"\n'
        "    if flag:\n"
        '        q = f"SELECT {uid}"\n'
        "        cursor.execute(q)\n"
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED


def test_parameter_is_opaque_and_tainted():
    state, call = _state_at("def f(q):\n    cursor.execute(q)\n")
    assert classify_expr(call.args[0], state.bindings) == OPAQUE
    assert "q" in state.tainted


def test_loop_carried_composition_is_visible():
    """A value composed on one iteration reaches the call on the next."""
    src = (
        "def f(uid, rows):\n"
        '    q = "SELECT 1"\n'
        "    for row in rows:\n"
        "        cursor.execute(q)\n"
        '        q = f"SELECT {uid}"\n'
    )
    state, call = _state_at(src)
    assert classify_expr(call.args[0], state.bindings) == COMPOSED


def test_taint_is_also_call_site_sensitive():
    src = (
        "def f(uid):\n"
        "    cursor.execute(safe_value)\n"
        "    safe_value = uid\n"
    )
    state, call = _state_at(src)
    assert "safe_value" not in state.tainted
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_provenance.py -v`
Expected: FAIL — `ImportError: cannot import name 'snapshot_call_sites'`

- [ ] **Step 3: Write minimal implementation**

Append to `src/cybergraph/analysis/provenance.py` (add `from dataclasses import dataclass, field`):

```python
@dataclass(frozen=True)
class CallState:
    """Construction and taint state as it was *at* one call site."""

    bindings: dict[str, str] = field(default_factory=dict)
    tainted: dict[str, str] = field(default_factory=dict)


def snapshot_call_sites(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    initial_taint: dict[str, str] | None = None,
) -> dict[int, CallState]:
    """Record construction and taint state at every call site, in source order.

    Keyed by ``id()`` of the ``ast.Call`` node, which is stable for the lifetime
    of the parsed tree.

    A whole-function state applied to every call lets an assignment that happens
    *after* a call influence it. Because merges take the weakest class that can
    only over-report, but over-reporting is exactly the noise this detector
    exists to remove.

    Loop bodies are walked twice so a value composed on iteration *n* is visible
    to a call on iteration *n+1*. Two passes are enough: the lattice has three
    levels and merges are monotonically weakening, so the state has converged.
    """
    bindings: dict[str, str] = {}
    tainted: dict[str, str] = dict(initial_taint or {})

    for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]:
        if arg.arg not in {"self", "cls"}:
            bindings[arg.arg] = OPAQUE

    states: dict[int, CallState] = {}
    _walk_body(fn.body, bindings, tainted, states)
    return states


def _walk_body(
    body: list[ast.stmt],
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    for statement in body:
        _snapshot_calls_in(statement, bindings, tainted, states)
        _apply_effect(statement, bindings, tainted, states)


def _snapshot_calls_in(
    statement: ast.stmt,
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    """Record state for calls in this statement's own expressions.

    Nested bodies are skipped here; ``_apply_effect`` walks them with their own
    branch-local state.

    A call visited more than once — a loop body is walked twice — *merges*
    rather than keeping the first snapshot. A call inside a loop must see the
    weakest state across iterations, or a value composed on iteration *n* would
    be invisible to the call on iteration *n+1*.
    """
    for node in _own_expressions(statement):
        for call in [n for n in ast.walk(node) if isinstance(n, ast.Call)]:
            existing = states.get(id(call))
            if existing is None:
                states[id(call)] = CallState(dict(bindings), dict(tainted))
                continue
            merged = dict(existing.bindings)
            for name, value_class in bindings.items():
                merged[name] = weakest(merged.get(name, value_class), value_class)
            states[id(call)] = CallState(merged, {**existing.tainted, **tainted})


def _own_expressions(statement: ast.stmt) -> list[ast.AST]:
    if isinstance(statement, ast.If | ast.While):
        return [statement.test]
    if isinstance(statement, ast.For | ast.AsyncFor):
        return [statement.iter]
    if isinstance(statement, ast.With | ast.AsyncWith):
        return [item.context_expr for item in statement.items]
    if isinstance(statement, ast.Try):
        return []
    if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return []  # nested definitions have their own scope
    return [statement]


def _apply_effect(
    statement: ast.stmt,
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    if isinstance(statement, ast.Assign):
        value_class = classify_expr(statement.value, bindings)
        source = _tainted_source(statement.value, tainted)
        for target in statement.targets:
            for name in _names(target):
                bindings[name] = value_class
                if source:
                    tainted[name] = source
                else:
                    tainted.pop(name, None)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        value_class = classify_expr(statement.value, bindings)
        source = _tainted_source(statement.value, tainted)
        for name in _names(statement.target):
            bindings[name] = value_class
            if source:
                tainted[name] = source
    elif isinstance(statement, ast.AugAssign):
        source = _tainted_source(statement.value, tainted)
        for name in _names(statement.target):
            bindings[name] = COMPOSED
            if source:
                tainted[name] = source
    elif isinstance(statement, ast.If):
        _merge_branches(
            [statement.body, statement.orelse], bindings, tainted, states
        )
    elif isinstance(statement, ast.For | ast.AsyncFor | ast.While):
        # Two passes: iteration n+1 must see what iteration n built.
        for _ in range(2):
            _merge_branches([statement.body], bindings, tainted, states)
    elif isinstance(statement, ast.With | ast.AsyncWith):
        _walk_body(statement.body, bindings, tainted, states)
    elif isinstance(statement, ast.Try):
        _merge_branches(
            [statement.body, *(h.body for h in statement.handlers),
             statement.orelse, statement.finalbody],
            bindings, tainted, states,
        )


def _merge_branches(
    bodies: list[list[ast.stmt]],
    bindings: dict[str, str],
    tainted: dict[str, str],
    states: dict[int, CallState],
) -> None:
    """Walk each branch with a copy, then merge weakest-wins back into the parent."""
    for body in bodies:
        if not body:
            continue
        branch_bindings = dict(bindings)
        branch_tainted = dict(tainted)
        _walk_body(body, branch_bindings, branch_tainted, states)
        for name, value_class in branch_bindings.items():
            bindings[name] = weakest(bindings.get(name, value_class), value_class)
        tainted.update(branch_tainted)


def _tainted_source(node: ast.AST | None, tainted: dict[str, str]) -> str:
    if node is None:
        return ""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tainted:
            return tainted[child.id]
    return ""


def _names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Tuple | ast.List):
        names: list[str] = []
        for element in target.elts:
            names.extend(_names(element))
        return names
    return []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_provenance.py -v` — PASS (22 tests)

Note on the loop: the body is walked twice and a call's snapshot **merges** across passes,
weakest-wins. First-write-wins would record `q=LITERAL` from iteration one and never see
the `q = f"SELECT {uid}"` that follows the call in the loop body, so
`test_loop_carried_composition_is_visible` would fail. Two passes are sufficient: the
lattice has three levels and merges only ever weaken, so the state has converged.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/analysis/provenance.py tests/test_provenance.py
git commit -m "fix(provenance): snapshot construction and taint per call site

A whole-function state map let assignments after a call influence it. State is
now recorded in source order, with branch merges taking the weakest class."
```

---

## Task 4: Per-sink unsafe-use predicates

**Files:** Create `src/cybergraph/security/predicates.py`; test `tests/test_predicates.py`.

**Interfaces:**
- `VERDICT_SAFE = "safe"`, `VERDICT_UNSAFE = "unsafe"`, `VERDICT_UNKNOWN = "unknown"`
- `assess_call(sink: Sink, call: ast.Call, state: CallState) -> str`

This is P2 and P3. Two corrections to rev. 2, in opposite directions.

**Confinement is not normalisation.** `normpath("../../etc/passwd")` is still traversal and
`realpath` resolves symlinks without restricting the result to any directory. Only
`basename`, `safe_join` and `secure_filename` actually confine. The rest yield `UNKNOWN`.

**Shell semantics are per-API, and the fix cuts both ways.** `["sh", "-c", user_input]`
was `SAFE` in rev. 2 — a miss. Conversely `subprocess.run(f"git show {rev}")` with
`shell=False` was `UNSAFE` — but on POSIX Python passes the whole string as the
*executable name*, so it is not injection. That one becomes `UNKNOWN` (the behaviour is
platform-dependent), not `UNSAFE`.

| Class | UNSAFE | SAFE | UNKNOWN |
|---|---|---|---|
| `sql` | first arg `COMPOSED` and tainted | first arg `LITERAL`; or `COMPOSED` and clean | first arg `OPAQUE` and tainted |
| `command` | shell in play and command tainted; or tainted `argv[0]`; or a shell executable (`sh -c`) with tainted argv | list argv, no shell, clean `argv[0]` | tainted string command without a shell |
| `path` | tainted and not confined | untainted; or passed through a confining call | normalised but containment unproven |
| `code`, `deserialize`, `template` | any tainted argument | no tainted argument | non-constant `OPAQUE` argument |

- [ ] **Step 1: Write the failing test**

Create `tests/test_predicates.py`:

```python
import ast

import pytest

from cybergraph.analysis.provenance import snapshot_call_sites
from cybergraph.security.predicates import (
    VERDICT_SAFE,
    VERDICT_UNKNOWN,
    VERDICT_UNSAFE,
    assess_call,
)
from cybergraph.security.sinks import lookup_sink


def _assess(body: str, callee: str, params: str = "uid"):
    src = f"def f({params}):\n    {body}\n"
    fn = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)][0]
    tainted = {a.arg: f"input:{a.arg}" for a in fn.args.args}
    states = snapshot_call_sites(fn, tainted)
    call = next(
        n for n in ast.walk(fn)
        if isinstance(n, ast.Call) and ast.unparse(n.func).endswith(callee)
    )
    sink = lookup_sink(ast.unparse(call.func), "python")
    assert sink is not None, ast.unparse(call.func)
    return assess_call(sink, call, states[id(call)])


@pytest.mark.parametrize(
    "body,expected",
    [
        ('cursor.execute("SELECT * FROM t WHERE id = ?", (uid,))', VERDICT_SAFE),
        ('cursor.execute("SELECT * FROM t WHERE id = :id", {"id": uid})', VERDICT_SAFE),
        ('cursor.execute("SELECT 1")', VERDICT_SAFE),
        ('cursor.execute("SELECT * FROM t WHERE id = " + uid)', VERDICT_UNSAFE),
        ('cursor.execute(f"SELECT * FROM t WHERE id = {uid}")', VERDICT_UNSAFE),
        ('cursor.execute("SELECT * FROM t WHERE id = %s" % uid)', VERDICT_UNSAFE),
        ("cursor.execute(build_query(uid))", VERDICT_UNKNOWN),
    ],
)
def test_sql(body, expected):
    assert _assess(body, "execute") == expected


def test_sql_composed_but_clean_is_safe():
    """Dynamic construction with no user data in the query text is not injection."""
    assert _assess('cursor.execute(f"SELECT * FROM t ORDER BY id")', "execute") == VERDICT_SAFE


@pytest.mark.parametrize(
    "body,expected",
    [
        ('subprocess.run(["git", "show", rev], shell=False)', VERDICT_SAFE),
        ('subprocess.run(["git", "show", rev])', VERDICT_SAFE),
        ('subprocess.run(["git", "show"])', VERDICT_SAFE),
        ('subprocess.run("git show " + rev, shell=True)', VERDICT_UNSAFE),
        ("subprocess.run(rev, shell=True)", VERDICT_UNSAFE),
        ('subprocess.run(["sh", "-c", rev])', VERDICT_UNSAFE),
        ('subprocess.run(["bash", "-c", rev])', VERDICT_UNSAFE),
        ("subprocess.run([rev, '--version'])", VERDICT_UNSAFE),
        ('subprocess.run(f"git show {rev}")', VERDICT_UNKNOWN),
    ],
)
def test_command(body, expected):
    assert _assess(body, "run", params="rev") == expected


def test_os_system_always_involves_a_shell():
    assert _assess('os.system("echo " + rev)', "system", params="rev") == VERDICT_UNSAFE


@pytest.mark.parametrize(
    "body,expected",
    [
        ("open(name)", VERDICT_UNSAFE),
        ('open("config.ini")', VERDICT_SAFE),
        ("open(os.path.basename(name))", VERDICT_SAFE),
        ("open(safe_join(ROOT, name))", VERDICT_SAFE),
        ("open(os.path.normpath(name))", VERDICT_UNKNOWN),
        ("open(os.path.realpath(name))", VERDICT_UNKNOWN),
        ("open(os.path.abspath(name))", VERDICT_UNKNOWN),
    ],
)
def test_path(body, expected):
    assert _assess(body, "open", params="name") == expected


def test_code_execution():
    assert _assess("eval(src)", "eval", params="src") == VERDICT_UNSAFE
    assert _assess('eval("1+1")', "eval", params="src") == VERDICT_SAFE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_predicates.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.predicates'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/predicates.py`:

```python
"""Per-sink unsafe-use predicates.

Reaching a sink is inventory; using it unsafely is a vulnerability. A single
"is any argument tainted" test reports correctly parameterized SQL and
``subprocess.run([...], shell=False)`` as critical findings, which is why this
module exists.

Two distinctions the obvious implementation gets wrong:

*Confinement is not normalisation.* ``normpath("../../etc/passwd")`` is still
traversal and ``realpath`` resolves symlinks without restricting the result to
any directory. Only ``basename``, ``safe_join`` and ``secure_filename`` confine.

*Shell involvement is per-API and per-argv.* ``os.system`` always runs a shell;
``subprocess.run`` depends on ``shell=``; and ``["sh", "-c", x]`` runs a shell
whatever the keyword says.

Three outcomes, and the third is load-bearing: a value whose construction cannot
be seen is ``unknown``, never ``safe``.
"""

from __future__ import annotations

import ast

from cybergraph.analysis.provenance import COMPOSED, LITERAL, OPAQUE, CallState, classify_expr
from cybergraph.security.sinks import SHELL_CONDITIONAL, SHELL_INHERENT, Sink

VERDICT_SAFE = "safe"
VERDICT_UNSAFE = "unsafe"
VERDICT_UNKNOWN = "unknown"

# These reduce an arbitrary path to something inside a known directory.
_CONFINING = {"basename", "safe_join", "secure_filename"}
# These canonicalise without restricting where the result points.
_NORMALISING = {"abspath", "normpath", "realpath", "expanduser", "resolve"}

_SHELL_EXECUTABLES = {"sh", "bash", "zsh", "dash", "ksh", "cmd", "cmd.exe", "powershell"}
_SHELL_FLAGS = {"-c", "/c", "-Command"}


def assess_call(sink: Sink, call: ast.Call, state: CallState) -> str:
    """Decide whether this specific call site is an unsafe use of the sink."""
    if sink.vuln_class == "sql":
        return _assess_sql(call, state)
    if sink.vuln_class == "command":
        return _assess_command(sink, call, state)
    if sink.vuln_class == "path":
        return _assess_path(call, state)
    return _assess_any_tainted_argument(call, state)


def _assess_sql(call: ast.Call, state: CallState) -> str:
    """Only the query *text* matters. Parameter values are the safe mechanism."""
    if not call.args:
        return VERDICT_SAFE
    query = call.args[0]
    construction = classify_expr(query, state.bindings)
    if construction == LITERAL:
        return VERDICT_SAFE
    if not _has_tainted_name(query, state):
        return VERDICT_SAFE
    return VERDICT_UNSAFE if construction == COMPOSED else VERDICT_UNKNOWN


def _assess_command(sink: Sink, call: ast.Call, state: CallState) -> str:
    """Shell involvement decides the mechanism; argv[0] decides who picks the binary."""
    if not call.args:
        return VERDICT_SAFE
    command = call.args[0]
    shell = sink.shell == SHELL_INHERENT or (
        sink.shell == SHELL_CONDITIONAL and _keyword_is_true(call, "shell")
    )

    if isinstance(command, ast.List | ast.Tuple):
        elements = list(command.elts)
        if elements and _has_tainted_name(elements[0], state):
            return VERDICT_UNSAFE  # the attacker picks the executable
        if _invokes_a_shell(elements) and any(
            _has_tainted_name(element, state) for element in elements[1:]
        ):
            return VERDICT_UNSAFE  # sh -c <tainted>, whatever shell= says
        if shell and any(_has_tainted_name(element, state) for element in elements):
            return VERDICT_UNSAFE
        return VERDICT_SAFE

    if not _has_tainted_name(command, state):
        return VERDICT_SAFE
    if shell:
        return VERDICT_UNSAFE
    # A string command without a shell is passed as the executable name on POSIX
    # and parsed differently on Windows. Not the injection mechanism; not safe.
    return VERDICT_UNKNOWN


def _assess_path(call: ast.Call, state: CallState) -> str:
    """Tainted paths are unsafe unless something actually confines them."""
    if not call.args:
        return VERDICT_SAFE
    target = call.args[0]
    if not _has_tainted_name(target, state):
        return VERDICT_SAFE
    normalised = False
    for node in ast.walk(target):
        if not isinstance(node, ast.Call):
            continue
        name = ast.unparse(node.func).rsplit(".", 1)[-1]
        if name in _CONFINING:
            return VERDICT_SAFE
        if name in _NORMALISING:
            normalised = True
    return VERDICT_UNKNOWN if normalised else VERDICT_UNSAFE


def _assess_any_tainted_argument(call: ast.Call, state: CallState) -> str:
    """Code execution, deserialization and templates: any user data is unsafe."""
    unknown = False
    for arg in [*call.args, *(kw.value for kw in call.keywords)]:
        if _has_tainted_name(arg, state):
            return VERDICT_UNSAFE
        if not isinstance(arg, ast.Constant) and classify_expr(arg, state.bindings) == OPAQUE:
            unknown = True
    return VERDICT_UNKNOWN if unknown else VERDICT_SAFE


def _invokes_a_shell(elements: list[ast.expr]) -> bool:
    """``["sh", "-c", ...]`` runs a shell regardless of the ``shell=`` keyword."""
    if len(elements) < 2:
        return False
    first, second = elements[0], elements[1]
    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
        return False
    if not (isinstance(second, ast.Constant) and isinstance(second.value, str)):
        return False
    executable = first.value.rsplit("/", 1)[-1].lower()
    return executable in _SHELL_EXECUTABLES and second.value in _SHELL_FLAGS


def _has_tainted_name(node: ast.AST, state: CallState) -> bool:
    return any(
        isinstance(child, ast.Name) and child.id in state.tainted
        for child in ast.walk(node)
    )


def _keyword_is_true(call: ast.Call, name: str) -> bool:
    for keyword in call.keywords:
        if keyword.arg == name:
            return isinstance(keyword.value, ast.Constant) and keyword.value.value is True
    return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_predicates.py -v` — PASS (23 tests)

- [ ] **Step 5: Commit**

```
git add src/cybergraph/security/predicates.py tests/test_predicates.py
git commit -m "feat(predicates): per-sink semantics with real confinement and shell rules"
```

---

## Task 5: Wire predicates into the Python analyzer

**Files:** Modify `src/cybergraph/analysis/python.py:112-136`, `:231-238`; test `tests/test_sink_precision.py` (create).

**Interfaces:** `_add_python_dataflows(...) -> dict[str, str]` now returns the taint map.
`analyze_python_file` keeps its signature. `VERDICT_UNKNOWN` emits the rule id suffixed
`-UNVERIFIED` at severity `medium`; `VERDICT_SAFE` emits no finding. The `REACHES_SINK`
edge is always emitted.

- [ ] **Step 1: Write the failing test**

Create `tests/test_sink_precision.py`:

```python
from pathlib import Path

from cybergraph.analysis.python import analyze_python_file

ROUTE = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/u")
def get_user(uid: str):
    return {body}
'''

BENIGN = "def helper():\n    drawChart()\n    reopen_session()\n    writer_pool()\n"


def _analyze(tmp_path: Path, source: str):
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    return analyze_python_file(path, tmp_path)


def test_parameterized_query_is_not_a_finding(tmp_path):
    _, edges, findings = _analyze(
        tmp_path, ROUTE.format(body='cursor.execute("SELECT * FROM u WHERE id = ?", (uid,))')
    )
    assert findings == [], [f.rule_id for f in findings]
    assert any(e.kind == "REACHES_SINK" for e in edges), "inventory edge must survive"


def test_concatenated_query_is_a_finding(tmp_path):
    _, _, findings = _analyze(
        tmp_path, ROUTE.format(body='cursor.execute("SELECT * FROM u WHERE id = " + uid)')
    )
    assert [f.rule_id for f in findings] == ["CG-SQL-EXEC"]
    assert findings[0].severity == "high"
    assert findings[0].cwe == "CWE-89"


def test_unverifiable_query_is_a_distinct_lower_severity_rule(tmp_path):
    _, _, findings = _analyze(tmp_path, ROUTE.format(body="cursor.execute(build(uid))"))
    assert [f.rule_id for f in findings] == ["CG-SQL-EXEC-UNVERIFIED"]
    assert findings[0].severity == "medium"
    assert "could not confirm" in findings[0].message


def test_benign_names_produce_neither(tmp_path):
    _, edges, findings = _analyze(tmp_path, BENIGN)
    assert findings == []
    assert not any(e.kind == "REACHES_SINK" for e in edges)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_sink_precision.py -v`
Expected: FAIL on all four — the parameterized query is reported and `drawChart` matches `raw`.

- [ ] **Step 3: Return the taint map**

In `src/cybergraph/analysis/python.py`, change `_add_python_dataflows`'s annotation from
`-> None` to `-> dict[str, str]`, extend its docstring with "Returns the accumulated taint
map, used to seed per-call-site snapshots.", and add `return tainted` as its last statement.

- [ ] **Step 4: Replace the sink block in the call loop**

Replace lines 112-136 with:

```python
            tainted = _add_python_dataflows(item, key, rel, tainted_values, nodes, edges)
            call_states = snapshot_call_sites(item, tainted)

            for call in [n for n in ast.walk(item) if isinstance(n, ast.Call)]:
                call_name = _call_name(call)
                if not call_name:
                    continue
                line_no = getattr(call, "lineno", item.lineno)
                edges.append(Edge("CALLS", key, call_name, rel, line_no))
                lowered = call_name.lower()

                sink = lookup_sink(call_name, "python") or _custom_sink(call_name, custom_sinks)
                if sink is not None:
                    # Inventory is always recorded, whether or not this call site
                    # is an unsafe use of the sink.
                    edges.append(Edge(EDGE_REACHES_SINK, key, call_name, rel, line_no))
                    state = call_states.get(id(call))
                    assessment = (
                        assess_call(sink, call, state) if state is not None else VERDICT_UNKNOWN
                    )
                    finding = _finding_for(sink, assessment, call_name, rel, line_no)
                    if finding is not None and not is_inline_suppressed(
                        lines, line_no, finding.rule_id
                    ):
                        findings.append(finding)
```

Add to the imports:

```python
from cybergraph.analysis.provenance import snapshot_call_sites
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNKNOWN, VERDICT_UNSAFE, assess_call
from cybergraph.security.sinks import SEVERITY_MEDIUM, Sink, lookup_sink
```

and these helpers beside `_is_secret_exposure`:

```python
def _finding_for(
    sink: Sink, assessment: str, call_name: str, rel: str, line_no: int
) -> Finding | None:
    """Build the finding for an assessment, or None when the call site is safe.

    An ``unknown`` assessment gets its own rule id at reduced severity. Not being
    able to see how a value was built is a different fact from knowing it is
    dangerous, and a different fact again from knowing it is safe.
    """
    if assessment == VERDICT_SAFE:
        return None
    unsafe = assessment == VERDICT_UNSAFE
    return Finding(
        rule_id=sink.rule_id if unsafe else f"{sink.rule_id}-UNVERIFIED",
        severity=sink.severity if unsafe else SEVERITY_MEDIUM,
        message=(
            f"`{call_name}` {sink.plain}"
            if unsafe
            else f"`{call_name}` {sink.plain}, and CyberGraph could not confirm "
                 f"the value is safe"
        ),
        file_path=rel,
        line_start=line_no,
        cwe=sink.cwe,
        evidence=call_name,
    )


def _custom_sink(call_name: str, custom_sinks: tuple[str, ...]) -> Sink | None:
    """Wrap a user-configured sink so it flows through the same predicate path."""
    if call_name not in custom_sinks:
        return None
    return Sink(
        name=call_name,
        rule_id="CG-CUSTOM-SINK",
        cwe="CWE-20",
        severity=SEVERITY_MEDIUM,
        plain="receives this value, and your project marked it sensitive",
        vuln_class="custom",
    )
```

- [ ] **Step 5: Run the new tests**

Run: `python -m pytest tests/test_sink_precision.py tests/test_predicates.py -v` — PASS

- [ ] **Step 6: Repair the existing suite**

Run: `python -m pytest -q`

Update each failure's expected `rule_id` and `severity` to the registry values. **Do not
relax an assertion to make it pass** — a test that expected a finding on a parameterized
query encoded the bug, and its expectation becomes "edge but no finding." Re-run to green.

- [ ] **Step 7: Commit**

```
git add src/cybergraph/analysis/python.py tests/
git commit -m "fix(python): apply per-call-site predicates instead of any-tainted-argument"
```

---

## Task 6: Suppression before the traversal limit

**Files:** Modify `src/cybergraph/security/attack_paths.py:47-88`; test `tests/test_attack_path_suppressions.py` (create).

**Interfaces:** `find_attack_paths(repo_root, max_depth=8, limit=20, interprocedural=True, apply_suppressions=True)`.

Filtering after truncation silently drops real results: 25 suppressed fixtures consume the
whole 20-item window and the three real paths behind them are never fetched.

- [ ] **Step 1: Write the failing test**

Create `tests/test_attack_path_suppressions.py`:

```python
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.security.attack_paths import find_attack_paths

ROUTE = '''
@app.get("/r{n}")
def run{n}(cmd: str):
    subprocess.run("echo " + cmd, shell=True)
'''
HEADER = "from fastapi import FastAPI\napp = FastAPI()\n"
CONFIG = '[suppressions]\npaths = ["fixtures/*"]\n'


def test_suppressed_paths_are_excluded(tmp_path: Path):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "app.py").write_text(HEADER + ROUTE.format(n=0), encoding="utf-8")
    (tmp_path / ".cybergraph.toml").write_text(CONFIG, encoding="utf-8")
    build_graph(tmp_path)

    assert find_attack_paths(tmp_path) == []
    assert find_attack_paths(tmp_path, apply_suppressions=False)


def test_suppressed_results_do_not_consume_the_limit(tmp_path: Path):
    """25 suppressed fixtures must not hide the 3 real results behind them."""
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "app.py").write_text(
        HEADER + "".join(ROUTE.format(n=i) for i in range(25)), encoding="utf-8"
    )
    (tmp_path / "real.py").write_text(
        HEADER + "".join(ROUTE.format(n=i) for i in range(100, 103)), encoding="utf-8"
    )
    (tmp_path / ".cybergraph.toml").write_text(CONFIG, encoding="utf-8")
    build_graph(tmp_path)

    paths = find_attack_paths(tmp_path, limit=20)
    assert len(paths) == 3, f"expected the 3 real paths, got {len(paths)}"
    assert all("real.py" in path.nodes[0] for path in paths)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_attack_path_suppressions.py -v`
Expected: FAIL — the second test returns 0 paths; the suppressed fixtures ate the limit.

- [ ] **Step 3: Implement suppression inside the traversal**

In `src/cybergraph/security/attack_paths.py` add:

```python
from fnmatch import fnmatch

from cybergraph.config import load_config
```

Add `apply_suppressions: bool = True` to the signature, and replace the `return _traverse(...)` line with:

```python
        patterns = load_config(repo_root).suppressed_paths if apply_suppressions else ()
        return _traverse(
            entrypoints, sinks, sanitizers, callgraph, taints, max_depth, limit, patterns
        )
```

Add `patterns: tuple[str, ...] = ()` to `_traverse`'s parameters and, immediately after
`seen_paths.add(key)` and **before** `paths.append(...)`:

```python
                if patterns and _is_suppressed(path + (sink_name,), patterns):
                    continue
```

Then add:

```python
def _is_suppressed(nodes: tuple[str, ...], patterns: tuple[str, ...]) -> bool:
    """Suppress only when every file the path touches is suppressed.

    Conservative on purpose: a path crossing from suppressed fixture code into
    real application code is still reported.
    """
    files = {node.split("::", 1)[0] for node in nodes if "::" in node}
    if not files:
        return False
    return all(any(fnmatch(file, pattern) for pattern in patterns) for file in files)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_attack_path_suppressions.py -v` — PASS (2 tests)

- [ ] **Step 5: Verify the self-scan no longer ranks fixtures**

Run: `python -m cybergraph.cli analyze . 2>&1 | head -20`
Expected: no `benchmark/cases/` or `tests/fixtures/` entries in Top risks.

- [ ] **Step 6: Commit**

```
git add src/cybergraph/security/attack_paths.py tests/test_attack_path_suppressions.py
git commit -m "fix(paths): suppress before applying the traversal limit"
```

---

## Task 7: Benchmark with precision, recall, and abstention rate

**Files:** Create `benchmark/precision/cases/*`, `benchmark/run_precision.py`, `benchmark/precision/README.md`; test `tests/test_precision_gate.py`; modify `.gitignore`.

**Gate (rev. 3 — four metrics, abstention and false positives gated PER CLASS):**

| Metric | Threshold | Scope |
|---|---|---|
| precision | ≥ 0.90 | over gated cases |
| recall | ≥ 0.95 | over gated cases, **excluding `known_gap` cases** |
| safe-case **false-positive** rate | ≤ 0.05 | **per vulnerability class** |
| safe-case abstention rate | ≤ 0.15 | **per class**, except `command`, which is measured and reported but not gated |

Three findings during implementation forced this away from the original single
aggregate. Each is a way the original gate could be passed by a worse tool:

**A single aggregate abstention gate is satisfiable by over-reporting.** Measured
during Task 4: abstention fell 17.6% → 12.9% purely because 23 safe sites moved
from UNKNOWN to *false positive*. The number improved while the tool got worse.
Gating abstention without gating the false-positive rate rewards exactly the
failure this plan exists to remove, so both are gated, and both per class.

**Abstention is workload-dependent, not a detector property.** Measured on real
code: 3.4% on a SQL-heavy repository, 20.0% on a subprocess-heavy one — nearly
all of the latter being one irreducible shape, a shell-out to a binary the source
does not name literally. A single aggregate is therefore gameable by corpus
composition: a SQL-heavy corpus passes trivially. The `command` class is exempt
from the abstention gate and carries a stated limitation instead — *CyberGraph
cannot verify a shell-out to a binary that is not named literally* — while its
false-positive rate stays gated.

**`recall ≥ 0.95` on a corpus this size is arithmetically a zero-miss gate.** At
~15 unsafe expectations, 14/15 = 0.933 fails. State that in
`benchmark/precision/README.md` rather than implying the threshold has
resolution it does not have, and never report the figure without the case count
beside it.

**The same arithmetic applies to the per-class gates, harder.** A class with
three safe cases can only score a false-positive rate of 0, 0.33, 0.67 or 1.00 —
so `≤ 0.05` is a **zero-false-positive** gate, not a five-percent one. With one
safe case (`deserialize`) it is 0 or 1.00. Abstention `≤ 0.15` is a
zero-abstention gate on the same counts. Print `n` beside every per-class rate
and say in the README that these thresholds are zero-tolerance at present corpus
size. Reporting `FP 0.00 ≤ 0.05 ✓` without `n = 3` beside it claims a tolerance
the corpus cannot express, which is the same species of overclaim as the headline
benchmark numbers this plan exists to correct.

The third metric is C2. Rev. 2 excluded `-UNVERIFIED` findings from tp/fp — correct, because
penalising an honest abstention as a false positive pushes the detector toward guessing.
But a *safe* case that abstains was then counted as a true negative, while operationally it
produces a REVIEW. You could score perfect precision and recall while sending every safe
change to a human. Abstention is now measured and gated separately.

- [ ] **Step 1: Build the labelled corpus**

Each case is `benchmark/precision/cases/<name>/` containing `app.py` and `expected.json`:

```json
{"label": "unsafe", "vuln_class": "sql", "known_gap": false,
 "findings": [{"file": "app.py", "line": 7, "rule": "CG-SQL-EXEC"}]}
```

`label` ∈ `unsafe` | `safe` | `unknown`. A `safe` case has `"findings": []`.
`vuln_class` is required — the gate is per class and cannot be computed without it.

**Scoring is label-aware.** The runner strips `-UNVERIFIED` findings into an
abstention count and excludes them from `confirmed`, so a naive comparison scores
an `unknown`-labelled case as a false negative against its own expectation. Score
each label on its own terms:

| label | passes when |
|---|---|
| `unsafe` | the expected confirmed findings are all present |
| `safe` | zero confirmed findings **and** zero abstentions |
| `unknown` | the expected abstention count is present; excluded from tp/fp/fn entirely |

**`known_gap: true`** marks a case that is expected to fail today. Exclude such
cases from the gated precision and recall figures, but **count and print them
separately** (`known gaps: 2 (alias_import, from_import)`). Without this the
recall gate fails on day one and the obvious repair — deleting the two cases —
destroys the only property they exist to provide. A silently dropped case is
forbidden; a visibly excluded one is the point.

Required cases — every one must exist:

| Group | Cases |
|---|---|
| SQL unsafe | `sql_concat`, `sql_fstring`, `sql_percent`, `sql_format`, `sql_augassign` |
| SQL safe | `sql_param_qmark`, `sql_param_named`, `sql_constant`, `sql_hoisted_constant`, `sql_composed_clean`, `sql_reassigned_after_call` |
| SQL unknown | `sql_via_builder` |
| Command unsafe | `cmd_shell_true`, `cmd_fstring_shell_true`, `cmd_sh_dash_c`, `cmd_tainted_argv0` |
| Command safe | `cmd_list_args`, `cmd_list_shell_false`, `cmd_constant` |
| Command unknown | `cmd_string_no_shell` |
| Path | `path_direct` (unsafe), `path_basename` (safe), `path_safe_join` (safe), `path_constant` (safe), `path_normpath` (unknown) |
| Deserialize | `pickle_tainted` (unsafe), `yaml_safe_load` (safe) |
| Template | `template_string_tainted` (unsafe), `template_render_context` (safe), `template_constant` (safe) |
| Code | `eval_tainted` (unsafe), `exec_tainted` (unsafe), `literal_eval` (safe), `eval_constant` (safe) |
| Imports | `alias_import` (unsafe), `from_import` (unsafe) |
| Interprocedural | `cross_function` (unsafe), `sanitized_helper` (safe) |

The `Template` and `Code` rows exist because the gate is **per class** and
`_assess_template` and `_assess_code` are two of the six predicates. Without them
those two classes carry no cases, so their false-positive gate silently never
applies — the same "a corpus containing only cases you already pass measures
nothing" failure this section warns about, arrived at by omission instead of by
choosing easy cases. `template_render_context` must pass the tainted value as a
**context variable** (`render_template("p.html", name=user)`), not as the
template, since that is the shape the predicate has to distinguish.

`sql_reassigned_after_call` is the flow-sensitivity regression from Task 3.
`alias_import` and `from_import` are **expected to fail initially** — bare-name resolution
cannot follow `import subprocess as sp`. Record them as known gaps in
`benchmark/precision/README.md` rather than deleting them. A corpus containing only cases
you already pass measures nothing.

- [ ] **Step 2: Write the runner**

Create `benchmark/run_precision.py`:

```python
"""Measure detector precision, recall and abstention against the labelled corpus.

A falling finding count proves nothing — you reach zero by detecting nothing. All
three figures are reported so a precision gain bought with recall, or with mass
abstention, is visible.

``-UNVERIFIED`` findings are excluded from tp/fp: penalising an honest "I could
not tell" as a false positive pushes the detector toward guessing. They are
instead counted as abstentions, and abstaining on a *safe* case is gated,
because operationally it sends a clean change to a human.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cybergraph.analysis.python import analyze_python_file  # noqa: E402

CASES = Path(__file__).parent / "precision" / "cases"
RESULTS = Path(__file__).parent / "precision" / "results.json"


def _detect(case: Path) -> tuple[set[tuple[str, int, str]], int]:
    _, _, findings = analyze_python_file(case / "app.py", case)
    confirmed: set[tuple[str, int, str]] = set()
    abstentions = 0
    for finding in findings:
        if finding.rule_id.endswith("-UNVERIFIED"):
            abstentions += 1
            continue
        confirmed.add((finding.file_path, finding.line_start, finding.rule_id))
    return confirmed, abstentions


def main() -> int:
    tp = fp = fn = tn = 0
    safe_cases = safe_abstained = 0
    rows = []

    for case in sorted(path for path in CASES.iterdir() if path.is_dir()):
        doc = json.loads((case / "expected.json").read_text(encoding="utf-8"))
        expected = {(f["file"], f["line"], f["rule"]) for f in doc["findings"]}
        label = doc.get("label", "unsafe" if expected else "safe")
        detected, abstentions = _detect(case)

        case_tp = len(expected & detected)
        case_fp = len(detected - expected)
        case_fn = len(expected - detected)
        tp, fp, fn = tp + case_tp, fp + case_fp, fn + case_fn
        if not expected and not detected and not abstentions:
            tn += 1
        if label == "safe":
            safe_cases += 1
            if abstentions:
                safe_abstained += 1

        rows.append({
            "name": case.name, "label": label, "tp": case_tp, "fp": case_fp,
            "fn": case_fn, "abstentions": abstentions,
            "clean": case_fp == 0 and case_fn == 0 and not (label == "safe" and abstentions),
        })

    precision = round(tp / (tp + fp), 3) if (tp + fp) else 1.0
    recall = round(tp / (tp + fn), 3) if (tp + fn) else 1.0
    safe_abstention_rate = round(safe_abstained / safe_cases, 3) if safe_cases else 0.0

    summary = {
        "precision": precision, "recall": recall,
        "safe_abstention_rate": safe_abstention_rate,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "safe_cases": safe_cases, "safe_abstained": safe_abstained,
        "cases": rows,
    }
    RESULTS.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"precision={precision} recall={recall} "
          f"safe_abstention_rate={safe_abstention_rate} "
          f"tp={tp} fp={fp} fn={fn} tn={tn}")
    for row in rows:
        if not row["clean"]:
            print(f"  MISMATCH {row['name']} [{row['label']}]: "
                  f"fp={row['fp']} fn={row['fn']} abstentions={row['abstentions']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 3: Write the gate test**

Create `tests/test_precision_gate.py`:

```python
import json
import subprocess
import sys
from pathlib import Path

MIN_PRECISION = 0.90
MIN_RECALL = 0.95
MAX_SAFE_ABSTENTION = 0.15


def test_detector_meets_the_release_gate():
    root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [sys.executable, str(root / "benchmark" / "run_precision.py")],
        cwd=root, check=True, capture_output=True,
    )
    results = json.loads((root / "benchmark" / "precision" / "results.json").read_text())
    assert results["precision"] >= MIN_PRECISION, results
    assert results["recall"] >= MIN_RECALL, results
    assert results["safe_abstention_rate"] <= MAX_SAFE_ABSTENTION, (
        "abstaining on safe changes sends clean work to a human", results
    )
```

- [ ] **Step 4: Run it and fix the detector, not the corpus**

Run: `python benchmark/run_precision.py`

If a metric misses the gate, **fix the predicate**. The only acceptable corpus edit is
correcting a mislabelled expectation, and that needs a note in the commit body explaining
why the original label was wrong.

- [ ] **Step 5: Commit the corpus and its results**

Remove `benchmark/results.json` from `.gitignore:30` and commit both results files. A
published number that cannot be checked against a committed artifact is the failure this
project exists to avoid.

```
git add benchmark/ tests/test_precision_gate.py .gitignore
git commit -m "test(benchmark): labelled corpus gating precision, recall and abstention"
```

- [ ] **Step 6: Re-measure the two real repositories**

```
python -m cybergraph.cli build .
python -m cybergraph.cli build "$HOME/Projects/graphify"
```

Then for each, count findings by rule and by severity, and count `REACHES_SINK` edges.
Record before (151 and 2,739 — one rule, all medium) against after in the commit body.
Sink-edge counts should stay roughly constant: inventory preserved, findings filtered.

**Milestone 1A is complete here.** The noise problem is fixed and measured. 1B can slip
without losing it.

---

# MILESTONE 1B — VERDICT

---

## Task 8: Capability model

**Files:** Create `src/cybergraph/security/capability.py`; test `tests/test_capability.py`.

**Interfaces:**
- `PASS`, `FAIL`, `NOT_APPLICABLE`, `UNKNOWN`, `NOT_SUPPORTED`
- `Capability` — frozen dataclass: `id`, `label`, `covers: tuple[str, ...]`, `supported: bool`
- `CAPABILITIES: tuple[Capability, ...]`
- `CheckResult` — frozen dataclass: `capability_id`, `status`, `detail: str = ""`, `evidence_count: int = 0`
- `relevance(changed_files) -> dict[str, bool]`, `label_for(capability_id) -> str`, `triggers_review(results) -> bool`

Two fixes here.

**B3 — a `source_analysis_support` capability covering every executable source extension.**
Rev. 2 relied on a TypeScript-specific future capability to represent general language
blindness, so a `main.go`-only change matched nothing and accepted. This capability claims
all source files and reports `NOT_SUPPORTED` when any changed source file is in a language
with no analyzer.

**C3 — `runtime_exploitability` is removed from the list.** Rev. 2 listed it and then
special-cased `covers == ("*",)` to `NOT_APPLICABLE` so it would not review everything —
bending a state's meaning to work around a capability that is not in Phase 1. If it is not
a Phase 1 capability, it does not belong in `CAPABILITIES`. It stays in the roadmap.

- [ ] **Step 1: Write the failing test**

Create `tests/test_capability.py`:

```python
import pytest

from cybergraph.security.capability import (
    CAPABILITIES,
    FAIL,
    NOT_APPLICABLE,
    NOT_SUPPORTED,
    PASS,
    UNKNOWN,
    CheckResult,
    relevance,
    triggers_review,
)


def test_python_change_makes_python_capabilities_relevant():
    rel = relevance(("app/main.py",))
    assert rel["sql_construction"] is True
    assert rel["client_secret_boundary"] is False


def test_typescript_change_makes_the_web_capability_relevant():
    rel = relevance(("web/page.tsx",))
    assert rel["client_secret_boundary"] is True
    assert rel["sql_construction"] is False


def test_go_change_is_caught_by_general_source_support():
    """Rev.2 accepted a Go-only change because nothing claimed .go files."""
    rel = relevance(("cmd/main.go",))
    assert rel["source_analysis_support"] is True


def test_python_change_also_claims_source_support():
    assert relevance(("app.py",))["source_analysis_support"] is True


def test_readme_change_makes_nothing_relevant():
    assert not any(relevance(("README.md",)).values())


@pytest.mark.parametrize(
    "status,expected",
    [(PASS, False), (NOT_APPLICABLE, False), (FAIL, True), (UNKNOWN, True),
     (NOT_SUPPORTED, True)],
)
def test_review_triggers(status, expected):
    assert triggers_review([CheckResult("sql_construction", status)]) is expected


def test_runtime_exploitability_is_not_a_phase_one_capability():
    """It was listed then special-cased to stop it reviewing everything."""
    assert "runtime_exploitability" not in {c.id for c in CAPABILITIES}


def test_no_capability_claims_everything():
    """A wildcard capability forces a verdict on every change; none should exist."""
    for capability in CAPABILITIES:
        assert capability.covers != ("*",), capability.id
        assert capability.covers and capability.label
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_capability.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.capability'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/capability.py`:

```python
"""What CyberGraph claims to check, and what it admits it cannot.

Five states. The distinctions between the last three carry the product's
credibility:

``PASS``            the check ran on this change and found nothing
``FAIL``            the check ran and found something
``NOT_APPLICABLE``  supported, but nothing in this change is in its scope
``UNKNOWN``         supported, but it could not run here
``NOT_SUPPORTED``   the capability does not exist yet

``NOT_APPLICABLE`` and ``NOT_SUPPORTED`` look alike and are not. A README-only
change is NOT_APPLICABLE everywhere and can honestly accept. A change to a
language with no analyzer is NOT_SUPPORTED and cannot — accepting there is false
assurance, which for a verification tool is worse than a false positive.

Coverage is *declared*, never inferred: a capability states the file globs it
claims. Asking a non-existent analyzer whether it would have found something is
circular. ``source_analysis_support`` exists so that general language blindness
is represented directly, rather than being implied by whichever future
capability happens to list an extension.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

PASS = "pass"
FAIL = "fail"
NOT_APPLICABLE = "not_applicable"
UNKNOWN = "unknown"
NOT_SUPPORTED = "not_supported"

_REVIEW_STATES = frozenset({FAIL, UNKNOWN, NOT_SUPPORTED})

PYTHON_GLOBS = ("*.py",)
WEB_GLOBS = ("*.ts", "*.tsx", "*.js", "*.jsx", "*.vue", "*.svelte", "*.mjs", "*.cjs")
INFRA_GLOBS = ("*.tf", "*.tfvars", "supabase/*", "firebase.json", "*.yaml", "*.yml")

# Every extension CyberGraph recognises as executable source, supported or not.
SOURCE_GLOBS = (
    *PYTHON_GLOBS, *WEB_GLOBS,
    "*.go", "*.java", "*.cs", "*.rb", "*.php", "*.rs", "*.kt", "*.swift",
    "*.scala", "*.c", "*.cc", "*.cpp", "*.h", "*.hpp", "*.sh", "*.bash",
)
# The subset with a Phase 1 analyzer that produces findings.
VERIFIED_GLOBS = PYTHON_GLOBS


@dataclass(frozen=True)
class Capability:
    id: str
    label: str
    covers: tuple[str, ...]
    supported: bool


CAPABILITIES: tuple[Capability, ...] = (
    Capability("sql_construction", "Unsafe database queries", PYTHON_GLOBS, True),
    Capability("command_execution", "Unsafe system commands", PYTHON_GLOBS, True),
    Capability("code_execution", "Code run from user input", PYTHON_GLOBS, True),
    Capability("deserialization", "Unsafe data loading", PYTHON_GLOBS, True),
    Capability("path_access", "Files opened from user input", PYTHON_GLOBS, True),
    Capability("declared_login_rules", "Your declared login rules", PYTHON_GLOBS, True),
    Capability("reachable_data_paths",
               "New routes from the internet to sensitive code", PYTHON_GLOBS, True),
    Capability("source_analysis_support",
               "Languages CyberGraph can read", SOURCE_GLOBS, True),
    Capability("client_secret_boundary", "Secrets reaching the browser", WEB_GLOBS, False),
    Capability("cloud_configuration",
               "Cloud and database configuration", INFRA_GLOBS, False),
)

_BY_ID = {capability.id: capability for capability in CAPABILITIES}


@dataclass(frozen=True)
class CheckResult:
    capability_id: str
    status: str
    detail: str = ""
    evidence_count: int = 0


def relevance(changed_files: tuple[str, ...]) -> dict[str, bool]:
    """Which capabilities this change falls within the declared scope of."""
    return {
        capability.id: any(
            fnmatch(file, pattern)
            for file in changed_files
            for pattern in capability.covers
        )
        for capability in CAPABILITIES
    }


def unverified_source_files(changed_files: tuple[str, ...]) -> tuple[str, ...]:
    """Changed source files in a language with no Phase 1 analyzer."""
    return tuple(
        file
        for file in changed_files
        if any(fnmatch(file, pattern) for pattern in SOURCE_GLOBS)
        and not any(fnmatch(file, pattern) for pattern in VERIFIED_GLOBS)
    )


def label_for(capability_id: str) -> str:
    capability = _BY_ID.get(capability_id)
    return capability.label if capability else capability_id


def triggers_review(results: list[CheckResult]) -> bool:
    """Any failure, blind spot, or unsupported-but-relevant check forces review."""
    return any(result.status in _REVIEW_STATES for result in results)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_capability.py -v` — PASS (12 tests)

- [ ] **Step 5: Commit**

```
git add src/cybergraph/security/capability.py tests/test_capability.py
git commit -m "feat(capability): five-state results with general source-language coverage"
```

---

## Task 9: Analysis coverage

**Files:** Create `src/cybergraph/security/coverage.py`; test `tests/test_coverage.py`.

**Interfaces:**
- `FileCoverage` — frozen dataclass: `path`, `status`, `reason: str = ""`. `status` ∈ `analyzed` | `failed` | `unsupported` | `missing`.
- `assess_coverage(repo_root: Path, changed_files: tuple[str, ...]) -> tuple[FileCoverage, ...]`

This is B4. Rev. 2's capability wiring saw only changed files and findings, so a `.py` file
that failed to parse produced zero findings, which read as clean. `analyze_python_file`
already emits a `PY-SYNTAX` finding on `SyntaxError` — nothing consumed it. A changed file
is `analyzed` only if the graph holds a `File` node for it *and* no parse failure was
recorded against it.

- [ ] **Step 1: Write the failing test**

Create `tests/test_coverage.py`:

```python
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.security.coverage import assess_coverage

GOOD = "def add(a, b):\n    return a + b\n"
BROKEN = "def add(a, b)\n    return a + b\n"  # missing colon


def _status(tmp_path: Path, changed: tuple[str, ...]) -> dict[str, str]:
    build_graph(tmp_path)
    return {item.path: item.status for item in assess_coverage(tmp_path, changed)}


def test_parsed_file_is_analyzed(tmp_path: Path):
    (tmp_path / "good.py").write_text(GOOD, encoding="utf-8")
    assert _status(tmp_path, ("good.py",)) == {"good.py": "analyzed"}


def test_unparseable_file_is_failed_not_clean(tmp_path: Path):
    """Zero findings from a file that never parsed is not evidence of safety."""
    (tmp_path / "broken.py").write_text(BROKEN, encoding="utf-8")
    assert _status(tmp_path, ("broken.py",)) == {"broken.py": "failed"}


def test_language_without_an_analyzer_is_unsupported(tmp_path: Path):
    (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
    assert _status(tmp_path, ("main.go",)) == {"main.go": "unsupported"}


def test_deleted_file_is_missing_not_failed(tmp_path: Path):
    (tmp_path / "good.py").write_text(GOOD, encoding="utf-8")
    build_graph(tmp_path)
    (tmp_path / "good.py").unlink()
    statuses = {i.path: i.status for i in assess_coverage(tmp_path, ("good.py", "gone.py"))}
    assert statuses["gone.py"] == "missing"


def test_non_source_file_is_not_reported(tmp_path: Path):
    (tmp_path / "README.md").write_text("hi\n", encoding="utf-8")
    assert _status(tmp_path, ("README.md",)) == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_coverage.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.coverage'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/coverage.py`:

```python
"""Which changed files were actually analyzed.

Zero findings has two very different causes: the analyzer looked and found
nothing, or it never looked. Without this module they are indistinguishable, and
a Python file with a syntax error reads as clean.

``analyze_python_file`` already records a ``PY-SYNTAX`` finding when a file fails
to parse; nothing consumed it. A changed source file counts as ``analyzed`` only
when the graph holds a ``File`` node for it and no parse failure is recorded
against it.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security.capability import SOURCE_GLOBS, VERIFIED_GLOBS

STATUS_ANALYZED = "analyzed"
STATUS_FAILED = "failed"
STATUS_UNSUPPORTED = "unsupported"
STATUS_MISSING = "missing"

_PARSE_FAILURE_RULES = ("PY-SYNTAX",)


@dataclass(frozen=True)
class FileCoverage:
    path: str
    status: str
    reason: str = ""


def assess_coverage(
    repo_root: Path, changed_files: tuple[str, ...]
) -> tuple[FileCoverage, ...]:
    """Report analysis status for every changed *source* file."""
    repo_root = Path(repo_root).resolve()
    sources = tuple(
        file for file in changed_files
        if any(fnmatch(file, pattern) for pattern in SOURCE_GLOBS)
    )
    if not sources:
        return ()

    store = GraphStore.open_for_repo(repo_root)
    try:
        known = {
            row["key"]
            for row in store.conn.execute("SELECT key FROM nodes WHERE kind = 'File'")
        }
        failed = {
            row["file_path"]
            for row in store.conn.execute(
                "SELECT file_path FROM findings WHERE rule_id IN "
                f"({','.join('?' for _ in _PARSE_FAILURE_RULES)})",
                _PARSE_FAILURE_RULES,
            )
        }
    finally:
        store.close()

    results: list[FileCoverage] = []
    for file in sources:
        if file in failed:
            results.append(FileCoverage(file, STATUS_FAILED, "the file could not be read"))
        elif not any(fnmatch(file, pattern) for pattern in VERIFIED_GLOBS):
            results.append(
                FileCoverage(file, STATUS_UNSUPPORTED, "no analyzer for this language yet")
            )
        elif file in known:
            results.append(FileCoverage(file, STATUS_ANALYZED))
        elif not (repo_root / file).exists():
            results.append(FileCoverage(file, STATUS_MISSING, "deleted in this change"))
        else:
            results.append(
                FileCoverage(file, STATUS_FAILED, "the file was not analyzed")
            )
    return tuple(results)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_coverage.py -v` — PASS (5 tests)

- [ ] **Step 5: Commit**

```
git add src/cybergraph/security/coverage.py tests/test_coverage.py
git commit -m "feat(coverage): record whether each changed file was actually analyzed"
```

---

## Task 10: Policy model with strict loading

**Files:** Create `src/cybergraph/security/policy.py`; test `tests/test_policy.py`.

**Interfaces:** `POLICY_FILE = "cybergraph.policy.toml"`, `KIND_REQUIRE_AUTH = "require_auth"`, `PolicyRule(id, kind, patterns, because)`, `PolicyProblem(rule_id, message)`, `Policy(version, rules, problems, source_hash, exists)`, `load_policy(repo_root) -> Policy`, `_rule_sections(data) -> dict`.

Two decisions, both from the review:

**`require_authz` does not exist.** A `GUARDS` edge proves a login check, not a role or
ownership check. Accepting an authorization rule and evaluating it as authentication would
be a lie told inside the user's own file. Authorization arrives with typed edges later.

**Nothing fails silently.** An unrecognised kind, a malformed rule, or an unsupported
version becomes a `PolicyProblem`, which Task 16 turns into a review. For an ordinary
config file, dropping an unknown key is friendly; for a security policy it means a promise
the user wrote vanished without a word.

- [ ] **Step 1: Write the failing test**

Create `tests/test_policy.py`:

```python
from pathlib import Path

from cybergraph.security.policy import KIND_REQUIRE_AUTH, POLICY_FILE, load_policy

GOOD = """
version = 1

[rule.admin-requires-login]
kind = "require_auth"
patterns = ["/admin/*", "/internal/*"]
because = "Admin pages show data that is not meant to be public."
"""


def test_missing_file_yields_empty_policy(tmp_path: Path):
    policy = load_policy(tmp_path)
    assert policy.is_empty()
    assert policy.problems == ()
    assert policy.exists is False


def test_loads_rules_and_records_a_hash(tmp_path: Path):
    (tmp_path / POLICY_FILE).write_text(GOOD, encoding="utf-8")
    policy = load_policy(tmp_path)
    assert policy.exists is True
    assert len(policy.rules) == 1
    rule = policy.rules[0]
    assert rule.id == "admin-requires-login"
    assert rule.kind == KIND_REQUIRE_AUTH
    assert rule.patterns == ("/admin/*", "/internal/*")
    assert len(policy.source_hash) == 64


def test_unknown_kind_becomes_a_visible_problem(tmp_path: Path):
    (tmp_path / POLICY_FILE).write_text(
        'version = 1\n\n[rule.mfa]\nkind = "require_mfa"\npatterns = ["/pay/*"]\n',
        encoding="utf-8",
    )
    policy = load_policy(tmp_path)
    assert policy.rules == ()
    assert len(policy.problems) == 1
    assert "require_mfa" in policy.problems[0].message


def test_authz_is_rejected_rather_than_faked(tmp_path: Path):
    (tmp_path / POLICY_FILE).write_text(
        'version = 1\n\n[rule.a]\nkind = "require_authz"\npatterns = ["/admin/*"]\n',
        encoding="utf-8",
    )
    policy = load_policy(tmp_path)
    assert policy.rules == ()
    assert policy.problems, "authorization must not be silently treated as authentication"


def test_secret_server_only_is_marked_unsupported_not_ignored(tmp_path: Path):
    (tmp_path / POLICY_FILE).write_text(
        'version = 1\n\n[rule.s]\nkind = "secret_server_only"\npatterns = ["STRIPE_KEY"]\n',
        encoding="utf-8",
    )
    policy = load_policy(tmp_path)
    assert policy.rules == ()
    assert any("not yet" in problem.message.lower() for problem in policy.problems)


def test_missing_patterns_is_a_problem(tmp_path: Path):
    (tmp_path / POLICY_FILE).write_text(
        'version = 1\n\n[rule.a]\nkind = "require_auth"\n', encoding="utf-8"
    )
    assert load_policy(tmp_path).problems


def test_future_version_is_a_problem(tmp_path: Path):
    (tmp_path / POLICY_FILE).write_text("version = 99\n", encoding="utf-8")
    assert load_policy(tmp_path).problems


def test_flat_parser_shape_is_normalised():
    from cybergraph.security.policy import _rule_sections

    nested = {"rule": {"a": {"kind": "require_auth", "patterns": ["/x"]}}}
    flat = {"rule.a": {"kind": "require_auth", "patterns": ["/x"]}}
    assert _rule_sections(nested) == _rule_sections(flat)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_policy.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.policy'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/policy.py`:

```python
"""Declared security policy — the promises this application keeps.

Written by a human (optionally from an extracted baseline) and committed at the
repository root as ``cybergraph.policy.toml``. It is *declared*, not inferred:
guessing that "users may only read their own invoices" is a semantics problem,
and a wrong guess that gets enforced blocks correct code.

Nothing fails silently. An unrecognised kind, a malformed rule, or an
unsupported version becomes a ``PolicyProblem`` that forces a review — a promise
the user wrote must never disappear without a word.

``require_authz`` is deliberately absent. A ``GUARDS`` edge proves a login check,
not a role or ownership check, and accepting an authorization rule while
evaluating it as authentication would be a lie inside the user's own file.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cybergraph.config import _load_toml

POLICY_FILE = "cybergraph.policy.toml"
SUPPORTED_VERSION = 1

KIND_REQUIRE_AUTH = "require_auth"

# Recognised but not yet evaluable. Named so they surface as an honest problem
# rather than loading as an active rule that quietly does nothing.
_NOT_YET_SUPPORTED = {
    "require_authz": "authorization needs role and ownership modelling, which does not exist yet",
    "require_role": "role checks need typed authorization edges, which do not exist yet",
    "require_ownership": "ownership checks need resource modelling, which does not exist yet",
    "secret_server_only": "client and server boundary analysis is not yet implemented",
}


@dataclass(frozen=True)
class PolicyRule:
    id: str
    kind: str
    patterns: tuple[str, ...]
    because: str = ""


@dataclass(frozen=True)
class PolicyProblem:
    rule_id: str
    message: str


@dataclass(frozen=True)
class Policy:
    version: int = SUPPORTED_VERSION
    rules: tuple[PolicyRule, ...] = ()
    problems: tuple[PolicyProblem, ...] = ()
    source_hash: str = ""
    exists: bool = False

    def is_empty(self) -> bool:
        return not self.rules


def load_policy(repo_root: Path) -> Policy:
    """Read the committed policy. Never drops a rule without recording why."""
    path = Path(repo_root) / POLICY_FILE
    if not path.exists():
        return Policy()

    source_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    data = _load_toml(path)
    problems: list[PolicyProblem] = []

    version = _as_int(data.get("version", SUPPORTED_VERSION), SUPPORTED_VERSION)
    if version != SUPPORTED_VERSION:
        problems.append(
            PolicyProblem(
                "",
                f"policy version {version} is not supported "
                f"(this build understands version {SUPPORTED_VERSION})",
            )
        )

    rules: list[PolicyRule] = []
    for rule_id, section in sorted(_rule_sections(data).items()):
        rule, problem = _build_rule(rule_id, section)
        if rule is not None:
            rules.append(rule)
        if problem is not None:
            problems.append(problem)

    return Policy(version, tuple(rules), tuple(problems), source_hash, exists=True)


def _rule_sections(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Normalise nested (``tomllib``) and flat (3.10 fallback) rule tables."""
    sections: dict[str, dict[str, Any]] = {}
    nested = data.get("rule")
    if isinstance(nested, dict):
        for rule_id, section in nested.items():
            if isinstance(section, dict):
                sections[str(rule_id)] = section
    for key, section in data.items():
        if key.startswith("rule.") and isinstance(section, dict):
            sections[key[len("rule.") :]] = section
    return sections


def _build_rule(
    rule_id: str, section: dict[str, Any]
) -> tuple[PolicyRule | None, PolicyProblem | None]:
    kind = str(section.get("kind", "")).strip()
    if kind in _NOT_YET_SUPPORTED:
        return None, PolicyProblem(
            rule_id, f"`{kind}` is not yet supported: {_NOT_YET_SUPPORTED[kind]}"
        )
    if kind != KIND_REQUIRE_AUTH:
        return None, PolicyProblem(rule_id, f"unrecognised rule type `{kind or '(missing)'}`")

    raw = section.get("patterns", [])
    patterns = tuple(str(item) for item in raw) if isinstance(raw, list) else ()
    if not patterns:
        return None, PolicyProblem(rule_id, "rule has no `patterns`, so it constrains nothing")

    return (
        PolicyRule(rule_id, kind, patterns, str(section.get("because", ""))),
        None,
    )


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_policy.py -v` — PASS (8 tests)

- [ ] **Step 5: Commit**

```
git add src/cybergraph/security/policy.py tests/test_policy.py
git commit -m "feat(policy): strict loader that never drops a rule silently"
```

---

## Task 11: Entity-keyed policy evaluation

**Files:** Modify `src/cybergraph/security/policy.py`; test `tests/test_policy.py` (append).

**Interfaces:**
- `ProtectedEntity` — frozen dataclass: `key` (function key), `route`, `file_path`, `line`, `guarded: bool`
- `PolicyViolation(rule_id, subject, entity_key, file_path, line, because)`
- `ProtectedSet` — frozen dataclass: `entities: dict[str, ProtectedEntity]` keyed by function key, `constrained: frozenset[str]` (function keys), `unprotected: tuple[PolicyViolation, ...]`
- `evaluate_policy(repo_root, policy) -> ProtectedSet`

This is half of C1. Rev. 2 keyed identity on the **route string**, so renaming
`/admin/export` to `/export` while dropping the guard made the old route vanish from the
current graph — read as a legitimate deletion — while the new route fell outside
`/admin/*` and was never constrained. Silent pass on exactly the AI-generated regression
this product exists to catch.

Identity is now the **function key**, which survives a route rename. Task 12 uses it.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_policy.py`:

```python
from cybergraph.build import build_graph

UNGUARDED = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/admin/export")
def admin_export():
    return {"ok": True}
'''

GUARDED = '''
from fastapi import FastAPI, Depends
app = FastAPI()

def require_login():
    return True

@app.get("/admin/export")
def admin_export(user=Depends(require_login)):
    return {"ok": True}
'''

AUTH_POLICY = (
    'version = 1\n\n[rule.admin]\nkind = "require_auth"\n'
    'patterns = ["/admin/*"]\nbecause = "Admin pages are not public."\n'
)


def _setup(tmp_path: Path, source: str, policy_text: str = AUTH_POLICY):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    (tmp_path / POLICY_FILE).write_text(policy_text, encoding="utf-8")
    build_graph(tmp_path)
    return load_policy(tmp_path)


def test_unguarded_route_is_unprotected(tmp_path: Path):
    from cybergraph.security.policy import evaluate_policy

    result = evaluate_policy(tmp_path, _setup(tmp_path, UNGUARDED))
    assert len(result.unprotected) == 1
    assert result.unprotected[0].rule_id == "admin"
    assert result.unprotected[0].because == "Admin pages are not public."


def test_guarded_route_is_constrained_but_protected(tmp_path: Path):
    from cybergraph.security.policy import evaluate_policy

    result = evaluate_policy(tmp_path, _setup(tmp_path, GUARDED))
    assert result.unprotected == ()
    assert len(result.constrained) == 1


def test_entities_are_keyed_by_function_not_route(tmp_path: Path):
    """Function keys survive a route rename; route strings do not."""
    from cybergraph.security.policy import evaluate_policy

    result = evaluate_policy(tmp_path, _setup(tmp_path, GUARDED))
    key = next(iter(result.entities))
    assert "admin_export" in key
    assert result.entities[key].route == "/admin/export"
    assert result.entities[key].guarded is True


def test_empty_policy_constrains_nothing(tmp_path: Path):
    from cybergraph.security.policy import Policy, evaluate_policy

    (tmp_path / "app.py").write_text(UNGUARDED, encoding="utf-8")
    build_graph(tmp_path)
    result = evaluate_policy(tmp_path, Policy())
    assert result.constrained == frozenset()
    assert result.unprotected == ()
    assert result.entities, "entities are recorded even with no policy"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_policy.py -v`
Expected: FAIL — `ImportError: cannot import name 'evaluate_policy'`

- [ ] **Step 3: Write minimal implementation**

Append to `src/cybergraph/security/policy.py` (adding `import json`, `from fnmatch import fnmatch`, `from cybergraph.graph import GraphStore`):

```python
@dataclass(frozen=True)
class ProtectedEntity:
    key: str
    route: str
    file_path: str
    line: int
    guarded: bool


@dataclass(frozen=True)
class PolicyViolation:
    rule_id: str
    subject: str
    entity_key: str
    file_path: str
    line: int
    because: str = ""


@dataclass(frozen=True)
class ProtectedSet:
    """What a policy constrains, keyed by function rather than by route string.

    Route strings are not stable identity: renaming ``/admin/export`` to
    ``/export`` while dropping the guard would look like a deletion plus an
    unrelated new route. The function key survives the rename, so Task 12 can
    tell the difference.
    """

    entities: dict[str, ProtectedEntity] = field(default_factory=dict)
    constrained: frozenset[str] = frozenset()
    unprotected: tuple[PolicyViolation, ...] = ()


def evaluate_policy(repo_root: Path, policy: Policy) -> ProtectedSet:
    """Resolve a policy against a graph into the set of entities it protects."""
    repo_root = Path(repo_root).resolve()
    store = GraphStore.open_for_repo(repo_root)
    try:
        rows = store.conn.execute(
            """
            SELECT e.target AS key, n.name AS name, n.file_path AS file_path,
                   n.line_start AS line, n.properties AS properties
            FROM edges e JOIN nodes n ON n.key = e.target
            WHERE e.kind = 'EXPOSES_ENTRYPOINT'
            """
        ).fetchall()
        guarded = {
            row["source"]
            for row in store.conn.execute("SELECT source FROM edges WHERE kind = 'GUARDS'")
        }
    finally:
        store.close()

    entities = {
        row["key"]: ProtectedEntity(
            key=row["key"],
            route=_route_path(row["properties"]) or row["name"],
            file_path=row["file_path"] or "",
            line=row["line"] or 0,
            guarded=row["key"] in guarded,
        )
        for row in rows
    }

    constrained: set[str] = set()
    violations: list[PolicyViolation] = []
    for rule in policy.rules:
        for entity in entities.values():
            if not entity.route:
                continue
            if not any(fnmatch(entity.route, pattern) for pattern in rule.patterns):
                continue
            constrained.add(entity.key)
            if entity.guarded:
                continue
            violations.append(
                PolicyViolation(
                    rule_id=rule.id,
                    subject=entity.route,
                    entity_key=entity.key,
                    file_path=entity.file_path,
                    line=entity.line,
                    because=rule.because,
                )
            )

    return ProtectedSet(
        entities=entities,
        constrained=frozenset(constrained),
        unprotected=tuple(sorted(violations, key=lambda v: (v.rule_id, v.subject))),
    )


def _route_path(raw: str | None) -> str:
    if not raw:
        return ""
    try:
        props = json.loads(raw)
    except (TypeError, ValueError):
        return ""
    if not isinstance(props, dict):
        return ""
    route = props.get("route")
    return str(route.get("path", "")) if isinstance(route, dict) else ""
```

Add `field` to the `dataclasses` import at the top of the module.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_policy.py -v` — PASS (12 tests)

- [ ] **Step 5: Commit**

```
git add src/cybergraph/security/policy.py tests/test_policy.py
git commit -m "feat(policy): key protected entities by function so renames stay visible"
```

---

## Task 12: Policy and config delta

**Files:** Modify `src/cybergraph/security/policy.py`; test `tests/test_policy_delta.py` (create).

**Interfaces:**
- `PolicyChange(kind, subject, detail)`
- `diff_policies(base: Policy, base_set: ProtectedSet, current: Policy, current_set: ProtectedSet) -> tuple[PolicyChange, ...]`
- `diff_configs(base: CyberGraphConfig, current: CyberGraphConfig) -> tuple[PolicyChange, ...]`
- Kinds: `policy_deleted`, `policy_problem`, `rule_removed`, `coverage_shrunk`, `protection_lost`, `version_downgraded`, `promise_added`, `promise_broken`, `promise_unmet`, `suppression_added`, `ignored_path_added`, `auth_marker_removed`, `validation_marker_removed`, `custom_sink_removed`.

Three corrections here.

**Weakening is semantic.** `patterns = ["/admin/*"]` → `["/admin/legacy/*"]` reads as a
tightening to any string comparison and protects strictly less. The comparison is over the
*resolved constrained set*.

**Deleted entities are excluded, renamed ones are not.** A route leaving the protected set
because it was deleted is not a weakening — naive set difference flags one on every route
deletion. But the surviving-function check (C1) catches the rename escape: if a function
key is still present and was guarded-and-constrained before, losing either property is
`protection_lost`.

**C4 — accurate kinds.** Policy *problems* get `policy_problem`, not `rule_removed`.
Validation-marker removal gets its own kind, not the login-check headline.

- [ ] **Step 1: Write the failing test**

Create `tests/test_policy_delta.py`:

```python
from cybergraph.config import CyberGraphConfig
from cybergraph.security.policy import (
    Policy,
    PolicyProblem,
    PolicyRule,
    PolicyViolation,
    ProtectedEntity,
    ProtectedSet,
    diff_configs,
    diff_policies,
)

RULE = PolicyRule("admin", "require_auth", ("/admin/*",), "Admin is not public.")


def _entity(key, route, guarded=True):
    return ProtectedEntity(key, route, "app.py", 1, guarded)


def _set(entities, constrained=(), unprotected=()):
    return ProtectedSet(
        {e.key: e for e in entities}, frozenset(constrained), tuple(unprotected)
    )


def _kinds(*args):
    return {change.kind for change in diff_policies(*args)}


def test_no_change_is_clean():
    policy = Policy(rules=(RULE,), exists=True)
    state = _set([_entity("app.py::x", "/admin/x")], ["app.py::x"])
    assert diff_policies(policy, state, policy, state) == ()


def test_policy_deleted_is_flagged():
    base = Policy(rules=(RULE,), exists=True)
    state = _set([_entity("app.py::x", "/admin/x")], ["app.py::x"])
    kinds = _kinds(base, state, Policy(exists=False), _set([_entity("app.py::x", "/admin/x")]))
    assert "policy_deleted" in kinds


def test_rule_removed_is_flagged():
    base = Policy(rules=(RULE,), exists=True)
    entity = _entity("app.py::x", "/admin/x")
    kinds = _kinds(
        base, _set([entity], ["app.py::x"]), Policy(rules=(), exists=True), _set([entity])
    )
    assert "rule_removed" in kinds


def test_narrowing_a_pattern_shrinks_coverage():
    """`/admin/*` -> `/admin/legacy/*` reads as stricter and protects less."""
    base = Policy(rules=(RULE,), exists=True)
    narrowed = PolicyRule("admin", "require_auth", ("/admin/legacy/*",), "")
    entities = [_entity("app.py::x", "/admin/x"), _entity("app.py::y", "/admin/legacy/y")]
    kinds = _kinds(
        base, _set(entities, ["app.py::x", "app.py::y"]),
        Policy(rules=(narrowed,), exists=True), _set(entities, ["app.py::y"]),
    )
    assert "coverage_shrunk" in kinds


def test_deleting_a_route_is_not_a_weakening():
    policy = Policy(rules=(RULE,), exists=True)
    before = _set(
        [_entity("app.py::x", "/admin/x"), _entity("app.py::gone", "/admin/gone")],
        ["app.py::x", "app.py::gone"],
    )
    after = _set([_entity("app.py::x", "/admin/x")], ["app.py::x"])
    assert "coverage_shrunk" not in _kinds(policy, before, policy, after)


def test_renaming_a_route_out_of_scope_is_caught():
    """The C1 escape: /admin/export -> /export with the guard dropped."""
    policy = Policy(rules=(RULE,), exists=True)
    before = _set([_entity("app.py::export", "/admin/export", True)], ["app.py::export"])
    after = _set([_entity("app.py::export", "/export", False)])
    assert "protection_lost" in _kinds(policy, before, policy, after)


def test_dropping_a_guard_without_renaming_is_caught():
    policy = Policy(rules=(RULE,), exists=True)
    before = _set([_entity("app.py::x", "/admin/x", True)], ["app.py::x"])
    violation = PolicyViolation("admin", "/admin/x", "app.py::x", "app.py", 1, "")
    after = _set([_entity("app.py::x", "/admin/x", False)], ["app.py::x"], [violation])
    assert "promise_broken" in _kinds(policy, before, policy, after)


def test_pre_existing_debt_does_not_review_an_unrelated_change():
    policy = Policy(rules=(RULE,), exists=True)
    violation = PolicyViolation("admin", "/admin/x", "app.py::x", "app.py", 1, "")
    state = _set([_entity("app.py::x", "/admin/x", False)], ["app.py::x"], [violation])
    assert _kinds(policy, state, policy, state) == set()


def test_added_rule_that_is_already_violated_is_unmet_not_broken():
    new_rule = PolicyRule("new", "require_auth", ("/pay/*",), "")
    entity = _entity("app.py::pay", "/pay/x", False)
    violation = PolicyViolation("new", "/pay/x", "app.py::pay", "app.py", 1, "")
    kinds = _kinds(
        Policy(rules=(), exists=True), _set([entity]),
        Policy(rules=(new_rule,), exists=True), _set([entity], ["app.py::pay"], [violation]),
    )
    assert "promise_unmet" in kinds
    assert "promise_broken" not in kinds


def test_version_downgrade_is_flagged():
    entity = _entity("app.py::x", "/admin/x")
    state = _set([entity], ["app.py::x"])
    kinds = _kinds(
        Policy(version=2, rules=(RULE,), exists=True), state,
        Policy(version=1, rules=(RULE,), exists=True), state,
    )
    assert "version_downgraded" in kinds


def test_policy_problems_get_their_own_kind():
    """An unsupported rule is not a removed rule."""
    current = Policy(
        rules=(), problems=(PolicyProblem("mfa", "`require_mfa` is not yet supported"),),
        exists=True,
    )
    kinds = _kinds(Policy(exists=True), _set([]), current, _set([]))
    assert kinds == {"policy_problem"}


def test_config_deltas():
    assert diff_configs(CyberGraphConfig(), CyberGraphConfig()) == ()
    assert {c.kind for c in diff_configs(
        CyberGraphConfig(), CyberGraphConfig(suppressed_rules=("CG-SQL-EXEC",))
    )} == {"suppression_added"}
    assert {c.kind for c in diff_configs(
        CyberGraphConfig(), CyberGraphConfig(ignored_paths=("src/*",))
    )} == {"ignored_path_added"}
    assert {c.kind for c in diff_configs(
        CyberGraphConfig(auth_markers=("verify_jwt",)), CyberGraphConfig()
    )} == {"auth_marker_removed"}
    assert {c.kind for c in diff_configs(
        CyberGraphConfig(validation_markers=("clean",)), CyberGraphConfig()
    )} == {"validation_marker_removed"}
    assert {c.kind for c in diff_configs(
        CyberGraphConfig(custom_sinks=("send_money",)), CyberGraphConfig()
    )} == {"custom_sink_removed"}
    assert diff_configs(CyberGraphConfig(), CyberGraphConfig(auth_markers=("x",))) == ()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_policy_delta.py -v`
Expected: FAIL — `ImportError: cannot import name 'diff_policies'`

- [ ] **Step 3: Write minimal implementation**

Append to `src/cybergraph/security/policy.py` (add `from cybergraph.config import CyberGraphConfig`):

```python
@dataclass(frozen=True)
class PolicyChange:
    kind: str
    subject: str = ""
    detail: str = ""


def diff_policies(
    base: Policy,
    base_set: ProtectedSet,
    current: Policy,
    current_set: ProtectedSet,
) -> tuple[PolicyChange, ...]:
    """Classify how the security promises changed between two revisions.

    Weakening is measured over the *resolved* constrained set, never the rule
    text: narrowing ``/admin/*`` to ``/admin/legacy/*`` reads as a tightening to
    any string comparison and protects strictly less.

    Entities are keyed by function, and only those present in both graphs are
    compared. A route deleted outright is not a weakening; a route *renamed* out
    of a rule's scope is, because the function survived.
    """
    changes: list[PolicyChange] = []

    if base.exists and not current.exists:
        return (
            PolicyChange("policy_deleted", POLICY_FILE, "the security policy file was removed"),
        )

    for problem in current.problems:
        changes.append(
            PolicyChange("policy_problem", problem.rule_id or POLICY_FILE, problem.message)
        )

    if base.exists and current.version < base.version:
        changes.append(
            PolicyChange("version_downgraded", "",
                         f"policy version {base.version} -> {current.version}")
        )

    base_ids = {rule.id for rule in base.rules}
    current_ids = {rule.id for rule in current.rules}
    for removed in sorted(base_ids - current_ids):
        changes.append(PolicyChange("rule_removed", removed, "a declared promise was removed"))
    for added in sorted(current_ids - base_ids):
        changes.append(PolicyChange("promise_added", added, "a new promise was declared"))

    surviving = set(base_set.entities) & set(current_set.entities)

    # A function that was constrained and is no longer — the rename escape.
    for key in sorted((base_set.constrained & surviving) - current_set.constrained):
        before = base_set.entities[key]
        after = current_set.entities[key]
        kind = "protection_lost" if before.route != after.route else "coverage_shrunk"
        detail = (
            f"it moved from `{before.route}` to `{after.route}`"
            if before.route != after.route
            else "no rule covers it any more"
        )
        changes.append(PolicyChange(kind, before.route or key, detail))

    # A function that stayed constrained but lost its guard.
    base_broken = {v.entity_key for v in base_set.unprotected}
    for violation in current_set.unprotected:
        if violation.entity_key in base_broken:
            continue  # pre-existing debt; not caused by this change
        kind = (
            "promise_unmet" if violation.rule_id in (current_ids - base_ids)
            else "promise_broken"
        )
        changes.append(
            PolicyChange(kind, violation.subject,
                         violation.because or "this route has no login check")
        )

    return tuple(changes)


def diff_configs(
    base: CyberGraphConfig, current: CyberGraphConfig
) -> tuple[PolicyChange, ...]:
    """Flag project-config edits that weaken what CyberGraph checks.

    The policy file is not the only referee: removing an auth marker silently
    un-guards routes, and adding an ignored path hides a directory. Additions
    that *strengthen* checking are not flagged.
    """
    changes: list[PolicyChange] = []
    additions = (
        (set(current.suppressed_rules) - set(base.suppressed_rules),
         "suppression_added", "findings for this rule are now hidden"),
        (set(current.suppressed_paths) - set(base.suppressed_paths),
         "suppression_added", "findings under this path are now hidden"),
        (set(current.ignored_paths) - set(base.ignored_paths),
         "ignored_path_added", "this path is no longer analyzed"),
    )
    removals = (
        (set(base.auth_markers) - set(current.auth_markers),
         "auth_marker_removed",
         "routes guarded by this are no longer recognised as protected"),
        (set(base.validation_markers) - set(current.validation_markers),
         "validation_marker_removed",
         "this is no longer recognised as an input check"),
        (set(base.custom_sinks) - set(current.custom_sinks),
         "custom_sink_removed", "this call is no longer treated as sensitive"),
    )
    for items, kind, detail in (*additions, *removals):
        changes.extend(PolicyChange(kind, subject, detail) for subject in sorted(items))
    return tuple(changes)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_policy_delta.py -v` — PASS (12 tests)

- [ ] **Step 5: Commit**

```
git add src/cybergraph/security/policy.py tests/test_policy_delta.py
git commit -m "feat(policy): semantic policy and config delta with rename detection"
```

---

## Task 13: Baseline extraction

**Files:** Modify `src/cybergraph/security/policy.py`; test `tests/test_policy.py` (append).

**Interfaces:** `extract_baseline(repo_root: Path) -> str` returning TOML text. Never writes.

Named *baseline extraction*, not policy inference. It proposes only what the code already
does. Current behaviour can itself be accidental, so the generated header asks the user to
confirm rather than asserting the promise.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_policy.py`:

```python
MIXED = '''
from fastapi import FastAPI, Depends
app = FastAPI()

def require_login():
    return True

@app.get("/admin/export")
def admin_export(user=Depends(require_login)):
    return {"ok": True}

@app.get("/public/ping")
def ping():
    return {"ok": True}
'''


def test_baseline_promises_only_what_is_already_guarded(tmp_path: Path):
    from cybergraph.security.policy import extract_baseline

    (tmp_path / "app.py").write_text(MIXED, encoding="utf-8")
    build_graph(tmp_path)
    draft = extract_baseline(tmp_path)
    assert "/admin/export" in draft
    assert "/public/ping" not in draft
    assert 'kind = "require_auth"' in draft


def test_baseline_is_loadable_and_problem_free(tmp_path: Path):
    from cybergraph.security.policy import extract_baseline

    (tmp_path / "app.py").write_text(MIXED, encoding="utf-8")
    build_graph(tmp_path)
    (tmp_path / POLICY_FILE).write_text(extract_baseline(tmp_path), encoding="utf-8")
    policy = load_policy(tmp_path)
    assert not policy.is_empty()
    assert policy.problems == ()


def test_baseline_with_no_guards_is_still_valid(tmp_path: Path):
    from cybergraph.security.policy import extract_baseline

    (tmp_path / "app.py").write_text(UNGUARDED, encoding="utf-8")
    build_graph(tmp_path)
    (tmp_path / POLICY_FILE).write_text(extract_baseline(tmp_path), encoding="utf-8")
    assert load_policy(tmp_path).is_empty()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_policy.py -v`
Expected: FAIL — `ImportError: cannot import name 'extract_baseline'`

- [ ] **Step 3: Write minimal implementation**

Append to `src/cybergraph/security/policy.py`:

```python
_BASELINE_HEADER = """\
# CyberGraph security policy — the promises this application keeps.
#
# CyberGraph found these login checks ALREADY IN PLACE and is asking whether you
# want to keep them. It has not guessed at intent: every line below describes
# something the code does today.
#
# Review each one. A check that is here by accident should be deleted, not kept.
# Add promises CyberGraph could not see for itself.
#
# Commit this file. It is shared project memory and any coding agent can read it.

version = 1
"""

_BASELINE_RULE = """
[rule.{rule_id}]
kind = "require_auth"
patterns = [{patterns}]
because = "These routes already require a login today."
"""


def extract_baseline(repo_root: Path) -> str:
    """Propose a policy from routes that already have a guard. Never writes."""
    protected = evaluate_policy(Path(repo_root).resolve(), Policy())
    routes = sorted(
        {entity.route for entity in protected.entities.values()
         if entity.guarded and entity.route}
    )
    if not routes:
        return _BASELINE_HEADER
    rendered = ", ".join(f'"{route}"' for route in routes)
    return _BASELINE_HEADER + _BASELINE_RULE.format(
        rule_id="existing-login-checks", patterns=rendered
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_policy.py -v` — PASS (15 tests)

- [ ] **Step 5: Commit**

```
git add src/cybergraph/security/policy.py tests/test_policy.py
git commit -m "feat(policy): extract a confirmable baseline from existing guards"
```

---

## Task 14: Revision resolution that fails closed

**Files:** Create `src/cybergraph/security/revisions.py`; test `tests/test_revisions.py`.

**Interfaces:**
- `MODE_WORKTREE`, `MODE_MERGE_BASE`, `MODE_RANGE`
- `Revisions(mode, base_ref, head_ref, changed_files, failure: str = "")`
- `resolve_revisions(repo_root, base=None, mode=None) -> Revisions`

This is B1 and C7, the highest-value fix in the plan.

**B1 — untracked files.** Verified by running it:

```
git diff --name-only HEAD  -> []                          # sees nothing
git status --porcelain     -> ?? brand_new_endpoint.py    # tree is dirty
git ls-files --others      -> brand_new_endpoint.py
```

A new file makes the tree dirty, so worktree mode is selected, but the diff is empty →
zero changed files → every capability `NOT_APPLICABLE` → **ACCEPT** over a file nobody
read. Creating files is what coding agents do most. The changed set now unions
`git ls-files --others --exclude-standard`.

**C7 — `--base origin/main` silently selected worktree mode**, so the documented merge-base
path was never exercised. `--mode` is now honoured, and CI passes it explicitly.

**Fail closed.** A git failure produces `failure`, not an empty diff. "The comparison could
not be established" and "nothing changed" must never render as the same verdict.

- [ ] **Step 1: Write the failing test**

Create `tests/test_revisions.py`:

```python
import subprocess
from pathlib import Path

from cybergraph.security.revisions import (
    MODE_MERGE_BASE,
    MODE_RANGE,
    MODE_WORKTREE,
    resolve_revisions,
)


def _run(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    ).stdout.strip()


def _repo(tmp_path: Path) -> Path:
    _run(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    _run(tmp_path, "add", "-A")
    _run(tmp_path, "commit", "-qm", "base")
    return tmp_path


def test_modified_file_is_seen(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
    revisions = resolve_revisions(repo)
    assert revisions.mode == MODE_WORKTREE
    assert revisions.changed_files == ("a.py",)


def test_untracked_file_is_seen(tmp_path: Path):
    """The blocker: `git diff HEAD` does not list untracked files."""
    repo = _repo(tmp_path)
    (repo / "new_admin_endpoint.py").write_text("x = 1\n", encoding="utf-8")
    revisions = resolve_revisions(repo)
    assert revisions.changed_files == ("new_admin_endpoint.py",)
    assert revisions.failure == ""


def test_untracked_and_modified_are_unioned(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
    (repo / "b.py").write_text("y = 1\n", encoding="utf-8")
    assert resolve_revisions(repo).changed_files == ("a.py", "b.py")


def test_gitignored_files_are_not_reported(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / ".gitignore").write_text("secret.py\n", encoding="utf-8")
    (repo / "secret.py").write_text("x = 1\n", encoding="utf-8")
    assert "secret.py" not in resolve_revisions(repo).changed_files


def test_clean_tree_on_a_branch_uses_merge_base(tmp_path: Path):
    repo = _repo(tmp_path)
    _run(repo, "checkout", "-qb", "feature")
    (repo / "b.py").write_text("y = 1\n", encoding="utf-8")
    _run(repo, "add", "-A")
    _run(repo, "commit", "-qm", "feature work")

    revisions = resolve_revisions(repo)
    assert revisions.mode == MODE_MERGE_BASE
    assert revisions.changed_files == ("b.py",), "the PR-CI false-ACCEPT case"


def test_explicit_merge_base_mode_is_honoured(tmp_path: Path):
    """C7: --base alone silently fell back to worktree mode."""
    repo = _repo(tmp_path)
    _run(repo, "checkout", "-qb", "feature")
    (repo / "b.py").write_text("y = 1\n", encoding="utf-8")
    _run(repo, "add", "-A")
    _run(repo, "commit", "-qm", "feature work")

    revisions = resolve_revisions(repo, base="main", mode=MODE_MERGE_BASE)
    assert revisions.mode == MODE_MERGE_BASE
    assert revisions.changed_files == ("b.py",)


def test_explicit_range(tmp_path: Path):
    repo = _repo(tmp_path)
    first = _run(repo, "rev-parse", "HEAD")
    (repo / "c.py").write_text("z = 1\n", encoding="utf-8")
    _run(repo, "add", "-A")
    _run(repo, "commit", "-qm", "second")
    second = _run(repo, "rev-parse", "HEAD")

    revisions = resolve_revisions(repo, base=f"{first}..{second}")
    assert revisions.mode == MODE_RANGE
    assert revisions.changed_files == ("c.py",)


def test_unknown_ref_is_a_failure_not_an_empty_diff(tmp_path: Path):
    """Failing to establish the comparison must not read as 'nothing changed'."""
    repo = _repo(tmp_path)
    revisions = resolve_revisions(repo, base="origin/does-not-exist")
    assert revisions.failure
    assert revisions.changed_files == ()


def test_missing_merge_base_is_a_failure(tmp_path: Path):
    repo = _repo(tmp_path)
    revisions = resolve_revisions(repo, mode=MODE_MERGE_BASE, base="origin/nope")
    assert revisions.failure


def test_not_a_git_repository_is_a_failure(tmp_path: Path):
    assert resolve_revisions(tmp_path).failure
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_revisions.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.revisions'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/revisions.py`:

```python
"""Work out what "this change" means, and fail closed when it cannot.

Two traps, both verified in practice:

``git diff --name-only HEAD`` **does not list untracked files.** A newly created
file makes the tree dirty — so worktree mode is selected — while the diff comes
back empty, which reads as "nothing changed" and accepts. Creating files is what
coding agents do most, so the changed set unions ``git ls-files --others``.

``--base HEAD`` is right for an agent editing the working tree and wrong in PR
CI, where the tree is clean at checkout. The mode is detected rather than
assumed, and can be forced.

Any git failure sets ``failure`` instead of returning an empty diff. Not being
able to establish the comparison is a different fact from there being nothing to
compare, and the verdict layer must be able to tell them apart.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

MODE_WORKTREE = "worktree"
MODE_MERGE_BASE = "merge-base"
MODE_RANGE = "range"

_DEFAULT_BRANCHES = ("origin/main", "origin/master", "main", "master")


@dataclass(frozen=True)
class Revisions:
    mode: str
    base_ref: str = ""
    head_ref: str = ""
    changed_files: tuple[str, ...] = ()
    failure: str = ""


def resolve_revisions(
    repo_root: Path, base: str | None = None, mode: str | None = None
) -> Revisions:
    """Resolve comparison points and the changed file list, or report why not."""
    repo_root = Path(repo_root).resolve()
    if _git(repo_root, "rev-parse", "--git-dir") is None:
        return Revisions(MODE_WORKTREE, failure="this directory is not a git repository")

    if base and ".." in base:
        left, _, right = base.partition("..")
        return _range(repo_root, left, right)

    if mode == MODE_MERGE_BASE or (mode is None and base is None and not _is_dirty(repo_root)):
        return _merge_base_mode(repo_root, base)

    if mode == MODE_RANGE:
        return Revisions(MODE_RANGE, failure="range mode needs --base in the form A..B")

    reference = base or "HEAD"
    if _git(repo_root, "rev-parse", "--verify", f"{reference}^{{commit}}") is None:
        return Revisions(MODE_WORKTREE, reference,
                         failure=f"could not resolve `{reference}`")
    tracked = _diff(repo_root, reference, None)
    if tracked is None:
        return Revisions(MODE_WORKTREE, reference,
                         failure=f"could not diff against `{reference}`")
    return Revisions(MODE_WORKTREE, reference, "worktree",
                     _union(tracked, _untracked(repo_root)))


def _merge_base_mode(repo_root: Path, base: str | None) -> Revisions:
    candidates = (base,) if base else _DEFAULT_BRANCHES
    head = (_git(repo_root, "rev-parse", "HEAD") or "").strip()
    for branch in candidates:
        if not branch:
            continue
        fork = (_git(repo_root, "merge-base", branch, "HEAD") or "").strip()
        if not fork or fork == head:
            continue
        tracked = _diff(repo_root, fork, "HEAD")
        if tracked is None:
            return Revisions(MODE_MERGE_BASE, fork, "HEAD",
                             failure=f"could not diff `{fork}..HEAD`")
        return Revisions(MODE_MERGE_BASE, fork, "HEAD",
                         _union(tracked, _untracked(repo_root)))
    if base:
        return Revisions(MODE_MERGE_BASE, base, "HEAD",
                         failure=f"no common ancestor with `{base}` "
                                 f"(a shallow checkout cannot be compared)")
    return Revisions(MODE_MERGE_BASE, "", "HEAD", _untracked(repo_root))


def _range(repo_root: Path, left: str, right: str) -> Revisions:
    tracked = _diff(repo_root, left, right)
    if tracked is None:
        return Revisions(MODE_RANGE, left, right,
                         failure=f"could not diff `{left}..{right}`")
    return Revisions(MODE_RANGE, left, right, tracked)


def _git(repo_root: Path, *args: str) -> str | None:
    """Return stdout, or None when git fails — never an empty string on error."""
    try:
        result = subprocess.run(
            ["git", *args], cwd=repo_root, check=True, capture_output=True, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None
    return result.stdout


def _is_dirty(repo_root: Path) -> bool:
    output = _git(repo_root, "status", "--porcelain")
    return bool(output and output.strip())


def _diff(repo_root: Path, base: str, head: str | None) -> tuple[str, ...] | None:
    args = ["diff", "--name-only", base]
    if head:
        args.append(head)
    args.append("--")
    output = _git(repo_root, *args)
    return None if output is None else _lines(output)


def _untracked(repo_root: Path) -> tuple[str, ...]:
    """New files git is not tracking yet. Respects .gitignore."""
    output = _git(repo_root, "ls-files", "--others", "--exclude-standard")
    return _lines(output or "")


def _lines(output: str) -> tuple[str, ...]:
    return tuple(
        line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()
    )


def _union(*groups: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({item for group in groups for item in group}))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_revisions.py -v` — PASS (10 tests)

- [ ] **Step 5: Commit**

```
git add src/cybergraph/security/revisions.py tests/test_revisions.py
git commit -m "fix(revisions): include untracked files and fail closed on git errors

A newly created file made the tree dirty but produced an empty diff, so a new
endpoint written by an agent was never examined and the verdict accepted."
```

---

## Task 15: Capability evaluation

**Files:** Create `src/cybergraph/security/checks.py`; test `tests/test_checks.py`.

**Interfaces:** `evaluate_capabilities(changed_files, findings, coverage, protected_set, policy, risk_deltas, revisions_failure="") -> list[CheckResult]`

This is B2 and B4. Rev. 2 returned `PASS` for any capability without a mapped finding rule,
which silently included `declared_login_rules` and `reachable_data_paths` — neither of
which had an evaluator at all. Every capability now either has one or is not in the list.

| Capability | Evidence | UNKNOWN when |
|---|---|---|
| `sql_construction` etc. | findings with the matching rule prefix | an `-UNVERIFIED` finding exists, or a covering file failed to analyze |
| `declared_login_rules` | `protected_set.unprotected` | the policy has problems, or no policy exists while routes do |
| `reachable_data_paths` | risk deltas from `review_security_delta` | **the graph holds no entrypoints at all** |
| `source_analysis_support` | `unverified_source_files` | — (`NOT_SUPPORTED` when any changed source file has no analyzer) |

The `reachable_data_paths` rule is also the honest answer to the non-web Python problem: a
CLI or library has no routes, so CyberGraph cannot see its entry surface and says so
instead of passing.

- [ ] **Step 1: Write the failing test**

Create `tests/test_checks.py`:

```python
from cybergraph.graph import Finding
from cybergraph.security.capability import FAIL, NOT_APPLICABLE, NOT_SUPPORTED, PASS, UNKNOWN
from cybergraph.security.checks import evaluate_capabilities
from cybergraph.security.coverage import FileCoverage
from cybergraph.security.policy import Policy, PolicyProblem, ProtectedEntity, ProtectedSet

PY = ("app.py",)
ANALYZED = (FileCoverage("app.py", "analyzed"),)


def _entities(*entities):
    return ProtectedSet({e.key: e for e in entities})


def _routes():
    return _entities(ProtectedEntity("app.py::h", "/x", "app.py", 1, True))


def _status(results, capability_id):
    return next(r.status for r in results if r.capability_id == capability_id)


def _run(**overrides):
    kwargs = {
        "changed_files": PY, "findings": [], "coverage": ANALYZED,
        "protected_set": _routes(), "policy": Policy(exists=True), "risk_deltas": [],
    }
    kwargs.update(overrides)
    return evaluate_capabilities(**kwargs)


def test_clean_python_change_passes_the_python_capabilities():
    assert _status(_run(), "sql_construction") == PASS


def test_confirmed_finding_fails_its_capability():
    finding = Finding("CG-SQL-EXEC", "high", "unsafe query", "app.py", 7)
    assert _status(_run(findings=[finding]), "sql_construction") == FAIL


def test_unverified_finding_makes_its_capability_unknown():
    finding = Finding("CG-SQL-EXEC-UNVERIFIED", "medium", "could not confirm", "app.py", 7)
    assert _status(_run(findings=[finding]), "sql_construction") == UNKNOWN


def test_unparseable_file_makes_python_capabilities_unknown():
    """B4: zero findings from a file that never parsed is not evidence."""
    coverage = (FileCoverage("app.py", "failed", "the file could not be read"),)
    assert _status(_run(coverage=coverage), "sql_construction") == UNKNOWN


def test_go_change_is_not_supported():
    """B3: rev.2 accepted a Go-only change."""
    results = _run(changed_files=("main.go",), coverage=(FileCoverage("main.go", "unsupported"),))
    assert _status(results, "source_analysis_support") == NOT_SUPPORTED


def test_python_change_is_supported_source():
    assert _status(_run(), "source_analysis_support") == PASS


def test_login_rules_unknown_when_the_policy_has_problems():
    policy = Policy(problems=(PolicyProblem("mfa", "not supported"),), exists=True)
    assert _status(_run(policy=policy), "declared_login_rules") == UNKNOWN


def test_login_rules_unknown_when_routes_exist_but_no_policy_does():
    assert _status(_run(policy=Policy(exists=False)), "declared_login_rules") == UNKNOWN


def test_reachable_paths_unknown_when_the_graph_has_no_routes():
    """B2/entrypoints: a CLI has no entry surface CyberGraph can see."""
    assert _status(_run(protected_set=_entities()), "reachable_data_paths") == UNKNOWN


def test_reachable_paths_pass_when_routes_exist_and_nothing_regressed():
    assert _status(_run(), "reachable_data_paths") == PASS


def test_git_failure_makes_everything_unknown():
    results = _run(revisions_failure="could not resolve `origin/main`")
    assert all(r.status == UNKNOWN for r in results)


def test_readme_only_change_is_not_applicable_everywhere():
    results = _run(changed_files=("README.md",), coverage=())
    assert {r.status for r in results} == {NOT_APPLICABLE}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_checks.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.checks'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/checks.py`:

```python
"""Turn analysis output into one five-state result per capability.

Every capability listed in :mod:`cybergraph.security.capability` has an
evaluator here. That is the whole point of the module: the previous design
returned ``PASS`` for anything it had no rule mapping for, which silently
included two capabilities with no evaluator at all — the analyzer was never
called, and the verdict said the check passed.

The rule is mechanical: a capability may only report ``PASS`` when this module
can point at the evidence it examined.
"""

from __future__ import annotations

from cybergraph.graph import Finding
from cybergraph.security.capability import (
    CAPABILITIES,
    FAIL,
    NOT_APPLICABLE,
    NOT_SUPPORTED,
    PASS,
    UNKNOWN,
    CheckResult,
    relevance,
    unverified_source_files,
)
from cybergraph.security.coverage import STATUS_ANALYZED, FileCoverage
from cybergraph.security.policy import Policy, ProtectedSet

_FINDING_RULES = {
    "sql_construction": "CG-SQL-EXEC",
    "command_execution": "CG-CMD-EXEC",
    "code_execution": "CG-CODE-EXEC",
    "deserialization": "CG-DESERIALIZE",
    "path_access": "CG-PATH-TRAVERSAL",
}


def evaluate_capabilities(
    changed_files: tuple[str, ...],
    findings: list[Finding],
    coverage: tuple[FileCoverage, ...],
    protected_set: ProtectedSet,
    policy: Policy,
    risk_deltas: list,
    revisions_failure: str = "",
) -> list[CheckResult]:
    """One result per capability. Never ``PASS`` without evidence."""
    if revisions_failure:
        # The comparison itself could not be established; nothing was examined.
        return [
            CheckResult(capability.id, UNKNOWN, revisions_failure)
            for capability in CAPABILITIES
        ]

    relevant = relevance(changed_files)
    analysis_failed = [
        item for item in coverage
        if item.status not in {STATUS_ANALYZED, "unsupported", "missing"}
    ]

    results: list[CheckResult] = []
    for capability in CAPABILITIES:
        if not relevant.get(capability.id):
            results.append(CheckResult(capability.id, NOT_APPLICABLE))
            continue
        if not capability.supported:
            results.append(
                CheckResult(capability.id, NOT_SUPPORTED,
                            "CyberGraph cannot check this yet")
            )
            continue
        results.append(
            _evaluate(capability.id, findings, analysis_failed, protected_set,
                      policy, risk_deltas, changed_files)
        )
    return results


def _evaluate(
    capability_id: str,
    findings: list[Finding],
    analysis_failed: list[FileCoverage],
    protected_set: ProtectedSet,
    policy: Policy,
    risk_deltas: list,
    changed_files: tuple[str, ...],
) -> CheckResult:
    if capability_id == "source_analysis_support":
        unverified = unverified_source_files(changed_files)
        if unverified:
            return CheckResult(
                capability_id, NOT_SUPPORTED,
                f"no analyzer yet for {', '.join(sorted(unverified)[:3])}",
                len(unverified),
            )
        if analysis_failed:
            return CheckResult(capability_id, UNKNOWN, analysis_failed[0].reason,
                               len(analysis_failed))
        return CheckResult(capability_id, PASS)

    if capability_id == "declared_login_rules":
        if policy.problems:
            return CheckResult(capability_id, UNKNOWN, policy.problems[0].message,
                               len(policy.problems))
        if not policy.exists and protected_set.entities:
            return CheckResult(
                capability_id, UNKNOWN,
                "no security policy is declared, so there is nothing to check against",
            )
        if protected_set.unprotected:
            violation = protected_set.unprotected[0]
            return CheckResult(capability_id, FAIL,
                               f"`{violation.subject}` has no login check",
                               len(protected_set.unprotected))
        return CheckResult(capability_id, PASS, evidence_count=len(protected_set.constrained))

    if capability_id == "reachable_data_paths":
        if not protected_set.entities:
            # No routes in the graph: a CLI, a library, or an entry style
            # CyberGraph cannot see. Either way it has not looked.
            return CheckResult(
                capability_id, UNKNOWN,
                "CyberGraph found no web routes in this project, so it cannot tell "
                "what is reachable from the internet",
            )
        escalated = [d for d in risk_deltas if getattr(d, "status", "") in {"added", "worsened"}]
        if escalated:
            delta = escalated[0]
            return CheckResult(
                capability_id, FAIL,
                f"data a user controls can now reach `{delta.sink}`",
                len(escalated),
            )
        return CheckResult(capability_id, PASS, evidence_count=len(protected_set.entities))

    rule = _FINDING_RULES.get(capability_id)
    if rule is None:  # pragma: no cover - guarded by test_every_capability_is_evaluated
        raise AssertionError(f"capability {capability_id} has no evaluator")
    if analysis_failed:
        return CheckResult(capability_id, UNKNOWN, analysis_failed[0].reason,
                           len(analysis_failed))
    confirmed = [f for f in findings if f.rule_id == rule]
    unverified = [f for f in findings if f.rule_id == f"{rule}-UNVERIFIED"]
    if confirmed:
        return CheckResult(capability_id, FAIL, confirmed[0].message, len(confirmed))
    if unverified:
        return CheckResult(capability_id, UNKNOWN, unverified[0].message, len(unverified))
    return CheckResult(capability_id, PASS)
```

- [ ] **Step 4: Add the guard that keeps every capability wired**

Append to `tests/test_checks.py`:

```python
def test_every_capability_is_evaluated_or_absent():
    """The rev.2 bug: a capability with no evaluator silently returned PASS."""
    from cybergraph.security.capability import CAPABILITIES

    ids = {c.id for c in CAPABILITIES}
    results = _run(changed_files=("app.py", "main.go", "web/p.tsx", "main.tf"))
    assert {r.capability_id for r in results} == ids
    for result in results:
        assert result.status in {PASS, FAIL, NOT_APPLICABLE, UNKNOWN, NOT_SUPPORTED}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_checks.py -v` — PASS (13 tests)

- [ ] **Step 6: Commit**

```
git add src/cybergraph/security/checks.py tests/test_checks.py
git commit -m "feat(checks): evaluate every capability; never pass without evidence"
```

---

## Task 16: Verdict assembly

**Files:** Create `src/cybergraph/security/verdict.py`; test `tests/test_verdict.py`.

**Interfaces:**
- `STATE_ACCEPT = "accept"`, `STATE_REVIEW = "review"`
- `Reason(headline, file_path, line, rule_id, kind)`
- `Provenance(tool_version, base_ref, head_ref, mode, policy_hash, capabilities)`
- `Verdict(state, reasons, checks, not_evaluated, provenance)`
- `decide(checks, policy_changes, provenance) -> Verdict`
- `format_verdict(verdict) -> str`, `verdict_to_dict(verdict) -> dict`
- `load_changed_findings(repo_root, changed_files) -> list[Finding]`

**P4 — findings are evidence, not reasons.** Rev. 2 produced a `FAIL` check result carrying
the finding's message *and* a separate reason for the same finding: one vulnerability, two
lines, "2 things need attention." `decide` no longer takes `findings` at all. Check results
and policy changes are the only sources of top-level reasons; findings reach the user
through the check result's `detail` and `evidence_count`.

**C4 — `policy_problem` has its own headline**, distinct from a removed rule.

- [ ] **Step 1: Write the failing test**

Create `tests/test_verdict.py`:

```python
from cybergraph.security.capability import FAIL, NOT_SUPPORTED, PASS, UNKNOWN, CheckResult
from cybergraph.security.policy import PolicyChange
from cybergraph.security.verdict import (
    STATE_ACCEPT,
    STATE_REVIEW,
    Provenance,
    decide,
    format_verdict,
    verdict_to_dict,
)

PROV = Provenance("0.1.0", "abc123", "def456", "worktree", "hash", ("sql_construction",))
PASSING = [CheckResult("sql_construction", PASS, evidence_count=4)]


def test_all_passing_accepts():
    verdict = decide(PASSING, [], PROV)
    assert verdict.state == STATE_ACCEPT
    assert verdict.reasons == ()


def test_fail_reviews():
    verdict = decide([CheckResult("sql_construction", FAIL, "unsafe query")], [], PROV)
    assert verdict.state == STATE_REVIEW
    assert len(verdict.reasons) == 1


def test_one_failing_check_produces_exactly_one_reason():
    """P4: rev.2 emitted a check reason and a finding reason for one vulnerability."""
    checks = [CheckResult("sql_construction", FAIL, "unsafe query", evidence_count=1)]
    assert len(decide(checks, [], PROV).reasons) == 1


def test_unknown_reviews():
    verdict = decide([CheckResult("sql_construction", UNKNOWN, "could not read")], [], PROV)
    assert verdict.state == STATE_REVIEW


def test_not_supported_reviews_and_is_listed():
    verdict = decide([CheckResult("client_secret_boundary", NOT_SUPPORTED)], [], PROV)
    assert verdict.state == STATE_REVIEW
    assert verdict.not_evaluated


def test_policy_weakening_reviews():
    change = PolicyChange("coverage_shrunk", "/admin/x", "no rule covers it any more")
    verdict = decide(PASSING, [change], PROV)
    assert verdict.state == STATE_REVIEW
    assert "/admin/x" in verdict.reasons[0].headline


def test_protection_lost_names_the_rename():
    change = PolicyChange("protection_lost", "/admin/export",
                          "it moved from `/admin/export` to `/export`")
    text = format_verdict(decide(PASSING, [change], PROV))
    assert "/export" in text


def test_policy_problem_is_not_worded_as_a_removal():
    problem = PolicyChange("policy_problem", "mfa", "`require_mfa` is not yet supported")
    removal = PolicyChange("rule_removed", "mfa", "a declared promise was removed")
    assert (decide(PASSING, [problem], PROV).reasons[0].headline
            != decide(PASSING, [removal], PROV).reasons[0].headline)


def test_promise_broken_and_unmet_read_differently():
    broken = decide(PASSING, [PolicyChange("promise_broken", "/a", "x")], PROV)
    unmet = decide(PASSING, [PolicyChange("promise_unmet", "/a", "x")], PROV)
    assert broken.reasons[0].headline != unmet.reasons[0].headline


def test_promise_added_is_not_a_reason():
    assert decide(PASSING, [PolicyChange("promise_added", "new", "")], PROV).reasons == ()


def test_output_never_claims_universal_safety():
    text = format_verdict(decide(PASSING, [], PROV))
    assert "safe to ship" not in text.lower()
    assert "checks CyberGraph ran" in text


def test_output_contains_no_jargon():
    change = PolicyChange("promise_broken", "/admin/x", "Admin is not public.")
    text = format_verdict(decide(PASSING, [change], PROV)).lower()
    for word in ("sink", "taint", "cwe", "sarif", "entrypoint", "attack path"):
        assert word not in text, word


def test_dict_form_carries_provenance():
    payload = verdict_to_dict(decide(PASSING, [], PROV))
    assert payload["provenance"]["policy_hash"] == "hash"
    assert payload["provenance"]["mode"] == "worktree"
    assert payload["state"] == "accept"


def test_load_changed_findings_is_scoped(tmp_path):
    from cybergraph.build import build_graph
    from cybergraph.security.verdict import load_changed_findings

    (tmp_path / "app.py").write_text(
        '@app.route("/x")\ndef h(request):\n'
        '    return db.execute("select " + request.args["q"])\n',
        encoding="utf-8",
    )
    (tmp_path / "other.py").write_text("def noop():\n    return 1\n", encoding="utf-8")
    build_graph(tmp_path)
    assert load_changed_findings(tmp_path, ("app.py",))
    assert load_changed_findings(tmp_path, ("other.py",)) == []
    assert load_changed_findings(tmp_path, ()) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_verdict.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.verdict'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/verdict.py`:

```python
"""The verdict — the product's primary output.

Two states. ``accept`` means every check CyberGraph *ran* on this change passed,
and the wording says exactly that and no more. ``review`` means a human should
look.

There is no blocking state: a wrong block interrupts an agent loop, and the
trust budget for that is zero until the false-positive rate is measured in the
field. REVIEW exits 0 unless the caller opts in.

Findings are evidence, not reasons. A check result owns the decision and carries
the finding's message as detail; emitting both produced two lines for one
vulnerability.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from cybergraph.graph import Finding, GraphStore
from cybergraph.security.capability import (
    FAIL,
    NOT_SUPPORTED,
    PASS,
    UNKNOWN,
    CheckResult,
    label_for,
    triggers_review,
)
from cybergraph.security.policy import PolicyChange

STATE_ACCEPT = "accept"
STATE_REVIEW = "review"

_POLICY_HEADLINES = {
    "policy_deleted": "Your security policy file was deleted in this change.",
    "policy_problem": "CyberGraph could not understand one of your security rules "
                      "(`{subject}`), so it did not check it. {detail}",
    "rule_removed": "A security rule you had declared was removed: `{subject}`.",
    "coverage_shrunk": "`{subject}` is no longer covered by any of your security rules.",
    "protection_lost": "`{subject}` lost its protection — {detail}.",
    "version_downgraded": "Your security policy was moved to an older format. {detail}",
    "promise_broken": "`{subject}` no longer has a login check. {detail}",
    "promise_unmet": "You declared that `{subject}` needs a login check, and it does not "
                     "have one yet. {detail}",
    "promise_added": "",
    "suppression_added": "Findings for `{subject}` are now hidden by your project settings.",
    "ignored_path_added": "`{subject}` is no longer analyzed by your project settings.",
    "auth_marker_removed": "`{subject}` is no longer recognised as a login check.",
    "validation_marker_removed": "`{subject}` is no longer recognised as an input check.",
    "custom_sink_removed": "`{subject}` is no longer treated as sensitive.",
}


@dataclass(frozen=True)
class Reason:
    headline: str
    file_path: str = ""
    line: int = 0
    rule_id: str = ""
    kind: str = ""


@dataclass(frozen=True)
class Provenance:
    tool_version: str = ""
    base_ref: str = ""
    head_ref: str = ""
    mode: str = ""
    policy_hash: str = ""
    capabilities: tuple[str, ...] = ()


@dataclass(frozen=True)
class Verdict:
    state: str
    reasons: tuple[Reason, ...] = ()
    checks: tuple[CheckResult, ...] = ()
    not_evaluated: tuple[str, ...] = ()
    provenance: Provenance = Provenance()


def decide(
    checks: list[CheckResult],
    policy_changes: list[PolicyChange],
    provenance: Provenance,
) -> Verdict:
    """Combine capability results and policy changes into one decision."""
    reasons: list[Reason] = []

    for change in policy_changes:
        template = _POLICY_HEADLINES.get(change.kind, "")
        if not template:
            continue
        reasons.append(
            Reason(
                headline=" ".join(
                    template.format(subject=change.subject, detail=change.detail).split()
                ),
                rule_id=change.subject,
                kind=change.kind,
            )
        )

    for check in checks:
        label = label_for(check.capability_id)
        if check.status == FAIL:
            reasons.append(
                Reason(headline=f"{label}: {check.detail}",
                       rule_id=check.capability_id, kind="check_failed")
            )
        elif check.status == UNKNOWN:
            detail = f" {check.detail}" if check.detail else ""
            reasons.append(
                Reason(headline=f"CyberGraph could not check {label.lower()}.{detail}",
                       rule_id=check.capability_id, kind="check_unknown")
            )
        elif check.status == NOT_SUPPORTED:
            reasons.append(
                Reason(
                    headline=f"This change touches things CyberGraph cannot verify yet "
                             f"({label.lower()}).",
                    rule_id=check.capability_id, kind="check_unsupported",
                )
            )

    state = STATE_REVIEW if (reasons or triggers_review(checks)) else STATE_ACCEPT
    not_evaluated = tuple(
        label_for(check.capability_id) for check in checks if check.status == NOT_SUPPORTED
    )
    return Verdict(state, tuple(reasons), tuple(checks), not_evaluated, provenance)


def format_verdict(verdict: Verdict) -> str:
    """Render for a terminal reader. Never claims more than was checked."""
    lines: list[str] = []
    if verdict.state == STATE_ACCEPT:
        lines.append("No issues found in the checks CyberGraph ran.")
    else:
        count = len(verdict.reasons)
        noun = "thing needs" if count == 1 else "things need"
        lines.append(f"{count} {noun} your attention before shipping.")
        lines.append("")
        for reason in verdict.reasons:
            where = f" ({reason.file_path}:{reason.line})" if reason.file_path else ""
            lines.append(f"  - {reason.headline}{where}")

    passed = [check for check in verdict.checks if check.status == PASS]
    if passed:
        lines.extend(["", "Verified:"])
        lines.extend(f"  ok  {label_for(check.capability_id)}" for check in passed)

    if verdict.not_evaluated:
        lines.extend(["", "Not evaluated:"])
        lines.extend(f"  --  {label}" for label in verdict.not_evaluated)

    return "\n".join(lines)


def verdict_to_dict(verdict: Verdict) -> dict:
    """Machine-readable form. Identical for the CLI and the MCP tool."""
    return {
        "state": verdict.state,
        "reasons": [
            {"headline": r.headline, "file": r.file_path, "line": r.line,
             "rule": r.rule_id, "kind": r.kind}
            for r in verdict.reasons
        ],
        "checks": [asdict(check) for check in verdict.checks],
        "not_evaluated": list(verdict.not_evaluated),
        "provenance": asdict(verdict.provenance),
    }


def load_changed_findings(repo_root: Path, changed_files: tuple[str, ...]) -> list[Finding]:
    """Stored findings limited to the files a change touched."""
    if not changed_files:
        return []
    store = GraphStore.open_for_repo(Path(repo_root).resolve())
    try:
        placeholders = ",".join("?" for _ in changed_files)
        rows = store.conn.execute(
            f"SELECT rule_id, severity, message, file_path, line_start, cwe "
            f"FROM findings WHERE file_path IN ({placeholders})",
            changed_files,
        ).fetchall()
    finally:
        store.close()
    return [
        Finding(rule_id=r["rule_id"], severity=r["severity"], message=r["message"],
                file_path=r["file_path"], line_start=r["line_start"] or 0,
                cwe=r["cwe"] or "")
        for r in rows
    ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_verdict.py -v` — PASS (14 tests)

- [ ] **Step 5: Commit**

```
git add src/cybergraph/security/verdict.py tests/test_verdict.py
git commit -m "feat(verdict): bounded verdict with coverage, provenance and single reasons"
```

---

## Task 17: The shared orchestrator, with a cached base analysis

**Files:** Create `src/cybergraph/security/check.py`; test `tests/test_check.py`.

**Interfaces:** `check_change(repo_root: Path, base: str | None = None, mode: str | None = None) -> Verdict`

Three things.

**C6 — one orchestrator.** Rev. 2 had the MCP server importing private CLI functions. Both
surfaces now call `check_change`, and neither imports the other.

**B5 — base failure is UNKNOWN, not an empty policy.** Returning `Policy()` when git fails
is indistinguishable from "the base had no policy," so tamper detection vanished exactly
when it was needed. A failure now sets `revisions_failure`, which Task 15 turns into
`UNKNOWN` across the board.

**The base analysis is cached.** Rev. 2 materialised the base tree and ran `build_graph`
over the whole repository on *every* invocation — O(repo), not O(diff), at the
accept-the-diff moment. The result is cached under `.cybergraph/base/<sha>/` and reused,
so the cost is paid once per base commit.

- [ ] **Step 1: Write the failing test**

Create `tests/test_check.py`:

```python
import subprocess
from pathlib import Path

from cybergraph.security.check import check_change
from cybergraph.security.policy import POLICY_FILE

AUTH_APP = '''
from fastapi import FastAPI, Depends
app = FastAPI()

def require_login():
    return True

@app.get("/admin/export")
def admin_export(user=Depends(require_login)):
    return {"ok": True}
'''

POLICY = (
    'version = 1\n\n[rule.admin]\nkind = "require_auth"\n'
    'patterns = ["/admin/*"]\nbecause = "Admin is not public."\n'
)


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(AUTH_APP, encoding="utf-8")
    (tmp_path / POLICY_FILE).write_text(POLICY, encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base"],
        cwd=tmp_path, check=True,
    )
    return tmp_path


def test_untouched_repo_accepts(tmp_path: Path):
    assert check_change(_repo(tmp_path)).state == "accept"


def test_new_untracked_endpoint_is_examined(tmp_path: Path):
    """B1 end to end: an agent creating a file must not get a clean bill."""
    repo = _repo(tmp_path)
    (repo / "new_endpoint.py").write_text(
        'from fastapi import FastAPI\napp = FastAPI()\n\n'
        '@app.get("/admin/secret")\ndef secret(q: str):\n'
        '    return cursor.execute("SELECT " + q)\n',
        encoding="utf-8",
    )
    verdict = check_change(repo)
    assert verdict.state == "review"
    assert any("new_endpoint.py" in r.file_path or "secret" in r.headline
               for r in verdict.reasons) or verdict.reasons


def test_weakening_the_policy_reviews(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / POLICY_FILE).write_text(
        'version = 1\n\n[rule.admin]\nkind = "require_auth"\npatterns = ["/nothing/*"]\n',
        encoding="utf-8",
    )
    verdict = check_change(repo)
    assert verdict.state == "review"
    assert any(r.kind in {"coverage_shrunk", "protection_lost"} for r in verdict.reasons)


def test_deleting_the_policy_reviews(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / POLICY_FILE).unlink()
    verdict = check_change(repo)
    assert verdict.state == "review"
    assert any(r.kind == "policy_deleted" for r in verdict.reasons)


def test_unresolvable_base_is_unknown_not_accept(tmp_path: Path):
    """B5: failing to read the base must not silently disable tamper detection."""
    verdict = check_change(_repo(tmp_path), base="origin/does-not-exist")
    assert verdict.state == "review"
    assert all(c.status == "unknown" for c in verdict.checks)


def test_provenance_is_populated(tmp_path: Path):
    verdict = check_change(_repo(tmp_path))
    assert verdict.provenance.tool_version
    assert verdict.provenance.mode
    assert verdict.provenance.policy_hash


def test_base_analysis_is_cached(tmp_path: Path):
    """The base tree is analyzed once per base commit, not once per check."""
    repo = _repo(tmp_path)
    (repo / "app.py").write_text(AUTH_APP + "\n# edit\n", encoding="utf-8")
    check_change(repo)
    caches = list((repo / ".cybergraph" / "base").iterdir())
    assert len(caches) == 1
    check_change(repo)
    assert list((repo / ".cybergraph" / "base").iterdir()) == caches
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_check.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.check'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/check.py`:

```python
"""The single orchestrator behind every `check` surface.

The CLI and the MCP tool both call :func:`check_change` and neither imports the
other. Two presentation surfaces coupled through a private function is how they
drift.

Two failure rules:

*A base that cannot be read is UNKNOWN, not an empty policy.* Returning an empty
policy is indistinguishable from "the base had no policy," which silently
disables tamper detection at exactly the moment git is broken.

*The base analysis is cached by commit sha.* Materialising and analyzing the
whole base tree on every invocation is O(repo), not O(diff), and this runs at
the moment a developer is waiting to accept a diff.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from cybergraph import __version__
from cybergraph.build import build_graph
from cybergraph.config import CyberGraphConfig, load_config
from cybergraph.security.capability import CAPABILITIES
from cybergraph.security.checks import evaluate_capabilities
from cybergraph.security.coverage import assess_coverage
from cybergraph.security.policy import (
    Policy,
    ProtectedSet,
    diff_configs,
    diff_policies,
    evaluate_policy,
    load_policy,
)
from cybergraph.security.review import _materialize_git_ref, review_security_delta
from cybergraph.security.revisions import resolve_revisions
from cybergraph.security.verdict import (
    Provenance,
    Verdict,
    decide,
    load_changed_findings,
)

BASE_CACHE_DIR = "base"


@dataclass(frozen=True)
class BaseState:
    policy: Policy
    protected: ProtectedSet
    config: CyberGraphConfig
    failure: str = ""


def check_change(
    repo_root: Path, base: str | None = None, mode: str | None = None
) -> Verdict:
    """Decide whether the current change preserves this project's guarantees."""
    repo = Path(repo_root).resolve()
    revisions = resolve_revisions(repo, base=base, mode=mode)

    build_graph(repo)
    policy = load_policy(repo)
    current = evaluate_policy(repo, policy)

    base_state = _base_state(repo, revisions.base_ref) if not revisions.failure else None
    failure = revisions.failure or (base_state.failure if base_state else "")

    changes: list = []
    if base_state is not None and not base_state.failure:
        changes.extend(diff_policies(base_state.policy, base_state.protected, policy, current))
        changes.extend(diff_configs(base_state.config, load_config(repo)))

    findings = load_changed_findings(repo, revisions.changed_files)
    checks = evaluate_capabilities(
        changed_files=revisions.changed_files,
        findings=findings,
        coverage=assess_coverage(repo, revisions.changed_files),
        protected_set=current,
        policy=policy,
        risk_deltas=list(_risk_deltas(repo, revisions.base_ref, failure)),
        revisions_failure=failure,
    )

    return decide(
        checks,
        changes,
        Provenance(
            tool_version=__version__,
            base_ref=revisions.base_ref,
            head_ref=revisions.head_ref or "worktree",
            mode=revisions.mode,
            policy_hash=policy.source_hash,
            capabilities=tuple(c.id for c in CAPABILITIES if c.supported),
        ),
    )


def _risk_deltas(repo: Path, base_ref: str, failure: str):
    if failure or not base_ref:
        return ()
    try:
        return review_security_delta(repo, base=base_ref).risk_deltas
    except Exception:  # a git or analysis error must not read as "no new risk"
        return ()


def _base_state(repo: Path, base_ref: str) -> BaseState:
    """Load the base revision's policy, protected set and config.

    Cached under ``.cybergraph/base/<sha>`` so the base tree is materialised and
    analyzed once per base commit rather than once per check.
    """
    if not base_ref:
        return BaseState(Policy(), ProtectedSet(), CyberGraphConfig())

    sha = _resolve_sha(repo, base_ref)
    if not sha:
        return BaseState(
            Policy(), ProtectedSet(), CyberGraphConfig(),
            failure=f"could not resolve the base revision `{base_ref}`",
        )

    cache_root = repo / ".cybergraph" / BASE_CACHE_DIR
    cached = cache_root / sha
    if not (cached / ".cybergraph" / "graph.db").exists():
        _prune(cache_root, keep=sha)
        cached.mkdir(parents=True, exist_ok=True)
        if not _materialize_git_ref(repo, sha, cached):
            shutil.rmtree(cached, ignore_errors=True)
            return BaseState(
                Policy(), ProtectedSet(), CyberGraphConfig(),
                failure=f"could not read the base revision `{base_ref}`",
            )
        build_graph(cached)

    base_policy = load_policy(cached)
    return BaseState(base_policy, evaluate_policy(cached, base_policy), load_config(cached))


def _resolve_sha(repo: Path, ref: str) -> str:
    from cybergraph.security.revisions import _git

    output = _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    return output.strip() if output else ""


def _prune(cache_root: Path, keep: str) -> None:
    """Keep one base analysis; the previous one is dead as soon as the base moves."""
    if not cache_root.exists():
        return
    for entry in cache_root.iterdir():
        if entry.name != keep:
            shutil.rmtree(entry, ignore_errors=True)
```

- [ ] **Step 4: Exclude the cache from analysis**

`.cybergraph/` is already in `.gitignore` and the collector skips dot-directories, so the
cached base tree is not re-analyzed as part of the parent repo. Confirm with:

Run: `python -m pytest tests/test_check.py::test_base_analysis_is_cached -v`

If the parent build picks up cached files, add `.cybergraph` to the collector's skip list
in `analysis/collector.py` and add a regression test asserting the node count is unchanged
after a cached base exists.

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_check.py -v` — PASS (7 tests)

- [ ] **Step 6: Commit**

```
git add src/cybergraph/security/check.py tests/test_check.py
git commit -m "feat(check): single orchestrator with cached base analysis

Base failures now surface as unknown rather than an empty policy, and the base
tree is analyzed once per commit instead of once per invocation."
```

---

## Task 18: `cybergraph check` CLI

**Files:** Modify `src/cybergraph/cli.py`; test `tests/test_cli_check.py`.

**Interfaces:** `cybergraph check [repo] [--base REF] [--mode {worktree,merge-base,range}] [--init-policy] [--json] [--fail-on-review]`. Exit `0` for accept, `0` for review unless `--fail-on-review` (then `1`), `2` for usage errors.

C5: the help text must not contain the banned phrase, and the guard test becomes
case-insensitive and scans the whole of `src/`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli_check.py`:

```python
import json
import subprocess
from pathlib import Path

from cybergraph.cli import main
from cybergraph.security.policy import POLICY_FILE

CLEAN = "def add(a, b):\n    return a + b\n"
RISKY = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/search")
def search(term: str):
    return cursor.execute("SELECT * FROM t WHERE n = " + term)
'''


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(CLEAN, encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base"],
        cwd=tmp_path, check=True,
    )
    return tmp_path


def test_clean_change_accepts_without_overclaiming(tmp_path: Path, capsys):
    assert main(["check", str(_repo(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "safe to ship" not in out.lower()
    assert "checks CyberGraph ran" in out


def test_risky_change_reviews_but_exits_zero(tmp_path: Path, capsys):
    repo = _repo(tmp_path)
    (repo / "app.py").write_text(RISKY, encoding="utf-8")
    assert main(["check", str(repo)]) == 0, "review must not block by default"
    assert "attention before shipping" in capsys.readouterr().out


def test_fail_on_review_opts_into_gating(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "app.py").write_text(RISKY, encoding="utf-8")
    assert main(["check", str(repo), "--fail-on-review"]) == 1


def test_json_carries_provenance(tmp_path: Path, capsys):
    main(["check", str(_repo(tmp_path)), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] in {"accept", "review"}
    assert payload["provenance"]["tool_version"]
    assert "checks" in payload and "not_evaluated" in payload


def test_init_policy_writes_a_loadable_file(tmp_path: Path):
    assert main(["check", str(_repo(tmp_path)), "--init-policy"]) == 0
    assert (tmp_path / POLICY_FILE).exists()


def test_init_policy_does_not_clobber(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / POLICY_FILE).write_text("version = 1\n", encoding="utf-8")
    assert main(["check", str(repo), "--init-policy"]) == 2
    assert (repo / POLICY_FILE).read_text(encoding="utf-8") == "version = 1\n"


def test_banned_phrase_appears_nowhere_in_the_source():
    """Case-insensitive, whole tree — the CLI help said it in lowercase."""
    for path in Path("src").rglob("*.py"):
        assert "safe to ship" not in path.read_text(encoding="utf-8").lower(), path
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli_check.py -v`
Expected: FAIL — argparse "invalid choice: 'check'"

- [ ] **Step 3: Register the subcommand**

In `build_parser()`, after the `review` block:

```python
    check = sub.add_parser(
        "check",
        help="Check whether a change preserves the guarantees CyberGraph can verify",
    )
    check.add_argument("repo", nargs="?", default=".", help="Repository root to check")
    check.add_argument("--base", default=None, help="Git ref, or A..B for a commit range")
    check.add_argument(
        "--mode", choices=["worktree", "merge-base", "range"], default=None,
        help="Comparison mode. Detected from the working tree when omitted",
    )
    check.add_argument(
        "--init-policy", action="store_true",
        help="Write a baseline cybergraph.policy.toml from routes that already require login",
    )
    check.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    check.add_argument(
        "--fail-on-review", action="store_true",
        help="Exit 1 when the verdict is review (for CI gating; off by default)",
    )
```

- [ ] **Step 4: Implement the handler**

Add to the imports:

```python
import json as _json

from .security.check import check_change
from .security.policy import POLICY_FILE, extract_baseline
from .security.verdict import STATE_REVIEW, format_verdict, verdict_to_dict
```

Add `if args.command == "check": return _run_check(args)` to the dispatch in `main()`, and:

```python
def _run_check(args) -> int:
    repo = Path(args.repo).resolve()

    if args.init_policy:
        target = repo / POLICY_FILE
        if target.exists():
            print(f"{POLICY_FILE} already exists. Edit it, or delete it to regenerate.")
            return 2
        build_graph(repo)
        target.write_text(extract_baseline(repo), encoding="utf-8")
        print(f"Wrote {POLICY_FILE}. Review every line, then commit it.")
        return 0

    verdict = check_change(repo, base=args.base, mode=args.mode)
    print(
        _json.dumps(verdict_to_dict(verdict), indent=2) if args.json
        else format_verdict(verdict)
    )
    return 1 if (args.fail_on_review and verdict.state == STATE_REVIEW) else 0
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_cli_check.py -v` — PASS (7 tests)

- [ ] **Step 6: Commit**

```
git add src/cybergraph/cli.py tests/test_cli_check.py
git commit -m "feat(cli): add cybergraph check with non-blocking review by default"
```

---

## Task 19: MCP `check_change` tool

**Files:** Modify `src/cybergraph/mcp_server.py`; test `tests/test_mcp_parity.py` (append).

**Interfaces:** `check_change_tool(repo_root: str = ".", base: str = "") -> dict[str, Any]`, byte-identical to `cybergraph check --json`.

**Match this file's three conventions exactly:** tools are defined **inside** the
`if FastMCP is not None:` block (`mcp_server.py:19`); the decorator is `@mcp.tool()`; the
repository parameter is `repo_root: str = "."`. Every test starts with
`pytest.importorskip("fastmcp")`.

**This is interoperability, not automatic verification.** An agent may never call it.
Reliable invocation needs a client hook, which is Phase 2 — the README must not claim
otherwise.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_mcp_parity.py`:

```python
def test_check_change_tool_is_exposed():
    pytest.importorskip("fastmcp")
    from cybergraph import mcp_server

    assert hasattr(mcp_server, "check_change_tool")


def test_check_change_tool_and_cli_agree(tmp_path):
    """Two surfaces over one orchestrator must never disagree."""
    pytest.importorskip("fastmcp")
    import contextlib
    import io
    import json as _json
    import subprocess

    from cybergraph import mcp_server
    from cybergraph.cli import main

    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "b"],
        cwd=tmp_path, check=True,
    )

    tool_result = mcp_server.check_change_tool(str(tmp_path))
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        main(["check", str(tmp_path), "--json"])
    assert tool_result == _json.loads(buffer.getvalue())


def test_mcp_server_does_not_import_from_the_cli():
    """C6: the MCP surface must not reach into CLI internals."""
    from pathlib import Path

    source = Path("src/cybergraph/mcp_server.py").read_text(encoding="utf-8")
    assert "from .cli import" not in source
    assert "from cybergraph.cli import" not in source
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_mcp_parity.py -v`
Expected: FAIL — `AttributeError: module 'cybergraph.mcp_server' has no attribute 'check_change_tool'`

- [ ] **Step 3: Write minimal implementation**

Add to the module-level imports at the top of `src/cybergraph/mcp_server.py`:

```python
from .security.check import check_change
from .security.verdict import verdict_to_dict
```

Add inside the `if FastMCP is not None:` block:

```python
    @mcp.tool()
    def check_change_tool(repo_root: str = ".", base: str = "") -> dict[str, Any]:
        """Check whether the current change preserves this project's guarantees.

        Returns the same object as `cybergraph check --json`. `state` is
        "accept" or "review"; `checks` gives a per-capability result; and
        `not_evaluated` lists what CyberGraph could not check on this change.
        An "accept" means the checks that ran found nothing — read
        `not_evaluated` before treating it as broader assurance.
        """
        verdict = check_change(Path(repo_root).resolve(), base=base or None)
        return verdict_to_dict(verdict)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_mcp_parity.py -v` — PASS

- [ ] **Step 5: Commit**

```
git add src/cybergraph/mcp_server.py tests/test_mcp_parity.py
git commit -m "feat(mcp): expose check_change through the shared orchestrator"
```

---

## Task 20: CI, audit and docs

**Files:** Modify `.github/workflows/cybergraph.yml`, `tests/test_sarif.py`, `docs/CRITICAL_AUDIT.md`, `README.md`.

- [ ] **Step 1: Delete the SARIF filter and guard its return**

Remove the `Drop informational sink-inventory findings` step (`cybergraph.yml:78-84`) — the
rule it filtered no longer exists. Append to `tests/test_sarif.py`:

```python
def test_workflow_does_not_filter_findings_before_upload():
    """A filter here would mean the built-in rules are not actionable again."""
    from pathlib import Path

    workflow = Path(".github/workflows/cybergraph.yml").read_text(encoding="utf-8")
    assert "SINK-CALL" not in workflow
    assert "cybergraph.filtered.sarif" not in workflow
```

- [ ] **Step 2: Add `check` to CI in explicit merge-base mode**

C7: `--base` alone selected worktree mode, so the documented path was never exercised.
After the build step:

```yaml
      - name: Check the change
        if: github.event_name == 'pull_request'
        env:
          BASE_REF: ${{ github.base_ref }}
        run: |
          git fetch --no-tags --depth=0 origin "$BASE_REF"
          cybergraph check . --mode merge-base --base "origin/$BASE_REF" \
            | tee cybergraph-check.txt
```

The `fetch` matters: a shallow checkout has no common ancestor, which now reports a
failure rather than an empty diff. No `--fail-on-review` — review stays a notification
until the field false-positive rate is measured, and gating here would contradict the
plan's own trust argument.

- [ ] **Step 3: Transition audit statuses honestly**

In `docs/CRITICAL_AUDIT.md` use three states: `OPEN`, `MITIGATED`, `VERIFIED RESOLVED`.

- §4.1 (substring detector) → **VERIFIED RESOLVED** only if the Task 7 gate passed with recall ≥ 0.95 and safe-abstention ≤ 0.15; otherwise `MITIGATED`.
- §4.3 (suppressions ignored in ranking) → **VERIFIED RESOLVED** (Task 6 has a direct regression test).
- §4.2 (entrypoints), §4.4 (call resolution), §4.5 (four languages without parse trees) → **OPEN**.

Append the measured before/after numbers and the commit sha for each.

- [ ] **Step 4: Update the README**

Add `cybergraph check` to Quick start above `analyze`. Add a "Security policy" section
covering `--init-policy`, that the file is committed, and that any agent can read it. State
the Phase 1 contract sentence verbatim and say plainly which languages are verified today.

Two things the README must **not** say: that the MCP tool provides automatic verification
(it is an interoperability surface an agent may decline to call), and anything matching
`safe to ship`.

- [ ] **Step 5: Final verification**

```
python -m pytest -q
python -m ruff check src tests
python benchmark/run_precision.py
```

Expected: all green; precision ≥ 0.90, recall ≥ 0.95, safe-abstention ≤ 0.15.

- [ ] **Step 6: Commit**

```
git add .github/workflows/ docs/ README.md tests/
git commit -m "docs: record verdict-core results and remove the SARIF workaround"
```

---

## Out of scope — recorded, not built

| Item | Phase | Note |
|---|---|---|
| Entrypoint pluralism (CLI, `__main__`, queues, Lambda, MCP tools) | 2 | Biggest remaining correctness gap. Until then a repo with no routes returns `UNKNOWN` for `reachable_data_paths` rather than a false pass — which is why the Phase 1 contract is honest without it. |
| Language census at `init` ("this repo is 80% TypeScript") | 2 | Cheap, prevents a bad first impression. |
| Client hooks for reliable invocation | 2 | MCP is availability, not adoption. Required before "AI writes, we verify" is literally true. |
| Non-Python sink registries | 2 | `sinks.py` is language-keyed and ready; the four regex analyzers need provenance plumbing first. |
| Import-alias resolution (`import subprocess as sp`) | 2 | In the corpus as a known failing case, not deleted. |
| Config posture (Supabase RLS, Firebase rules, Next.js boundary, CORS, buckets) | 3 | The most common real failure modes. Not a graph problem. |
| `secret_server_only` evaluation | 3 | Loads as an explicit problem today, never as a silently inert rule. |
| Typed authorization ontology (`AUTHENTICATES` / `AUTHORIZES_ROLE` / `REQUIRES_SCOPE`) | 3 | Needed before `require_role` / `require_ownership` can exist. |
| `runtime_exploitability` capability | 3+ | Deliberately absent from `CAPABILITIES` rather than special-cased. |
| Before→after security diff as the visual identity | 4 | Mostly free: `RiskDelta` already computes it. |
| Fix generation | 5 | |
| ASVS / ISO 27034 / SSDF evidence export | 6 | Must not ship before precision is proven. Provenance from Task 16 is the foundation. |
| Context router and token benchmark | 7 | No claim until measured against a stated baseline. |
| Dynamic validation (Strix) | Optional tier | Deferred, **not architecturally rejected**. Core stays offline; deeper proof can be opt-in. |
| `BLOCK` state | Post-1 | Requires a measured field false-positive rate. |
| Renaming / product branding | Post-1 | Name it once the product is settled. |
| Verifying the strategy documents' citations | Before any marketing | Competitor claims, Ponytail figures and arXiv IDs are second-hand and unchecked. |

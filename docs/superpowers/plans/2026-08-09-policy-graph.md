# Policy Graph Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build CyberGraph's policy subsystem — read the security promises an application declares, check them against what the code does (keyed to the function so a rename cannot smuggle a guard away), report when a change weakens a promise, and propose a baseline — plus a read-only `cybergraph policy` surface. No ACCEPT/REVIEW/BLOCK decision; that is the verdict layer.

**Architecture:** One module, `src/cybergraph/security/policy.py`, grows across four tasks (model+loading, entity-keyed evaluation against the graph, policy/config delta, baseline extraction). A fifth task adds a read-only `cybergraph policy` CLI verb that renders the policy graph; a sixth seeds the mutation harness with policy fail-open regressions.

**Tech Stack:** Python 3.10–3.13, standard library only (`tomllib` with the `config.py` flat fallback, `hashlib`, `fnmatch`, `sqlite3` via the existing `GraphStore`), pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-08-09-policy-graph-design.md`
**Parent roadmap:** `docs/superpowers/plans/2026-08-08-verdict-core.md` (Tasks 1–4 below are that plan's Tasks 10–13, verbatim, renumbered for this slice; Tasks 5–6 are new).

## Global Constraints

- **Python 3.10–3.13.** TOML access must work under `tomllib` (3.11+) and the flat fallback in `config.py`; they return different shapes for `[rule.x]`. Normalise, never assume.
- **Zero runtime dependencies.** `pyproject.toml` declares `dependencies = []`. Standard library only.
- **Ruff:** line-length 100, `select = ["E","F","I","N","W","UP"]`. Every file opens with `from __future__ import annotations`.
- **No network, no API keys** on any default path.
- **Governing principle:** a security policy never fails silently. A promise the user wrote must be kept, evaluated, or reported as a visible problem — never dropped. Identity is the function key, so a route rename cannot smuggle a guard away. Weakening is judged over the resolved constrained set, not string comparison. `require_authz` is rejected, not faked.
- **No verdict.** Nothing in this slice emits ACCEPT/REVIEW/BLOCK or the word "clean". The "declared promise weakened → review" behaviour belongs to the verdict layer (a later slice).
- **Commits:** author `Laraib <lxh417bham@gmail.com>` only. Never `azizur@sirio-strategies.com`, never `-c user.email=…`, no `Co-Authored-By`, no AI attribution. Inherit the repo git config, which is already correct. Multiple small commits.
- **Baseline:** the full suite is green before this slice; `python benchmark/run_precision.py` prints `GATE PASSED` exit 0; `python benchmark/run_eval.py` is 1.0/1.0/1.0. None may regress.

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `src/cybergraph/security/policy.py` | policy model + strict loading; entity-keyed evaluation; policy/config delta; baseline extraction | 1, 2, 3, 4 |
| `src/cybergraph/security/policy_report.py` | render a `Policy` + `ProtectedSet` as a read-only report (assembly separate from CLI) | 5 |
| `src/cybergraph/cli.py` (modify) | register the `policy` subcommand; dispatch to load/evaluate/render or `--baseline` | 5 |
| `benchmark/mutation_harness.py` (modify) | seed policy fail-open mutations | 6 |

---

## Task 1: Policy model with strict loading

**Files:** Create `src/cybergraph/security/policy.py`; test `tests/test_policy.py`.

**Interfaces:** `POLICY_FILE = "cybergraph.policy.toml"`, `KIND_REQUIRE_AUTH = "require_auth"`, `PolicyRule(id, kind, patterns, because)`, `PolicyProblem(rule_id, message)`, `Policy(version, rules, problems, source_hash, exists)`, `load_policy(repo_root) -> Policy`, `_rule_sections(data) -> dict`.

Two decisions, both from the review:

**`require_authz` does not exist.** A `GUARDS` edge proves a login check, not a role or
ownership check. Accepting an authorization rule and evaluating it as authentication would
be a lie told inside the user's own file. Authorization arrives with typed edges later.

**Nothing fails silently.** An unrecognised kind, a malformed rule, or an unsupported
version becomes a `PolicyProblem`, which the verdict layer (a later slice) turns into a review. For an ordinary
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

## Task 2: Entity-keyed policy evaluation

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

Identity is now the **function key**, which survives a route rename. Task 3 (policy delta) uses it.

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
    unrelated new route. The function key survives the rename, so Task 3 can
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

## Task 3: Policy and config delta

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

## Task 4: Baseline extraction

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

---

## Task 5: Policy report and the `cybergraph policy` surface

**Files:**
- Create: `src/cybergraph/security/policy_report.py`
- Modify: `src/cybergraph/cli.py` (register the `policy` subparser near the other `sub.add_parser(...)` calls; add an `elif args.command == "policy":` branch in the dispatch chain)
- Test: `tests/test_policy_report.py`, `tests/test_cli_policy.py`

**Interfaces:**
- Consumes (from Tasks 1–4, all in `cybergraph.security.policy`): `load_policy(repo_root) -> Policy`; `Policy` with `.exists`, `.rules` (each `PolicyRule` has `.id`, `.kind`, `.patterns`), `.problems` (each `PolicyProblem` has `.rule_id`, `.message`); `evaluate_policy(repo_root, policy) -> ProtectedSet` with `.constrained: frozenset[str]` and `.unprotected: tuple[PolicyViolation, ...]` (each `PolicyViolation` has `.entity_key`, `.subject`, `.because`); `extract_baseline(repo_root) -> str`. Also `cybergraph.build.build_graph(repo_root)`.
- Produces: `format_policy_report(policy: Policy, protected_set: ProtectedSet) -> str`; a `cybergraph policy [--repo R] [--baseline]` command.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_policy_report.py`:

```python
from cybergraph.security.policy import (
    Policy,
    PolicyProblem,
    PolicyRule,
    PolicyViolation,
    ProtectedSet,
)
from cybergraph.security.policy_report import format_policy_report


def _policy(rules=(), problems=(), exists=True):
    return Policy(version=1, rules=tuple(rules), problems=tuple(problems),
                  source_hash="0" * 64, exists=exists)


def test_absent_policy_says_so_and_names_no_verdict():
    text = format_policy_report(_policy(exists=False), ProtectedSet({}, frozenset(), ()))
    assert "No policy" in text
    assert "clean" not in text.lower()
    assert "accept" not in text.lower()


def test_rules_and_problems_are_both_shown():
    policy = _policy(
        rules=[PolicyRule("admin-login", "require_auth", ("/admin/*",), "because")],
        problems=[PolicyProblem("mfa", "kind 'require_mfa' is not supported")],
    )
    text = format_policy_report(policy, ProtectedSet({}, frozenset(), ()))
    assert "admin-login" in text and "require_auth" in text and "/admin/*" in text
    assert "require_mfa" in text


def test_unprotected_entities_are_listed():
    policy = _policy(rules=[PolicyRule("a", "require_auth", ("/admin/*",), "b")])
    violation = PolicyViolation("a", "/admin/export", "app.py::export", "app.py", 4, "no login check")
    pset = ProtectedSet({}, frozenset({"app.py::export"}), (violation,))
    text = format_policy_report(policy, pset)
    assert "1 unprotected" in text
    assert "app.py::export" in text
```

Create `tests/test_cli_policy.py`:

```python
import subprocess
from pathlib import Path

from cybergraph.cli import main

APP = '''from fastapi import FastAPI
app = FastAPI()

@app.get("/admin/export")
def export():
    return {}
'''

POLICY = '''version = 1

[rule.admin-requires-login]
kind = "require_auth"
patterns = ["/admin/*"]
because = "Admin pages are not public."
'''


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    (tmp_path / "cybergraph.policy.toml").write_text(POLICY, encoding="utf-8")
    return tmp_path


def test_policy_command_renders_and_exits_zero(tmp_path: Path, capsys):
    repo = _repo(tmp_path)
    code = main(["policy", "--repo", str(repo)])
    out = capsys.readouterr().out
    assert code in (0, None)
    assert "admin-requires-login" in out
    assert "clean" not in out.lower()


def test_baseline_prints_toml_and_writes_nothing(tmp_path: Path, capsys):
    repo = _repo(tmp_path)
    before = sorted(p.name for p in repo.iterdir())
    code = main(["policy", "--repo", str(repo), "--baseline"])
    out = capsys.readouterr().out
    assert code in (0, None)
    assert "version" in out
    assert sorted(p.name for p in repo.iterdir()) == before, "baseline must not write files"


def test_invalid_repo_exits_nonzero(tmp_path: Path):
    missing = tmp_path / "nope"
    code = main(["policy", "--repo", str(missing)])
    assert code not in (0, None)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_policy_report.py tests/test_cli_policy.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.policy_report'`

- [ ] **Step 3: Write the implementation**

Create `src/cybergraph/security/policy_report.py`:

```python
"""Render the declared policy and what it protects, as a read-only report.

Assembly is separated from the CLI so a later verdict/MCP surface can reuse it.
This makes no accept/block decision: policy problems are reported, never turned
into a verdict here.
"""

from __future__ import annotations

from cybergraph.security.policy import Policy, ProtectedSet


def format_policy_report(policy: Policy, protected_set: ProtectedSet) -> str:
    lines: list[str] = []
    if not policy.exists:
        lines.append("No policy declared (cybergraph.policy.toml absent).")
    else:
        count = len(policy.rules)
        suffix = "" if count == 1 else "s"
        lines.append(f"Policy: cybergraph.policy.toml ({count} rule{suffix})")
        for rule in policy.rules:
            lines.append(f"  {rule.id}  {rule.kind}  {', '.join(rule.patterns)}")

    if policy.problems:
        lines.append("")
        lines.append(f"Policy problems: {len(policy.problems)}")
        for problem in policy.problems:
            lines.append(f"  ! {problem.rule_id}: {problem.message}")

    unprotected = protected_set.unprotected
    lines.append("")
    lines.append(
        f"Protected entities: {len(protected_set.constrained)} in scope, "
        f"{len(unprotected)} unprotected"
    )
    for violation in unprotected:
        lines.append(f"  x {violation.entity_key}  ({violation.subject})  {violation.because}")
    return "\n".join(lines)
```

Modify `src/cybergraph/cli.py`. Register the subparser alongside the others:

```python
    policy_cmd = sub.add_parser(
        "policy",
        help="Show the declared security policy and which entities it protects",
    )
    policy_cmd.add_argument("--repo", default=".", help="Repository root")
    policy_cmd.add_argument(
        "--baseline", action="store_true",
        help="Print a proposed policy baseline (TOML) to stdout; writes nothing",
    )
```

Add the dispatch branch:

```python
    elif args.command == "policy":
        from .security.policy import evaluate_policy, extract_baseline, load_policy
        from .security.policy_report import format_policy_report

        repo = Path(args.repo).resolve()
        if not repo.is_dir():
            print(f"Not a directory: {repo}", file=sys.stderr)
            return 1
        build_graph(repo)
        if args.baseline:
            print(extract_baseline(repo))
            return 0
        policy = load_policy(repo)
        protected = evaluate_policy(repo, policy)
        print(format_policy_report(policy, protected))
        return 0
```

**Notes for the implementer:**
- Confirm `import sys`, `from pathlib import Path`, and the `build_graph` import are already present near the top of `cli.py` (they are used by other commands); add any that is missing.
- Match `main()`'s existing exit-status convention: the other `elif` branches `return <int>` and `main` falls through to `return 0`, so `return 1` / `return 0` above is correct. If `main` returns `None` on success for other commands, that is why the tests accept `code in (0, None)`; the invalid-repo case must return a non-zero, non-None code.
- Do **NOT** add `policy` to the `read_commands` set that requires a pre-built graph — this command builds its own graph via `build_graph`.
- The word "clean" and any ACCEPT/REVIEW/BLOCK vocabulary must not appear on any output path.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_policy_report.py tests/test_cli_policy.py -v`
Expected: PASS (6 tests). Also run `python -m pytest -q` (full suite, no regressions) and `python -m ruff check src tests`.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/security/policy_report.py src/cybergraph/cli.py tests/test_policy_report.py tests/test_cli_policy.py
git commit -m "feat(policy): read-only cybergraph policy surface"
```

---

## Task 6: Seed the mutation harness with policy fail-open regressions

**Files:**
- Modify: `benchmark/mutation_harness.py` (append to the `MUTATIONS: list[Mutation]` list, before its closing `]`)

**Interfaces:**
- Consumes: the existing `Mutation(id, disaster, file, old, new, tests, note, count)` frozen dataclass and `MUTATIONS` list.
- Produces: two new caught mutations covering the policy fail-open regressions this slice removes.

The harness restores a pristine `src/` clone per mutation, requires the mapped tests green on the clean clone, applies the `old → new` edit, and requires them red. The `old` string must match the shipped source **byte-for-byte** (copy it from the file after Tasks 1–4 land) or the harness reports UNCAUGHT.

- [ ] **Step 1: Add the two mutations**

Append two `Mutation(...)` entries to `MUTATIONS` in `benchmark/mutation_harness.py`. Copy each `old` string verbatim from the shipped `src/cybergraph/security/policy.py`:

1. **`D1-policy-unknown-kind-silently-dropped`** (disaster `D1`) — target the branch in `load_policy` (or its rule-parsing helper) that appends a `PolicyProblem` when a rule's `kind` is not `require_auth`. Mutate it so an unrecognised kind is silently skipped (no problem appended) instead of recorded. Map to `tests/test_policy.py::test_unknown_kind_becomes_a_visible_problem`. A security policy that silently drops a promise the user wrote is the fail-open this task guards.

2. **`D2-policy-rename-escape-not-detected`** (disaster `D2`) — target the delta logic that flags `protection_lost` when a function key survives but loses its guard/constraint (the C1 rename-escape fix, Task 3). Mutate it so the rename escape is not flagged. Map to the Task 3 delta test in `tests/test_policy_delta.py` that asserts `protection_lost` on a guarded-then-unguarded renamed function (identify the exact node id by reading the shipped test file).

For each: `old`/`new` must flip a real fail-closed behaviour to fail-open, and the mapped test must currently pass on clean source and fail under the mutation. If either cannot be mapped to a real line + a currently-passing guard test, STOP and report rather than seeding an UNCAUGHT or vacuous mutation.

- [ ] **Step 2: Run the harness**

Run: `python benchmark/mutation_harness.py`
Expected: every mutation reports `CAUGHT` including the two new ids; exit 0. If either new one reports `UNCAUGHT`, the `old` string did not match shipped source or the test does not cover it — fix and rerun.

- [ ] **Step 3: Run the full suite and gate**

Run:
```
python -m pytest -q
python -m ruff check src tests
python benchmark/run_precision.py
```
Expected: suite green; ruff clean; `GATE PASSED` exit 0. `run_eval.py` unchanged at 1.0/1.0/1.0.

- [ ] **Step 4: Commit**

```bash
git add benchmark/mutation_harness.py
git commit -m "test(harness): seed the policy fail-open mutations"
```

---

## Notes for the executor

- Tasks 1–4 build `security/policy.py` incrementally and must run in order (2 consumes 1; 3 consumes 1–2; 4 consumes 1). Task 5 consumes 1–4. Task 6 runs last so its `old` strings match shipped source.
- Tasks 2 and 4 read the graph (real integration, not transcription) and Task 3's semantic-weakening logic needs care — dispatch those on a standard-tier implementer, not the cheapest. Tasks 1, 5, 6 are lighter.
- Follow the prior slices' discipline: a fresh implementer per task, an adversarial review between tasks, and verify every new test goes **red** under the mutation it guards. Task 6's harness makes that runnable.
- Nothing in this slice makes an ACCEPT/REVIEW/BLOCK decision. If a task starts to, it has left scope — stop and confirm.

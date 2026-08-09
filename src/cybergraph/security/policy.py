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
import json
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from cybergraph.config import CyberGraphConfig, _load_toml
from cybergraph.graph import GraphStore

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
    # An id that now surfaces as a problem did not vanish — it became invalid,
    # which is already reported above as `policy_problem`. Only an id absent
    # from *both* current rules and current problems is genuinely removed.
    current_problem_ids = {problem.rule_id for problem in current.problems if problem.rule_id}
    current_present_ids = current_ids | current_problem_ids
    for removed in sorted(base_ids - current_present_ids):
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

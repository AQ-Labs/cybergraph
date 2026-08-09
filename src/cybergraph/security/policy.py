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

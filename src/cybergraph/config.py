"""CyberGraph project configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None  # type: ignore[assignment]


CONFIG_FILE = ".cybergraph.toml"


@dataclass(frozen=True)
class Suppression:
    kind: str
    matcher: str
    reason: str
    expires: date | None
    approver: str = ""


@dataclass(frozen=True)
class SuppressionProblem:
    kind: str
    matcher: str
    message: str


@dataclass(frozen=True)
class CyberGraphConfig:
    ignored_paths: tuple[str, ...] = ()
    custom_sinks: tuple[str, ...] = ()
    auth_markers: tuple[str, ...] = ()
    validation_markers: tuple[str, ...] = ()
    secret_markers: tuple[str, ...] = ()
    suppressed_rules: tuple[str, ...] = ()
    suppressed_paths: tuple[str, ...] = ()
    severity_overrides: dict[str, str] = field(default_factory=dict)
    suppressions: tuple[Suppression, ...] = ()
    suppression_problems: tuple[SuppressionProblem, ...] = ()


def load_config(repo_root: Path) -> CyberGraphConfig:
    path = repo_root / CONFIG_FILE
    if not path.exists():
        return CyberGraphConfig()
    data = _load_toml(path)
    suppressions, suppression_problems = _parse_suppressions(data)
    return CyberGraphConfig(
        ignored_paths=tuple(_list(data, "ignore", "paths")),
        custom_sinks=tuple(_list(data, "security", "sinks")),
        auth_markers=tuple(_list(data, "security", "auth_markers")),
        validation_markers=tuple(_list(data, "security", "validation_markers")),
        secret_markers=tuple(_list(data, "security", "secret_markers")),
        suppressed_rules=tuple(_list(data, "suppressions", "rules")),
        suppressed_paths=tuple(_list(data, "suppressions", "paths")),
        severity_overrides=dict(data.get("severity", {}).get("overrides", {})),
        suppressions=suppressions,
        suppression_problems=suppression_problems,
    )


def _parse_suppressions(
    data: dict[str, Any],
) -> tuple[tuple[Suppression, ...], tuple[SuppressionProblem, ...]]:
    """Parse the accountable `[[suppressions.rule]]` / `[[suppressions.path]]` tables.

    These array-of-tables entries can only be represented by `tomllib`
    (Python 3.11+); the hand-rolled `_load_simple_toml` fallback used on
    Python 3.10 has no notion of array-of-tables. Under that fallback,
    `[[suppressions.rule]]` mangles into a stray top-level key
    `data["suppressions.rule"]` (the fallback strips `[`/`]` indiscriminately,
    so the doubled brackets just leave the dotted name intact) instead of
    `data["suppressions"]["rule"]`. Rather than silently dropping the entry
    (fail-open but silent — the whole point of this feature is to never be
    silent), we detect that fingerprint and surface one `SuppressionProblem`
    per affected kind so the finding still re-surfaces AND the operator is
    told why their accountable suppression didn't take effect.
    """
    suppressions: list[Suppression] = []
    problems: list[SuppressionProblem] = []
    suppressions_section = data.get("suppressions", {})
    if not isinstance(suppressions_section, dict):
        suppressions_section = {}

    for kind, matcher_key in (("rule", "id"), ("path", "pattern")):
        entries = suppressions_section.get(kind, [])
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                _parse_suppression_entry(kind, matcher_key, entry, suppressions, problems)
        elif kind in suppressions_section:
            # `[suppressions.rule]` (single bracket) is a nested TABLE on
            # 3.11+ tomllib, not an array-of-tables -- `data["suppressions"]
            # ["rule"]` comes back as a dict. That is the same silent-drop the
            # 3.10 fallback fingerprint below exists to close, so it gets the
            # same treatment: fail open (no `Suppression`), but say so.
            problems.append(
                SuppressionProblem(
                    kind, "",
                    f"expected [[suppressions.{kind}]] array-of-tables, got a table",
                )
            )

        if f"suppressions.{kind}" in data:
            problems.append(
                SuppressionProblem(
                    kind,
                    "",
                    "accountable suppressions require Python 3.11+ (tomllib); "
                    "this entry was ignored",
                )
            )

    return tuple(suppressions), tuple(problems)


def _parse_suppression_entry(
    kind: str,
    matcher_key: str,
    entry: dict[str, Any],
    suppressions: list[Suppression],
    problems: list[SuppressionProblem],
) -> None:
    matcher = str(entry.get(matcher_key, "") or "").strip()
    if not matcher:
        problems.append(
            SuppressionProblem(kind, matcher, f"missing '{matcher_key}' for {kind} suppression")
        )
        return

    reason = str(entry.get("reason", "") or "").strip()
    if not reason:
        problems.append(SuppressionProblem(kind, matcher, "missing required 'reason'"))
        return

    expires: date | None = None
    raw_expires = entry.get("expires")
    if raw_expires is not None:
        try:
            expires = date.fromisoformat(str(raw_expires))
        except ValueError:
            problems.append(
                SuppressionProblem(kind, matcher, f"invalid 'expires' value: {raw_expires!r}")
            )
            return

    approver = str(entry.get("approver", "") or "")
    suppressions.append(Suppression(kind, matcher, reason, expires, approver))


def _load_toml(path: Path) -> dict[str, Any]:
    if tomllib is None:
        return _load_simple_toml(path)
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _load_simple_toml(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current: dict[str, Any] = data
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]").strip()
            current = data.setdefault(section, {})
            continue
        if "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        current[key] = _parse_simple_value(value)
    return data


def _parse_simple_value(value: str) -> Any:
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [item.strip().strip("\"'") for item in inner.split(",")]
    if value == "{}":
        return {}
    return value.strip("\"'")


def _list(data: dict[str, Any], section: str, key: str) -> list[str]:
    value = data.get(section, {}).get(key, [])
    if isinstance(value, list):
        return [str(item) for item in value]
    return []

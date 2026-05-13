"""CyberGraph project configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None  # type: ignore[assignment]


CONFIG_FILE = ".cybergraph.toml"


@dataclass(frozen=True)
class CyberGraphConfig:
    ignored_paths: tuple[str, ...] = ()
    custom_sinks: tuple[str, ...] = ()
    auth_markers: tuple[str, ...] = ()
    validation_markers: tuple[str, ...] = ()
    secret_markers: tuple[str, ...] = ()
    severity_overrides: dict[str, str] = field(default_factory=dict)


def load_config(repo_root: Path) -> CyberGraphConfig:
    path = repo_root / CONFIG_FILE
    if not path.exists():
        return CyberGraphConfig()
    data = _load_toml(path)
    return CyberGraphConfig(
        ignored_paths=tuple(_list(data, "ignore", "paths")),
        custom_sinks=tuple(_list(data, "security", "sinks")),
        auth_markers=tuple(_list(data, "security", "auth_markers")),
        validation_markers=tuple(_list(data, "security", "validation_markers")),
        secret_markers=tuple(_list(data, "security", "secret_markers")),
        severity_overrides=dict(data.get("severity", {}).get("overrides", {})),
    )


def _load_toml(path: Path) -> dict[str, Any]:
    if tomllib is None:
        return _load_simple_toml(path)
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _load_simple_toml(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current: dict[str, Any] | None = None
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]").strip()
            current = data.setdefault(section, {})
            continue
        if current is None or "=" not in line:
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
    return value.strip("\"'")


def _list(data: dict[str, Any], section: str, key: str) -> list[str]:
    value = data.get(section, {}).get(key, [])
    if isinstance(value, list):
        return [str(item) for item in value]
    return []

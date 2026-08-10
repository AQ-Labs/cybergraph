from __future__ import annotations

import json
from pathlib import Path

from .base import (
    InstallResult,
    Status,
    quoted_invocation,
    read_json,
    write_json,
)

_RUN_CMD = "hook run claude-code"


def _settings_path(repo_root: Path) -> Path:
    return repo_root / ".claude" / "settings.json"


def _our_command(strict: bool) -> str:
    return f"{quoted_invocation()} {_RUN_CMD}" + (" --strict" if strict else "")


def _entry(strict: bool) -> dict:
    return {"matcher": "*", "hooks": [{"type": "command", "command": _our_command(strict)}]}


def _is_ours(entry: dict) -> bool:
    return any(
        _RUN_CMD in h.get("command", "")
        for h in entry.get("hooks", [])
        if isinstance(h, dict)
    )


class ClaudeCodeTarget:
    name = "claude-code"

    def install(self, repo_root: Path, *, strict: bool, force: bool) -> InstallResult:
        settings = _settings_path(repo_root)
        try:
            data = read_json(settings)
        except json.JSONDecodeError:
            return InstallResult(
                Status.MALFORMED,
                f"{settings} is not valid JSON; refusing to overwrite it. Fix or remove it, "
                "then re-run.",
            )
        hooks = data.setdefault("hooks", {})
        stop = hooks.setdefault("Stop", [])
        already = [e for e in stop if _is_ours(e)]
        if len(already) == 1 and already[0] == _entry(strict):
            return InstallResult(
                Status.ALREADY_PRESENT,
                f"CyberGraph Stop hook already installed "
                f"({'strict' if strict else 'advisory'}).",
            )
        stop[:] = [e for e in stop if not _is_ours(e)]
        stop.append(_entry(strict))
        write_json(settings, data)
        return InstallResult(
            Status.INSTALLED,
            f"Installed the CyberGraph Stop hook "
            f"({'strict' if strict else 'advisory'}) in {settings}. It runs `cybergraph "
            "check` when an agent turn ends; a REVIEW is "
            f"{'blocked' if strict else 'surfaced, not blocked'}.",
        )

    def uninstall(self, repo_root: Path) -> InstallResult:
        settings = _settings_path(repo_root)
        try:
            data = read_json(settings)
        except json.JSONDecodeError:
            return InstallResult(Status.MALFORMED, f"{settings} is not valid JSON")
        stop = data.get("hooks", {}).get("Stop", [])
        if not any(_is_ours(e) for e in stop):
            return InstallResult(Status.ABSENT, "no CyberGraph Stop hook to remove.")
        stop[:] = [e for e in stop if not _is_ours(e)]
        if not stop:
            data["hooks"].pop("Stop", None)
        if not data.get("hooks"):
            data.pop("hooks", None)
        write_json(settings, data)
        return InstallResult(Status.REMOVED, "Removed the CyberGraph Stop hook.")

    def status(self, repo_root: Path) -> InstallResult:
        settings = _settings_path(repo_root)
        try:
            data = read_json(settings)
        except json.JSONDecodeError:
            return InstallResult(Status.MALFORMED, "settings.json is not valid JSON")
        ours = [
            h.get("command", "")
            for e in data.get("hooks", {}).get("Stop", [])
            if _is_ours(e)
            for h in e.get("hooks", [])
            if _RUN_CMD in h.get("command", "")
        ]
        if not ours:
            return InstallResult(Status.ABSENT, "not installed")
        mode = "strict" if any("--strict" in c for c in ours) else "advisory"
        return InstallResult(Status.ALREADY_PRESENT, f"installed ({mode})")

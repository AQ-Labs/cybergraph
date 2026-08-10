from __future__ import annotations

import json
from pathlib import Path

from ..security.check import check_change
from ..security.verdict import STATE_REVIEW, format_verdict
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


def _strip_ours(stop: list) -> list:
    """Remove only our hooks from each Stop entry; drop an entry only when it
    becomes empty. Foreign hooks sharing an entry with ours are preserved."""
    result = []
    for entry in stop:
        if not isinstance(entry, dict):
            result.append(entry)
            continue
        hooks = entry.get("hooks", [])
        kept = [
            h for h in hooks
            if not (isinstance(h, dict) and _RUN_CMD in h.get("command", ""))
        ]
        if kept == hooks:
            result.append(entry)          # nothing of ours in this entry
        elif kept:
            result.append({**entry, "hooks": kept})  # keep foreign hooks
        # else: entry held only our hook(s) -> drop it
    return result


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
        stop[:] = _strip_ours(stop)
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
        stop[:] = _strip_ours(stop)
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


def _summary(verdict) -> str:
    heads = [r.headline for r in verdict.reasons if getattr(r, "headline", "")]
    if heads:
        return " ".join(heads[:3])
    return format_verdict(verdict).strip().splitlines()[0] if format_verdict(verdict) else "review"


def run(strict: bool, stdin_text: str, *, check=check_change) -> int:
    try:
        payload = json.loads(stdin_text) if stdin_text.strip() else {}
    except json.JSONDecodeError:
        payload = {}
    cwd = Path(payload.get("cwd") or ".").resolve()
    stop_active = bool(payload.get("stop_hook_active"))

    try:
        verdict = check(cwd, mode="worktree")
    except Exception as exc:  # never trap the agent on our own failure
        print(json.dumps({"systemMessage": f"CyberGraph could not run: {exc}"}))
        return 0

    if verdict.state != STATE_REVIEW:
        return 0  # ACCEPT (or anything non-review): silent

    summary = _summary(verdict)
    if strict and not stop_active:
        print(json.dumps({
            "decision": "block",
            "reason": f"CyberGraph REVIEW — {summary} Address these before finishing.",
        }))
        return 0
    print(json.dumps({"systemMessage": f"CyberGraph REVIEW — {summary}"}))
    return 0

from __future__ import annotations

import json
from pathlib import Path

from cybergraph.hooks.base import Status
from cybergraph.hooks.claude_code import ClaudeCodeTarget

RUN_CMD = "hook run claude-code"


def _settings(repo: Path) -> Path:
    return repo / ".claude" / "settings.json"


def _load(repo: Path) -> dict:
    return json.loads(_settings(repo).read_text(encoding="utf-8"))


def test_fresh_install_creates_stop_hook(tmp_path: Path) -> None:
    res = ClaudeCodeTarget().install(tmp_path, strict=False, force=False)
    assert res.status is Status.INSTALLED
    data = _load(tmp_path)
    cmds = [h["command"] for e in data["hooks"]["Stop"] for h in e["hooks"]]
    assert any(RUN_CMD in c for c in cmds)
    assert not any("--strict" in c for c in cmds)  # advisory


def test_strict_encodes_strict_flag(tmp_path: Path) -> None:
    ClaudeCodeTarget().install(tmp_path, strict=True, force=False)
    data = _load(tmp_path)
    cmds = [h["command"] for e in data["hooks"]["Stop"] for h in e["hooks"]]
    assert any(RUN_CMD in c and "--strict" in c for c in cmds)


def test_install_preserves_siblings_and_other_hooks(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({
        "model": "opus",
        "hooks": {
            "PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": "echo pre"}]}],
            "Stop": [{"matcher": "*", "hooks": [
                {"type": "command", "command": "echo other-stop"}]}],
        },
    }), encoding="utf-8")

    ClaudeCodeTarget().install(tmp_path, strict=False, force=False)
    data = _load(tmp_path)

    assert data["model"] == "opus"
    assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "echo pre"
    stop_cmds = [h["command"] for e in data["hooks"]["Stop"] for h in e["hooks"]]
    assert "echo other-stop" in stop_cmds
    assert any(RUN_CMD in c for c in stop_cmds)


def test_reinstall_does_not_duplicate(tmp_path: Path) -> None:
    ClaudeCodeTarget().install(tmp_path, strict=False, force=False)
    ClaudeCodeTarget().install(tmp_path, strict=False, force=False)
    data = _load(tmp_path)
    ours = [h for e in data["hooks"]["Stop"] for h in e["hooks"] if RUN_CMD in h["command"]]
    assert len(ours) == 1


def test_uninstall_removes_only_ours(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({
        "hooks": {"Stop": [{"matcher": "*", "hooks": [
            {"type": "command", "command": "echo other-stop"}]}]},
    }), encoding="utf-8")
    ClaudeCodeTarget().install(tmp_path, strict=False, force=False)

    res = ClaudeCodeTarget().uninstall(tmp_path)
    assert res.status is Status.REMOVED
    stop_cmds = [h["command"] for e in _load(tmp_path)["hooks"]["Stop"] for h in e["hooks"]]
    assert "echo other-stop" in stop_cmds
    assert not any(RUN_CMD in c for c in stop_cmds)


def test_malformed_settings_is_refused_not_overwritten(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text("{not json", encoding="utf-8")
    res = ClaudeCodeTarget().install(tmp_path, strict=False, force=False)
    assert res.status is Status.MALFORMED
    assert settings.read_text(encoding="utf-8") == "{not json"


def _seed_shared_entry(repo: Path) -> None:
    settings = _settings(repo)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({
        "hooks": {"Stop": [{"matcher": "*", "hooks": [
            {"type": "command", "command": "echo important-foreign-thing"},
            {"type": "command", "command": "python -m cybergraph hook run claude-code"},
        ]}]},
    }), encoding="utf-8")


def test_uninstall_preserves_foreign_hook_sharing_our_entry(tmp_path: Path) -> None:
    _seed_shared_entry(tmp_path)
    res = ClaudeCodeTarget().uninstall(tmp_path)
    assert res.status is Status.REMOVED
    stop_cmds = [h["command"] for e in _load(tmp_path)["hooks"]["Stop"] for h in e["hooks"]]
    assert "echo important-foreign-thing" in stop_cmds
    assert not any(RUN_CMD in c for c in stop_cmds)


def test_install_preserves_foreign_hook_sharing_an_entry(tmp_path: Path) -> None:
    _seed_shared_entry(tmp_path)
    ClaudeCodeTarget().install(tmp_path, strict=False, force=False)
    data = _load(tmp_path)
    stop_cmds = [h["command"] for e in data["hooks"]["Stop"] for h in e["hooks"]]
    assert "echo important-foreign-thing" in stop_cmds
    assert sum(1 for c in stop_cmds if RUN_CMD in c) == 1


def test_status_reports_absent_advisory_and_strict(tmp_path: Path) -> None:
    target = ClaudeCodeTarget()
    fresh = target.status(tmp_path)
    assert fresh.status is Status.ABSENT

    target.install(tmp_path, strict=False, force=False)
    assert "advisory" in target.status(tmp_path).message.lower()

    target.install(tmp_path, strict=True, force=False)
    assert "strict" in target.status(tmp_path).message.lower()

from __future__ import annotations

from .base import InstallResult, Status, Target
from .claude_code import ClaudeCodeTarget
from .pre_commit import PreCommitTarget

TARGETS: dict[str, Target] = {
    "claude-code": ClaudeCodeTarget(),
    "pre-commit": PreCommitTarget(),
}


def resolve_target(name: str) -> Target:
    return TARGETS[name]


__all__ = ["TARGETS", "resolve_target", "InstallResult", "Status", "Target"]

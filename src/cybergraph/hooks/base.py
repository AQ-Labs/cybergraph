from __future__ import annotations

import json
import shlex
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

MARKER = "cybergraph-hook"


class Status(str, Enum):
    INSTALLED = "installed"
    ALREADY_PRESENT = "already_present"
    REFUSED_FOREIGN = "refused_foreign"
    NOT_A_REPO = "not_a_repo"
    REMOVED = "removed"
    ABSENT = "absent"
    MALFORMED = "malformed"
    ERROR = "error"


@dataclass(frozen=True)
class InstallResult:
    status: Status
    message: str

    @property
    def ok(self) -> bool:
        return self.status in {
            Status.INSTALLED, Status.ALREADY_PRESENT, Status.REMOVED, Status.ABSENT,
        }


def resolve_invocation() -> list[str]:
    """A command that runs the CyberGraph CLI without depending on PATH.

    Git hooks and the Claude Code hook shell often run with a bare environment
    where the `cybergraph` console script is not on PATH; `python -m cybergraph`
    resolves whenever the package is importable in this interpreter.
    """
    return [sys.executable, "-m", "cybergraph"]


def quoted_invocation() -> str:
    return " ".join(shlex.quote(part) for part in resolve_invocation())


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return {}
    return json.loads(text)


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


@runtime_checkable
class Target(Protocol):
    name: str

    def install(self, repo_root: Path, *, strict: bool, force: bool) -> InstallResult: ...
    def uninstall(self, repo_root: Path) -> InstallResult: ...
    def status(self, repo_root: Path) -> InstallResult: ...

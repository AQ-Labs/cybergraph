"""Graph domain objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Node:
    kind: str
    key: str
    name: str
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Edge:
    kind: str
    source: str
    target: str
    file_path: str = ""
    line: int = 0
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    file_path: str
    line_start: int = 0
    line_end: int = 0
    cwe: str = ""
    owasp: str = ""
    tool: str = "cybergraph"
    evidence: str = ""

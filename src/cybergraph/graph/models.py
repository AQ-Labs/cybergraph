"""Graph domain objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# A finding the analyser could neither clear nor confirm carries its rule's id
# with this appended, at reduced severity. It is a derived id rather than a rule
# of its own, so `cybergraph.suppressions` strips it before matching: accepting
# `CG-SQL-EXEC` on a line accepts the abstention on that line too. Defined here,
# beside `Finding`, because the analyser that mints the id and the suppression
# layer that strips it must not import each other.
UNVERIFIED_SUFFIX = "-UNVERIFIED"


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

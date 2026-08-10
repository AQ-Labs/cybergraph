"""Supabase RLS analyzer for SQL migrations.

Row-level security is Supabase's authorization boundary; a table with RLS off
(or a policy that re-opens it with ``USING (true)``) exposes its rows to the
public API role. Regex-based, per-file. Three definite signals:

* ``DISABLE ROW LEVEL SECURITY`` -- an explicit switch-off;
* ``CREATE POLICY ... USING (true)`` -- a policy that grants everyone access;
* ``CREATE TABLE t`` with no ``ENABLE ROW LEVEL SECURITY`` for ``t`` in the same
  file -- Supabase migrations conventionally enable RLS in the migration that
  creates the table, so a create with no same-file enable is the classic
  "forgot to turn on RLS" bug. Cross-file enable is possible but rare; the
  same-file scope keeps precision high and the finding is a REVIEW, not a block.

Table identity is compared on the bare table name (schema-qualified or not).
"""

from __future__ import annotations

import re
from pathlib import Path

from cybergraph.graph import Edge, Finding, Node
from cybergraph.suppressions import is_inline_suppressed

DISABLE_RE = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?P<tbl>[\w.\"]+)\s+disable\s+row\s+level\s+security",
    re.IGNORECASE,
)
ENABLE_RE = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?P<tbl>[\w.\"]+)\s+enable\s+row\s+level\s+security",
    re.IGNORECASE,
)
CREATE_TABLE_RE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?P<tbl>[\w.\"]+)",
    re.IGNORECASE,
)
POLICY_TRUE_RE = re.compile(
    r"create\s+policy\b[^;]*?\busing\s*\(\s*true\s*\)",
    re.IGNORECASE | re.DOTALL,
)


def _bare(name: str) -> str:
    return name.replace('"', "").split(".")[-1].lower()


def _line_of(source: str, index: int) -> int:
    return source.count("\n", 0, index) + 1


def analyze_supabase_rls_file(
    path: Path, repo_root: Path
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()
    rel = path.relative_to(repo_root).as_posix()
    nodes: list[Node] = [Node("File", rel, rel, rel, 1, len(lines), {"language": "sql"})]
    findings: list[Finding] = []

    def emit(line_no: int, message: str) -> None:
        if is_inline_suppressed(lines, line_no, "CG-SUPABASE-RLS-DISABLED"):
            return
        findings.append(
            Finding(
                rule_id="CG-SUPABASE-RLS-DISABLED",
                severity="high",
                message=message,
                file_path=rel,
                line_start=line_no,
                cwe="CWE-1230",
                evidence=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "",
            )
        )

    for m in DISABLE_RE.finditer(source):
        emit(_line_of(source, m.start()),
             f"row-level security is disabled on `{_bare(m.group('tbl'))}`")
    for m in POLICY_TRUE_RE.finditer(source):
        emit(_line_of(source, m.start()),
             "a policy grants access to everyone (`USING (true)`)")

    enabled = {_bare(m.group("tbl")) for m in ENABLE_RE.finditer(source)}
    for m in CREATE_TABLE_RE.finditer(source):
        tbl = _bare(m.group("tbl"))
        if tbl not in enabled:
            emit(_line_of(source, m.start()),
                 f"table `{tbl}` is created without enabling row-level security")

    return nodes, [], findings

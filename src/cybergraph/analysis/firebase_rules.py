"""Firebase security-rules analyzer (firestore.rules / storage.rules).

Regex-based, no dependency. Flags an ``allow`` whose condition is
unconditionally true -- the classic "open to the whole internet" rule. A rule
guarded by any real condition (``request.auth != null``, a function call, a
comparison) produces no finding. Conservative: only a literal-true condition is
flagged, and the file always yields a File node so the build never crashes.
"""

from __future__ import annotations

import re
from pathlib import Path

from cybergraph.graph import Edge, Finding, Node
from cybergraph.suppressions import is_inline_suppressed

# allow <ops> : if <condition> ;   -- capture the condition up to the semicolon.
ALLOW_RE = re.compile(
    r"allow\s+(?P<ops>[a-z, \t]+?)\s*:\s*if\s+(?P<cond>[^;{]+);",
    re.IGNORECASE,
)
# An unconditionally-true condition: `true`, `(true)`, `true == true`, etc.
_TRUE_RE = re.compile(r"^\(*\s*true\s*\)*$", re.IGNORECASE)


def analyze_firebase_rules_file(
    path: Path, repo_root: Path
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()
    rel = path.relative_to(repo_root).as_posix()
    nodes: list[Node] = [
        Node("File", rel, rel, rel, 1, len(lines), {"language": "firebase-rules"})
    ]
    findings: list[Finding] = []

    for match in ALLOW_RE.finditer(source):
        cond = match.group("cond").strip()
        if not _TRUE_RE.match(cond):
            continue
        line_no = source.count("\n", 0, match.start()) + 1
        if is_inline_suppressed(lines, line_no, "CG-FIREBASE-RULES-OPEN"):
            continue
        ops = " ".join(match.group("ops").split())
        findings.append(
            Finding(
                rule_id="CG-FIREBASE-RULES-OPEN",
                severity="high",
                message=f"Firebase rule grants `{ops}` to everyone (condition is always true)",
                file_path=rel,
                line_start=line_no,
                cwe="CWE-732",
                evidence=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "",
            )
        )
    return nodes, [], findings

"""Standalone S3/GCS bucket-policy analyzer (not Terraform -- terraform.py owns HCL).

Parses a JSON policy file and flags a grant of public access:

* S3 bucket policy: a ``Statement`` with ``Effect: Allow`` and a wildcard
  ``Principal`` (``"*"`` or ``{"AWS": "*"}``);
* GCS IAM policy: a ``binding`` whose ``members`` include ``allUsers`` or
  ``allAuthenticatedUsers`` on a storage role.

A valid JSON that is not a policy shape yields no finding (a bare File node).
Malformed JSON is NOT caught here -- it raises ``JSONDecodeError`` (a
``ValueError``) so the registry's per-file containment records the file as
unreadable, which the coverage layer reads as UNKNOWN rather than a clean pass.
"""

from __future__ import annotations

import json
from pathlib import Path

from cybergraph.graph import Edge, Finding, Node
from cybergraph.suppressions import is_inline_suppressed

_PUBLIC_MEMBERS = {"allusers", "allauthenticatedusers"}


def _is_wildcard_principal(principal: object) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(
            v == "*" or (isinstance(v, list) and "*" in v) for v in principal.values()
        )
    return False


def _evidence_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, start=1):
        if needle in line:
            return i
    return 1


def analyze_bucket_policy_file(
    path: Path, repo_root: Path
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()
    rel = path.relative_to(repo_root).as_posix()
    nodes: list[Node] = [Node("File", rel, rel, rel, 1, len(lines), {"language": "json"})]
    findings: list[Finding] = []

    data = json.loads(source)  # JSONDecodeError propagates -> registry containment

    def emit(line_no: int, message: str) -> None:
        if is_inline_suppressed(lines, line_no, "CG-STORAGE-BUCKET-PUBLIC"):
            return
        findings.append(
            Finding(
                rule_id="CG-STORAGE-BUCKET-PUBLIC",
                severity="high",
                message=message,
                file_path=rel,
                line_start=line_no,
                cwe="CWE-732",
                evidence=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "",
            )
        )

    if isinstance(data, dict) and isinstance(data.get("Statement"), list):
        for stmt in data["Statement"]:
            if not isinstance(stmt, dict):
                continue
            if stmt.get("Effect") == "Allow" and _is_wildcard_principal(stmt.get("Principal")):
                emit(_evidence_line(lines, "Principal"),
                     "S3 bucket policy grants access to everyone (Principal \"*\")")
                break

    if isinstance(data, dict) and isinstance(data.get("bindings"), list):
        for binding in data["bindings"]:
            if not isinstance(binding, dict):
                continue
            members = binding.get("members", [])
            if isinstance(members, list) and any(
                isinstance(m, str) and m.lower() in _PUBLIC_MEMBERS for m in members
            ):
                emit(_evidence_line(lines, "allUsers"),
                     "storage IAM binding grants access to all users")
                break

    return nodes, [], findings

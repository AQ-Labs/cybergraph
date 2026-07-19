"""Simple evidence retrieval over the local CyberGraph database."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cybergraph.graph import GraphStore


@dataclass(frozen=True)
class Evidence:
    kind: str
    title: str
    file_path: str
    line: int
    detail: str


def retrieve_evidence(repo_root: Path, question: str, limit: int = 8) -> list[Evidence]:
    terms = [t.lower() for t in question.replace("?", " ").split() if len(t) > 2]
    store = GraphStore.open_for_repo(repo_root)
    try:
        evidence: list[Evidence] = []
        for row in store.conn.execute(
            """
            SELECT rule_id, severity, message, file_path, line_start, evidence
            FROM findings
            ORDER BY CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                file_path,
                line_start
            LIMIT 50
            """
        ):
            haystack = " ".join(str(row[k]) for k in row.keys()).lower()
            if not terms or any(term in haystack for term in terms):
                evidence.append(
                    Evidence(
                        "finding",
                        f"{row['severity']} {row['rule_id']}",
                        row["file_path"],
                        row["line_start"],
                        row["message"] or row["evidence"],
                    )
                )
            if len(evidence) >= limit:
                return evidence

        for row in store.conn.execute(
            """
            SELECT v.name AS vulnerability, d.name AS dependency, e.properties AS properties
            FROM edges e
            JOIN nodes v ON v.key = e.source
            JOIN nodes d ON d.key = e.target
            WHERE e.kind = 'AFFECTS_DEPENDENCY'
            ORDER BY v.name, d.name
            LIMIT 50
            """
        ):
            haystack = " ".join(str(row[key]) for key in row.keys()).lower()
            if not terms or any(term in haystack for term in terms):
                evidence.append(
                    Evidence(
                        "vulnerability",
                        row["vulnerability"],
                        "",
                        0,
                        f"affects dependency {row['dependency']} ({row['properties']})",
                    )
                )
            if len(evidence) >= limit:
                return evidence

        for row in store.conn.execute(
            """
            SELECT kind, name, file_path, line_start, properties
            FROM nodes
            WHERE kind != 'File'
            ORDER BY file_path, line_start
            LIMIT 200
            """
        ):
            haystack = " ".join(str(row[k]) for k in row.keys()).lower()
            if any(term in haystack for term in terms):
                evidence.append(
                    Evidence("node", row["name"], row["file_path"], row["line_start"], row["kind"])
                )
            if len(evidence) >= limit:
                return evidence
        return evidence
    finally:
        store.close()


def answer_question(repo_root: Path, question: str) -> str:
    evidence = retrieve_evidence(repo_root, question)
    if not evidence:
        return (
            "No matching security evidence found. "
            "Run `cybergraph build` first or ask a broader question."
        )

    lines = [f"Question: {question}", "", "Evidence:"]
    for item in evidence:
        location = f"{item.file_path}:{item.line}" if item.line else item.file_path
        lines.append(f"- [{item.kind}] {item.title} at {location} - {item.detail}")
    lines.append("")
    lines.append(
        "Next step: inspect the listed paths and verify whether the control or sink "
        "is reachable in the changed flow."
    )
    return "\n".join(lines)

"""SARIF export for CyberGraph findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cybergraph.graph import GraphStore

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def export_sarif(repo_root: Path, output: Path) -> Path:
    repo_root = repo_root.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    sarif = build_sarif(repo_root)
    output.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return output


def build_sarif(repo_root: Path) -> dict[str, Any]:
    store = GraphStore.open_for_repo(repo_root.resolve())
    try:
        rows = store.conn.execute(
            """
            SELECT rule_id, severity, message, file_path, line_start, line_end, cwe, owasp, tool, evidence
            FROM findings
            ORDER BY rule_id, file_path, line_start
            """
        ).fetchall()
    finally:
        store.close()

    rules = _rules(rows)
    results = [_result(row) for row in rows]
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CyberGraph",
                        "informationUri": "https://github.com/khan-ARK/cybergraph",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _rules(rows) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for row in rows:
        rule_id = row["rule_id"]
        if rule_id in rules:
            continue
        tags = [value for value in (row["cwe"], row["owasp"], row["tool"]) if value]
        rules[rule_id] = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": row["message"] or rule_id},
            "properties": {"tags": tags, "precision": "medium"},
        }
    return rules


def _result(row) -> dict[str, Any]:
    return {
        "ruleId": row["rule_id"],
        "level": _sarif_level(row["severity"]),
        "message": {"text": row["message"]},
        "locations": [_location(row)],
        "properties": {
            "severity": row["severity"],
            "tool": row["tool"],
            "evidence": row["evidence"],
        },
    }


def _location(row) -> dict[str, Any]:
    uri = row["file_path"] or "."
    start_line = max(int(row["line_start"] or 1), 1)
    end_line = max(int(row["line_end"] or start_line), start_line)
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": start_line, "endLine": end_line},
        }
    }


def _sarif_level(severity: str) -> str:
    lowered = severity.lower()
    if lowered in {"critical", "high", "error"}:
        return "error"
    if lowered in {"medium", "warning", "warn"}:
        return "warning"
    return "note"

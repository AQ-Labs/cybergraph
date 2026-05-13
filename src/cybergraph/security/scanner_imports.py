"""Import findings from common security scanner report formats."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cybergraph.graph import Finding


def load_scanner_findings(report_path: Path) -> list[Finding]:
    data = json.loads(report_path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "results" in data:
        return _load_semgrep(data)
    if isinstance(data, dict) and "runs" in data:
        return _load_sarif(data)
    if isinstance(data, list) and data and "RuleID" in data[0]:
        return _load_gitleaks(data)
    return []


def _load_semgrep(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        start = item.get("start", {})
        findings.append(
            Finding(
                rule_id=item.get("check_id", "semgrep"),
                severity=str(extra.get("severity", "warning")).lower(),
                message=extra.get("message", "Semgrep finding"),
                file_path=item.get("path", ""),
                line_start=int(start.get("line", 0) or 0),
                line_end=int(item.get("end", {}).get("line", start.get("line", 0)) or 0),
                cwe=_first_metadata(extra, "cwe"),
                owasp=_first_metadata(extra, "owasp"),
                tool="semgrep",
                evidence=item.get("extra", {}).get("lines", ""),
            )
        )
    return findings


def _load_sarif(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for run in data.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "sarif")
        rules = {
            rule.get("id", ""): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "sarif")
            rule = rules.get(rule_id, {})
            location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            region = location.get("region", {})
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=result.get("level", "warning"),
                    message=result.get("message", {}).get("text", rule.get("name", "SARIF finding")),
                    file_path=location.get("artifactLocation", {}).get("uri", ""),
                    line_start=int(region.get("startLine", 0) or 0),
                    line_end=int(region.get("endLine", region.get("startLine", 0)) or 0),
                    tool=tool,
                    evidence=rule.get("shortDescription", {}).get("text", ""),
                )
            )
    return findings


def _load_gitleaks(data: list[dict[str, Any]]) -> list[Finding]:
    return [
        Finding(
            rule_id=item.get("RuleID", "gitleaks"),
            severity="high",
            message=item.get("Description", "Potential secret detected"),
            file_path=item.get("File", ""),
            line_start=int(item.get("StartLine", 0) or 0),
            line_end=int(item.get("EndLine", item.get("StartLine", 0)) or 0),
            tool="gitleaks",
            evidence=item.get("Match", ""),
        )
        for item in data
    ]


def _first_metadata(extra: dict[str, Any], key: str) -> str:
    value = extra.get("metadata", {}).get(key, "")
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value)

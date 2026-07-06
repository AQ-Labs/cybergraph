"""Import validated findings from Strix AI pentest runs.

Strix (https://github.com/usestrix/strix) is an autonomous AI pentesting tool.
Unlike a static scanner, every issue Strix reports is *dynamically validated*
with a working proof-of-concept, so a Strix finding is much stronger evidence
than a static candidate: it is known-reachable and known-exploitable.

This module normalizes a Strix run into CyberGraph :class:`Finding` objects
(``tool="strix"``) so validated exploits live in the same graph as static
findings, flow into SARIF export, and can boost risk prioritization. The
``tool == "strix"`` marker is the canonical "PoC-validated" signal used by the
rest of the pipeline.

A Strix run directory contains ``vulnerabilities.json`` (a list of records like
the example below). We accept either that directory or the JSON file directly::

    {
      "id": "vuln-0001",
      "title": "Broken Function-Level Authorization on GET /users",
      "severity": "high",
      "description": "...",
      "cwe": "CWE-863",
      "cvss": 7.5,
      "endpoint": "/users",
      "method": "GET",
      "poc_description": "...",
      "poc_script_code": "...",
      "code_locations": [{"file": "app.py", "start_line": 6, "end_line": 8, ...}]
    }
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cybergraph.graph import Finding
from cybergraph.security.risk import RiskScore, score_risk

#: ``Finding.tool`` value that marks a dynamically validated (PoC-backed) issue.
VALIDATED_TOOL = "strix"

#: Files that hold the machine-readable findings inside a Strix run directory.
_VULN_FILENAMES = ("vulnerabilities.json", "findings.json")

_SEVERITY_ALIASES = {
    "informational": "low",
    "info": "low",
    "none": "low",
    "moderate": "medium",
}


def load_strix_findings(path: Path) -> list[Finding]:
    """Load validated findings from a Strix run directory or JSON file."""
    json_path = _resolve_findings_json(Path(path))
    if json_path is None:
        return []
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    records = _records(data)
    return [_finding_from_record(record) for record in records if isinstance(record, dict)]


def score_validated_finding(severity: str, cvss: float | None = None) -> RiskScore:
    """Score a PoC-validated finding.

    Validation removes the two biggest sources of static-analysis noise: the
    issue is proven reachable and proven exploitable. We therefore pin
    reachability, exposure, and confidence high, and drive exploitability/impact
    from CVSS when present, otherwise from severity.
    """
    sev = _normalize_severity(severity)
    severity_weight = {"critical": 1.0, "high": 0.8, "medium": 0.55, "low": 0.3}.get(sev, 0.4)
    cvss_weight = None
    if cvss is not None:
        try:
            cvss_weight = max(0.0, min(1.0, float(cvss) / 10.0))
        except (TypeError, ValueError):
            cvss_weight = None
    return score_risk(
        reachability=1.0,
        # A working proof-of-concept means exploitability is proven, not inferred.
        exploitability=0.95,
        exposure=1.0,
        impact=max(severity_weight, cvss_weight or 0.0),
        controls=0.0,
        confidence="high",
    )


def _resolve_findings_json(path: Path) -> Path | None:
    if path.is_file():
        return path
    if path.is_dir():
        for name in _VULN_FILENAMES:
            candidate = path / name
            if candidate.is_file():
                return candidate
    return None


def _records(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("vulnerabilities", "findings", "results"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def _finding_from_record(record: dict[str, Any]) -> Finding:
    location = _first_location(record)
    file_path = str(location.get("file") or record.get("file") or record.get("endpoint") or "")
    line_start = _int(location.get("start_line"))
    line_end = _int(location.get("end_line")) or line_start
    cwe = str(record.get("cwe") or "")
    rule_id = cwe or f"strix/{record.get('id') or 'finding'}"
    return Finding(
        rule_id=rule_id,
        severity=_normalize_severity(str(record.get("severity", "medium"))),
        message=str(record.get("title") or record.get("description") or "Strix validated finding"),
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        cwe=cwe,
        owasp=str(record.get("owasp") or ""),
        tool=VALIDATED_TOOL,
        evidence=_evidence(record),
    )


def _evidence(record: dict[str, Any]) -> str:
    """Human-readable, PoC-backed evidence string for the finding."""
    parts = ["validated-by=strix"]
    endpoint = record.get("endpoint")
    method = record.get("method")
    if endpoint:
        parts.append(f"{method or 'ANY'} {endpoint}")
    cvss = record.get("cvss")
    if cvss is not None:
        parts.append(f"CVSS {cvss}")
    poc = record.get("poc_description") or record.get("impact")
    if poc:
        parts.append(f"PoC: {str(poc).strip()[:400]}")
    return " | ".join(parts)


def _first_location(record: dict[str, Any]) -> dict[str, Any]:
    locations = record.get("code_locations")
    if isinstance(locations, list) and locations and isinstance(locations[0], dict):
        return locations[0]
    return {}


def _normalize_severity(severity: str) -> str:
    lowered = severity.strip().lower()
    return _SEVERITY_ALIASES.get(lowered, lowered or "medium")


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

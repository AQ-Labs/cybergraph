"""Import dependency vulnerability reports into the graph."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cybergraph.graph import Edge, Finding, GraphStore, Node


EDGE_AFFECTS_DEPENDENCY = "AFFECTS_DEPENDENCY"


@dataclass(frozen=True)
class VulnerabilityRecord:
    vuln_id: str
    package: str
    ecosystem: str = ""
    installed_version: str = ""
    severity: str = "unknown"
    summary: str = ""
    source: str = "osv"


def load_vulnerability_report(report_path: Path) -> list[VulnerabilityRecord]:
    data = json.loads(report_path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "results" in data:
        return _load_osv_scanner(data)
    if isinstance(data, dict) and "vulnerabilities" in data:
        return _load_npm_audit(data)
    return []


def import_vulnerability_report(repo_root: Path, report_path: Path) -> dict[str, int]:
    records = load_vulnerability_report(report_path)
    store = GraphStore.open_for_repo(repo_root.resolve())
    try:
        dep_index = _dependency_index(store)
        nodes: list[Node] = []
        edges: list[Edge] = []
        findings: list[Finding] = []
        for record in records:
            vuln_key = f"vulnerability::{record.vuln_id}"
            nodes.append(
                Node(
                    "Vulnerability",
                    vuln_key,
                    record.vuln_id,
                    "",
                    0,
                    0,
                    {
                        "package": record.package,
                        "ecosystem": record.ecosystem,
                        "installed_version": record.installed_version,
                        "severity": record.severity,
                        "summary": record.summary,
                        "layer": "dependency",
                    },
                )
            )
            for dep_key in dep_index.get(record.package.lower(), []):
                edges.append(
                    Edge(
                        EDGE_AFFECTS_DEPENDENCY,
                        vuln_key,
                        dep_key,
                        "",
                        0,
                        {
                            "package": record.package,
                            "installed_version": record.installed_version,
                            "severity": record.severity,
                        },
                    )
                )
            findings.append(
                Finding(
                    rule_id=record.vuln_id,
                    severity=record.severity,
                    message=f"{record.package} is affected by {record.vuln_id}: {record.summary}",
                    file_path="",
                    tool=record.source,
                    evidence=f"{record.ecosystem}:{record.package}@{record.installed_version}",
                )
            )
        store.upsert_nodes(nodes)
        store.add_edges(edges)
        store.add_findings(findings)
        return {"vulnerabilities": len(records), "matched_dependencies": len(edges)}
    finally:
        store.close()


def _dependency_index(store: GraphStore) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for row in store.conn.execute("SELECT key, name FROM nodes WHERE kind = 'Dependency'"):
        index.setdefault(row["name"].lower(), []).append(row["key"])
    return index


def _load_osv_scanner(data: dict[str, Any]) -> list[VulnerabilityRecord]:
    records: list[VulnerabilityRecord] = []
    for result in data.get("results", []):
        for package_entry in result.get("packages", []):
            package = package_entry.get("package", {})
            package_name = package.get("name", "")
            ecosystem = package.get("ecosystem", "")
            version = package.get("version", "")
            for vuln in package_entry.get("vulnerabilities", []):
                records.append(
                    VulnerabilityRecord(
                        vuln_id=vuln.get("id", "OSV-UNKNOWN"),
                        package=package_name,
                        ecosystem=ecosystem,
                        installed_version=version,
                        severity=_osv_severity(vuln),
                        summary=vuln.get("summary", ""),
                        source="osv-scanner",
                    )
                )
    return records


def _load_npm_audit(data: dict[str, Any]) -> list[VulnerabilityRecord]:
    records: list[VulnerabilityRecord] = []
    for package_name, vuln in data.get("vulnerabilities", {}).items():
        via = vuln.get("via", [])
        vuln_id = package_name
        summary = vuln.get("title", "")
        if via and isinstance(via[0], dict):
            vuln_id = via[0].get("source") or via[0].get("url") or package_name
            summary = via[0].get("title", summary)
        records.append(
            VulnerabilityRecord(
                vuln_id=str(vuln_id),
                package=package_name,
                ecosystem="npm",
                installed_version=str(vuln.get("range", "")),
                severity=str(vuln.get("severity", "unknown")).lower(),
                summary=summary,
                source="npm-audit",
            )
        )
    return records


def _osv_severity(vuln: dict[str, Any]) -> str:
    severities = vuln.get("severity") or []
    if not severities:
        return "unknown"
    score = str(severities[0].get("score", "")).upper()
    if score.startswith("CVSS:"):
        parts = dict(part.split(":", 1) for part in score.split("/") if ":" in part)
        availability = parts.get("A", "")
        confidentiality = parts.get("C", "")
        integrity = parts.get("I", "")
        if "H" in {availability, confidentiality, integrity}:
            return "high"
        if "L" in {availability, confidentiality, integrity}:
            return "medium"
    return "unknown"

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
    aliases: tuple[str, ...] = ()
    advisory_urls: tuple[str, ...] = ()
    cvss_score: float | None = None
    cvss_vector: str = ""
    epss_score: float | None = None
    kev: bool = False
    exploit_maturity: str = ""


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
                        "aliases": list(record.aliases),
                        "advisory_urls": list(record.advisory_urls),
                        "cvss_score": record.cvss_score,
                        "cvss_vector": record.cvss_vector,
                        "epss_score": record.epss_score,
                        "kev": record.kev,
                        "exploit_maturity": record.exploit_maturity,
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


def enrich_vulnerabilities(repo_root: Path, report_path: Path) -> dict[str, int]:
    """Merge offline advisory intelligence into existing Vulnerability nodes.

    Expected JSON shape:
    ``{"advisories": [{"id": "CVE-...", "epss": 0.42, "kev": true, ...}]}``.
    Aliases are matched too, so an EPSS/CISA feed keyed by CVE can enrich a GHSA node
    when that alias was imported from OSV.
    """
    enrichment = _load_advisory_enrichment(report_path)
    if not enrichment:
        return {"advisories": 0, "matched_vulnerabilities": 0}

    store = GraphStore.open_for_repo(repo_root.resolve())
    try:
        nodes: list[Node] = []
        matched = 0
        for row in store.conn.execute(
            "SELECT key, name, properties FROM nodes WHERE kind = 'Vulnerability'"
        ):
            props = _loads(row["properties"])
            candidates = {row["name"], *props.get("aliases", [])}
            merged = {}
            for candidate in candidates:
                merged.update(enrichment.get(str(candidate), {}))
            if not merged:
                continue
            matched += 1
            props.update({key: value for key, value in merged.items() if value not in (None, "", [])})
            nodes.append(Node("Vulnerability", row["key"], row["name"], "", 0, 0, props))
        store.upsert_nodes(nodes)
        return {"advisories": len(enrichment), "matched_vulnerabilities": matched}
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
                        aliases=tuple(vuln.get("aliases") or ()),
                        advisory_urls=tuple(_reference_urls(vuln)),
                        cvss_score=_cvss_numeric_score(vuln),
                        cvss_vector=_cvss_vector(vuln),
                        epss_score=_optional_float(vuln.get("epss") or vuln.get("epss_score")),
                        kev=bool(vuln.get("kev") or vuln.get("known_exploited")),
                        exploit_maturity=str(vuln.get("exploit_maturity") or ""),
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
                advisory_urls=tuple(_npm_urls(vuln)),
                cvss_score=_optional_float(vuln.get("cvss", {}).get("score")) if isinstance(vuln.get("cvss"), dict) else None,
                cvss_vector=str(vuln.get("cvss", {}).get("vectorString", "")) if isinstance(vuln.get("cvss"), dict) else "",
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


def _load_advisory_enrichment(report_path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(report_path.read_text(encoding="utf-8"))
    entries = data.get("advisories", []) if isinstance(data, dict) else []
    enrichment: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        vuln_id = str(entry.get("id") or entry.get("vuln_id") or entry.get("cve") or "")
        aliases = tuple(str(alias) for alias in entry.get("aliases", []) if alias)
        if not vuln_id and not aliases:
            continue
        payload = {
            "aliases": sorted(set(aliases)),
            "advisory_urls": _entry_urls(entry),
            "cvss_score": _optional_float(entry.get("cvss_score") or entry.get("cvss")),
            "cvss_vector": str(entry.get("cvss_vector") or ""),
            "epss_score": _optional_float(entry.get("epss_score") or entry.get("epss")),
            "kev": bool(entry.get("kev") or entry.get("cisa_kev") or entry.get("known_exploited")),
            "exploit_maturity": str(entry.get("exploit_maturity") or entry.get("exploit") or ""),
        }
        for key in (vuln_id, *aliases):
            if key:
                enrichment[key] = payload
    return enrichment


def _reference_urls(vuln: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for ref in vuln.get("references") or []:
        if isinstance(ref, dict) and ref.get("url"):
            urls.append(str(ref["url"]))
    return urls


def _npm_urls(vuln: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for via in vuln.get("via", []):
        if isinstance(via, dict) and via.get("url"):
            urls.append(str(via["url"]))
    return urls


def _entry_urls(entry: dict[str, Any]) -> list[str]:
    urls = entry.get("advisory_urls") or entry.get("urls") or []
    if isinstance(urls, str):
        return [urls]
    return [str(url) for url in urls if url]


def _cvss_vector(vuln: dict[str, Any]) -> str:
    for severity in vuln.get("severity") or []:
        score = str(severity.get("score", ""))
        if score.startswith("CVSS:"):
            return score
    return str(vuln.get("cvss_vector") or "")


def _cvss_numeric_score(vuln: dict[str, Any]) -> float | None:
    for severity in vuln.get("severity") or []:
        value = severity.get("score")
        numeric = _optional_float(value)
        if numeric is not None:
            return numeric
    return _optional_float(vuln.get("cvss_score"))


def _optional_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _loads(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}

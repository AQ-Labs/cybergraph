"""Local investigation summaries for dashboards and Markdown exports."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security.attack_paths import find_attack_paths
from cybergraph.security.cloud import find_cloud_code_paths
from cybergraph.security.iac_paths import find_iac_attack_paths
from cybergraph.security.sca import prioritize_vulnerabilities
from cybergraph.security.secrets import find_secret_exposures
from cybergraph.security.strix_imports import VALIDATED_TOOL, score_validated_finding


@dataclass(frozen=True)
class TopRisk:
    category: str
    title: str
    risk_score: int
    risk_label: str
    detail: str


def _validated_findings(repo_root: Path) -> list[TopRisk]:
    """PoC-validated (Strix) findings already imported into the graph.

    These are dynamically confirmed and always rank at the top: a working
    exploit is the strongest evidence CyberGraph can carry.
    """
    db = repo_root / ".cybergraph" / "graph.db"
    if not db.exists():
        return []
    store = GraphStore.open_for_repo(repo_root)
    try:
        rows = store.conn.execute(
            "SELECT rule_id, severity, message, file_path, line_start, evidence "
            "FROM findings WHERE tool = ? ORDER BY file_path, line_start",
            (VALIDATED_TOOL,),
        ).fetchall()
    finally:
        store.close()
    risks: list[TopRisk] = []
    for row in rows:
        cvss = _cvss_from_evidence(row["evidence"])
        risk = score_validated_finding(row["severity"], cvss)
        location = f"{row['file_path']}:{row['line_start']}" if row["file_path"] else "app"
        risks.append(
            TopRisk(
                "validated",
                f"{row['message']} ({location})",
                risk.score,
                risk.label,
                "PoC-validated by Strix",
            )
        )
    return risks


def _cvss_from_evidence(evidence: str | None) -> float | None:
    if not evidence:
        return None
    for part in evidence.split("|"):
        token = part.strip()
        if token.upper().startswith("CVSS "):
            try:
                return float(token[5:].strip())
            except ValueError:
                return None
    return None


def collect_top_risks(repo_root: Path, limit: int = 10) -> list[TopRisk]:
    risks: list[TopRisk] = list(_validated_findings(repo_root))
    for path in find_attack_paths(repo_root, limit=50):
        if path.risk:
            risks.append(
                TopRisk(
                    "attack-path",
                    f"{path.entrypoint} -> {path.sink}",
                    path.risk.score,
                    path.risk.label,
                    "data-reachable" if path.data_reachable else "structural reachability",
                )
            )
    for exposure in find_secret_exposures(repo_root):
        risks.append(
            TopRisk(
                "secret",
                f"{exposure.function} -> {exposure.sink}",
                exposure.risk.score,
                exposure.risk.label,
                "entrypoint-reachable" if exposure.entrypoint_reachable else "internal",
            )
        )
    for path in find_iac_attack_paths(repo_root):
        if path.risk:
            risks.append(
                TopRisk(
                    "iac",
                    f"{path.entrypoint} -> {path.sink}",
                    path.risk.score,
                    path.risk.label,
                    "public exposure to privileged resource",
                )
            )
    for path in find_cloud_code_paths(repo_root):
        risks.append(
            TopRisk(
                "cloud-code",
                f"{path.resource} -> {path.code}",
                path.risk.score,
                path.risk.label,
                f"reaches {path.sink}" if path.sink else "resource referenced by code",
            )
        )
    for vuln in prioritize_vulnerabilities(repo_root):
        if vuln.risk:
            risks.append(
                TopRisk(
                    "dependency",
                    f"{vuln.vuln_id} affects {vuln.package}",
                    vuln.risk.score,
                    vuln.risk.label,
                    vuln.reach_tier,
                )
            )
    # Highest score first; on ties, PoC-validated findings outrank static ones.
    risks.sort(
        key=lambda risk: (-risk.risk_score, risk.category != "validated", risk.category, risk.title)
    )
    return risks[:limit]


def format_top_risks(risks: list[TopRisk]) -> str:
    if not risks:
        return (
            "No prioritized risks found. "
            "Build the graph and import vulnerability reports for more context."
        )
    lines = [f"Top risks: {len(risks)}"]
    for risk in risks:
        lines.append(
            f"- [{risk.risk_label.upper()} {risk.risk_score}/100] "
            f"{risk.category}: {risk.title} ({risk.detail})"
        )
    return "\n".join(lines)


def export_investigation_markdown(repo_root: Path, output: Path, limit: int = 10) -> Path:
    risks = collect_top_risks(repo_root, limit=limit)
    lines = [
        "# CyberGraph Investigation",
        "",
        "## Top Risks",
        "",
    ]
    if risks:
        for risk in risks:
            lines.append(
                f"- **{risk.risk_label.upper()} {risk.risk_score}/100** "
                f"`{risk.category}` {risk.title} - {risk.detail}"
            )
    else:
        lines.append("No prioritized risks found.")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output

"""Reachability-based SCA prioritization.

`import-vulns` records every CVE from a scanner report as a finding, regardless of
whether the affected package is actually used. This module re-ranks those CVEs by
**severity x reachability** so developers triage *reachable* vulnerabilities first:

  entrypoint-reachable  > imported            > declared-only
  (used in a file that    (imported somewhere   (in a manifest but no import
   also exposes an         but not in an          found in scanned code)
   entrypoint)             entrypoint file)

Reachability comes from the graph: ``USES_DEPENDENCY`` edges (file imports a declared
dependency) intersected with ``EXPOSES_ENTRYPOINT`` edges. It is purely deterministic
— no LLM — so it is always safe to run.

**Guardrail (the SCA analog of the recall guard):** a CVE is NEVER dropped. An
unused or unmatched dependency is *downgraded and labelled*, never hidden, because
the import scan is best-effort (transitive and dynamically imported packages exist).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security.ontology import EDGE_EXPOSES_ENTRYPOINT, EDGE_USES_DEPENDENCY
from cybergraph.security.risk import RiskScore, score_dependency_vulnerability
from cybergraph.security.vulnerabilities import EDGE_AFFECTS_DEPENDENCY

TIER_ENTRYPOINT = "entrypoint-reachable"
TIER_IMPORTED = "imported"
TIER_DECLARED = "declared-only"

_REACH_WEIGHT = {TIER_ENTRYPOINT: 3, TIER_IMPORTED: 2, TIER_DECLARED: 1}
_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1}


@dataclass(frozen=True)
class VulnPriority:
    vuln_id: str
    package: str
    severity: str
    reach_tier: str
    used_by: tuple[str, ...]
    score: int
    priority: str
    rationale: str
    epss_score: float | None = None
    kev: bool = False
    exploit_maturity: str = ""
    risk: RiskScore | None = None


def _severity_weight(severity: str) -> int:
    # Unknown severities weigh 1 (never 0) so an unrated CVE is still ranked, never dropped.
    return _SEVERITY_WEIGHT.get((severity or "").strip().lower(), 1)


def _priority_label(score: int) -> str:
    if score >= 9:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def _rationale(
    severity: str,
    tier: str,
    package: str,
    files: list[str],
    linked: bool,
    props: dict,
) -> str:
    sev = severity or "unknown"
    where = ", ".join(files[:3]) if files else ""
    intel = _intel_suffix(props)
    if tier == TIER_ENTRYPOINT:
        return f"{sev} severity; `{package}` is imported in {where}, which exposes an entrypoint — reachable from external input.{intel}"
    if tier == TIER_IMPORTED:
        return f"{sev} severity; `{package}` is imported in {where} but not in an entrypoint file.{intel}"
    if not linked:
        return f"{sev} severity; no matching dependency node in the graph — retained for review (verify package name/ecosystem).{intel}"
    return (
        f"{sev} severity; `{package}` is declared but no import was found in scanned code — "
        f"likely unreachable (transitive/dynamic use possible). Retained, not dropped.{intel}"
    )


def prioritize_vulnerabilities(repo_root: Path) -> list[VulnPriority]:
    """Rank dependency vulnerabilities by severity x reachability (highest first).

    Every Vulnerability node in the graph appears exactly once in the result; none
    is ever filtered out (the never-drop guardrail)."""
    store = GraphStore.open_for_repo(Path(repo_root).resolve())
    try:
        vulns: dict[str, tuple[str, dict]] = {}
        for row in store.conn.execute(
            "SELECT key, name, properties FROM nodes WHERE kind = 'Vulnerability'"
        ):
            vulns[row["key"]] = (row["name"], json.loads(row["properties"] or "{}"))

        affects: dict[str, list[str]] = {}
        for row in store.conn.execute(
            "SELECT source, target FROM edges WHERE kind = ?", (EDGE_AFFECTS_DEPENDENCY,)
        ):
            affects.setdefault(row["source"], []).append(row["target"])

        uses: dict[str, set[str]] = {}
        for row in store.conn.execute(
            "SELECT source, target FROM edges WHERE kind = ?", (EDGE_USES_DEPENDENCY,)
        ):
            uses.setdefault(row["target"], set()).add(row["source"])

        entry_files = {
            row["source"]
            for row in store.conn.execute(
                "SELECT source FROM edges WHERE kind = ?", (EDGE_EXPOSES_ENTRYPOINT,)
            )
        }
    finally:
        store.close()

    results: list[VulnPriority] = []
    for vuln_key, (vuln_id, props) in vulns.items():
        package = props.get("package", "")
        severity = props.get("severity", "unknown")
        dep_keys = affects.get(vuln_key, [])
        using_files: set[str] = set()
        for dep_key in dep_keys:
            using_files |= uses.get(dep_key, set())

        if using_files & entry_files:
            tier = TIER_ENTRYPOINT
        elif using_files:
            tier = TIER_IMPORTED
        else:
            tier = TIER_DECLARED

        score = _severity_weight(severity) * _REACH_WEIGHT[tier]
        files = sorted(using_files)
        epss = _optional_float(props.get("epss_score"))
        kev = bool(props.get("kev"))
        exploit_maturity = str(props.get("exploit_maturity") or "")
        risk = score_dependency_vulnerability(
            severity=severity,
            reach_tier=tier,
            epss_score=epss,
            kev=kev,
            exploit_maturity=exploit_maturity,
        )
        results.append(
            VulnPriority(
                vuln_id=vuln_id,
                package=package,
                severity=severity,
                reach_tier=tier,
                used_by=tuple(files),
                score=score,
                priority=_priority_label(score),
                rationale=_rationale(severity, tier, package, files, bool(dep_keys), props),
                epss_score=epss,
                kev=kev,
                exploit_maturity=exploit_maturity,
                risk=risk,
            )
        )

    results.sort(key=lambda v: (-(v.risk.score if v.risk else 0), -v.score, v.vuln_id))
    return results


def format_sca(results: list[VulnPriority]) -> str:
    if not results:
        return "No dependency vulnerabilities in the graph. Run 'import-vulns <report.json>' first."
    reachable = [r for r in results if r.reach_tier != TIER_DECLARED]
    declared = [r for r in results if r.reach_tier == TIER_DECLARED]
    lines = [
        f"SCA prioritization: {len(results)} vulnerabilit(y/ies) — "
        f"{len(reachable)} reachable, {len(declared)} declared-only (retained, ranked last)."
    ]
    for r in results:
        lines.append(
            f"  [{r.priority.upper()}] {r.vuln_id}  {r.package}  "
            f"(severity={r.severity}, {r.reach_tier}, score={r.score})"
        )
        if r.risk:
            lines.append(f"      Risk: {r.risk.label.upper()} {r.risk.score}/100 ({r.risk.rationale})")
        lines.append(f"      {r.rationale}")
    return "\n".join(lines)


def _intel_suffix(props: dict) -> str:
    details: list[str] = []
    epss = _optional_float(props.get("epss_score"))
    if epss is not None:
        details.append(f"EPSS={epss:.3f}")
    if props.get("kev"):
        details.append("CISA KEV")
    if props.get("exploit_maturity"):
        details.append(f"exploit={props['exploit_maturity']}")
    if not details:
        return ""
    return " Advisory intelligence: " + ", ".join(details) + "."


def _optional_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

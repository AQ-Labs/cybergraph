"""Guided one-command onboarding: init -> build -> analyze -> report."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.init_project import init_project
from cybergraph.orchestrator import run_full_analysis
from cybergraph.visualize import generate_html_report


@dataclass
class QuickstartResult:
    report_path: Path
    steps: list[str] = field(default_factory=list)
    top_risk: str | None = None


def run_quickstart(repo_root: Path, *, with_source: bool = False) -> QuickstartResult:
    repo_root = Path(repo_root).resolve()
    steps: list[str] = []

    if not (repo_root / ".cybergraph.toml").is_file():
        init_project(repo_root)
        steps.append("[1/4] init ... created .cybergraph.toml")
    else:
        steps.append("[1/4] init ... config already present")

    counts = build_graph(repo_root)
    steps.append(f"[2/4] build ... {counts['nodes']} nodes, {counts['findings']} findings")

    result = run_full_analysis(repo_root)
    top = result.top_risks[0] if result.top_risks else None
    top_risk = (
        f"{top.risk_label.upper()} {top.risk_score}/100 {top.category}: {top.title}"
        if top else None
    )
    steps.append(f"[3/4] analyze ... {len(result.top_risks)} risk(s)"
                 + (f"; top: {top_risk}" if top_risk else ""))

    report = generate_html_report(repo_root, with_source=with_source)
    steps.append(f"[4/4] report ... {report}")

    return QuickstartResult(report_path=report, steps=steps, top_risk=top_risk)

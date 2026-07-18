"""Shared analysis result consumed by the CLI, HTML report, and MCP server."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCHEMA = "cybergraph.analysis/1"


@dataclass(frozen=True)
class AnalysisResult:
    repo: str
    counts: dict[str, int]
    top_risks: list[Any]
    attack_paths: list[Any]
    secret_exposures: list[Any]
    sca: list[Any]
    iac_paths: list[Any]
    cloud_code_paths: list[Any]
    layers: list[Any]
    truncated: bool = False
    timings: dict[str, float] = field(default_factory=dict)
    llm_configured: bool = False
    errors: dict[str, str] = field(default_factory=dict)


def to_json(result: AnalysisResult) -> dict[str, Any]:
    """Stable, versioned JSON view (schema ``cybergraph.analysis/1``)."""
    return {
        "schema": SCHEMA,
        "repo": result.repo,
        "counts": dict(result.counts),
        "truncated": bool(result.truncated),
        "llm_configured": bool(result.llm_configured),
        "timings": {k: round(v, 4) for k, v in result.timings.items()},
        "errors": dict(result.errors),
        "top_risks": [
            {
                "category": r.category, "title": r.title,
                "risk_score": r.risk_score, "risk_label": r.risk_label,
                "detail": r.detail,
            }
            for r in result.top_risks
        ],
        "component_counts": {
            "attack_paths": len(result.attack_paths),
            "secret_exposures": len(result.secret_exposures),
            "sca": len(result.sca),
            "iac_paths": len(result.iac_paths),
            "cloud_code_paths": len(result.cloud_code_paths),
        },
        "layers": [
            {
                "key": l.key, "label": l.label,
                "node_count": l.node_count, "edge_count": l.edge_count,
                "finding_count": l.finding_count,
            }
            for l in result.layers
        ],
    }

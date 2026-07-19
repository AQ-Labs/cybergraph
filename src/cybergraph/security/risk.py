"""Transparent risk scoring helpers.

The score is intentionally simple and explainable: each factor is normalized to
0..1, then weighted into a 0..100 score. Callers keep their domain-specific
evidence, but share the same vocabulary for priority labels and factor output.
"""

from __future__ import annotations

from dataclasses import dataclass

_CONFIDENCE = {"high": 1.0, "medium": 0.75, "low": 0.45, "insufficient": 0.2}
_SEVERITY = {"critical": 1.0, "high": 0.8, "medium": 0.55, "moderate": 0.55, "low": 0.3}


@dataclass(frozen=True)
class RiskScore:
    score: int
    label: str
    factors: dict[str, float | bool | str]
    rationale: str


def score_risk(
    *,
    reachability: float,
    exposure: float,
    exploitability: float,
    impact: float,
    controls: float = 0.0,
    confidence: str = "high",
) -> RiskScore:
    """Return an explainable 0..100 risk score.

    ``controls`` is subtracted, so validation/auth/sanitization can reduce but
    not erase risk. Unknowns should be modeled as lower confidence rather than
    as zero impact.
    """
    reachability = _clamp(reachability)
    exposure = _clamp(exposure)
    exploitability = _clamp(exploitability)
    impact = _clamp(impact)
    controls = _clamp(controls)
    confidence_weight = _CONFIDENCE.get(confidence, 0.45)

    raw = (
        reachability * 0.30
        + exposure * 0.20
        + exploitability * 0.20
        + impact * 0.20
        + confidence_weight * 0.10
        - controls * 0.15
    )
    score = max(1, min(100, round(raw * 100)))
    return RiskScore(
        score=score,
        label=risk_label(score),
        factors={
            "reachability": reachability,
            "exposure": exposure,
            "exploitability": exploitability,
            "impact": impact,
            "controls": controls,
            "confidence": confidence,
        },
        rationale=(
            f"reachability={reachability:.2f}, exposure={exposure:.2f}, "
            f"exploitability={exploitability:.2f}, impact={impact:.2f}, "
            f"controls={controls:.2f}, confidence={confidence}"
        ),
    )


def score_dependency_vulnerability(
    *,
    severity: str,
    reach_tier: str,
    epss_score: float | None = None,
    kev: bool = False,
    exploit_maturity: str = "",
) -> RiskScore:
    reachability = {
        "entrypoint-reachable": 1.0,
        "imported": 0.65,
        "declared-only": 0.25,
    }.get(reach_tier, 0.25)
    exploitability = _clamp(epss_score if epss_score is not None else _SEVERITY.get(severity, 0.35))
    if kev:
        exploitability = max(exploitability, 0.95)
    if exploit_maturity:
        exploitability = max(exploitability, 0.75)
    return score_risk(
        reachability=reachability,
        exposure=1.0 if reach_tier == "entrypoint-reachable" else 0.45,
        exploitability=exploitability,
        impact=_SEVERITY.get(severity, 0.35),
        controls=0.0,
        confidence="high" if reach_tier != "declared-only" else "medium",
    )


def risk_label(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, float(value)))

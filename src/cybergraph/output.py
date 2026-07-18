"""Human-facing rendering of an AnalysisResult (colour + plain, no dependencies)."""

from __future__ import annotations

import os
import sys
from typing import TextIO

from cybergraph.report_model import AnalysisResult

_LEVEL_COLOR = {"critical": "31", "high": "31", "medium": "33", "low": "36"}


def should_color(stream: TextIO | None = None) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def _c(text: str, code: str, color: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if color else text


def render_text(result: AnalysisResult, *, color: bool = True) -> str:
    lines: list[str] = []
    lines.append(_c(f"CyberGraph analysis — {result.repo}", "1", color))
    c = result.counts
    lines.append(
        f"Nodes: {c.get('nodes', 0)} | Edges: {c.get('edges', 0)} | "
        f"Findings: {c.get('findings', 0)}"
    )
    if result.truncated:
        lines.append(_c("! graph truncated — raise --max-nodes to see more", "33", color))

    lines.append("")
    lines.append(_c(f"Top risks ({len(result.top_risks)}):", "1", color))
    if not result.top_risks:
        lines.append("  none found")
    for r in result.top_risks:
        label = _c(f"{r.risk_label.upper()} {r.risk_score}/100",
                   _LEVEL_COLOR.get(r.risk_label.lower(), "0"), color)
        lines.append(f"  [{label}] {r.category}: {r.title}")
        if r.detail:
            lines.append(f"      {r.detail}")

    if result.errors:
        lines.append("")
        lines.append(_c(f"Stages with errors: {', '.join(sorted(result.errors))}", "33", color))
    return "\n".join(lines)

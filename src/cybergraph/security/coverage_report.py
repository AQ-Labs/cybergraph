"""Compose the honesty primitives into one report, and render it.

This surface reports coverage; it makes no accept/block decision. A capability's
status here is derived from whether the files it covers were analyzable, never
from running its predicate -- that is the verdict layer's job (roadmap Tasks
15-17). ``CAP_CHECKED`` means only "the analyzer ran on the files in scope",
never "safe".
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.security.capability import (
    CAPABILITIES,
    NOT_APPLICABLE,
    NOT_SUPPORTED,
    UNKNOWN,
    label_for,
    relevance,
)
from cybergraph.security.coverage import (
    STATUS_FAILED,
    STATUS_UNSUPPORTED,
    FileCoverage,
    assess_coverage,
)
from cybergraph.security.revisions import resolve_revisions

CAP_CHECKED = "checked"


@dataclass(frozen=True)
class CapabilityCoverage:
    capability_id: str
    label: str
    status: str


@dataclass(frozen=True)
class CoverageReport:
    mode: str
    changed_files: tuple[str, ...]
    files: tuple[FileCoverage, ...]
    capabilities: tuple[CapabilityCoverage, ...]
    failure: str = ""

    @property
    def established(self) -> bool:
        return not self.failure


def _covered_file_failed(
    covers: tuple[str, ...], failed_paths: set[str]
) -> bool:
    return any(
        fnmatch(path, pattern) for path in failed_paths for pattern in covers
    )


def build_coverage_report(repo_root, base=None, mode=None) -> CoverageReport:
    repo_root = Path(repo_root).resolve()
    revisions = resolve_revisions(repo_root, base=base, mode=mode)
    if revisions.failure:
        return CoverageReport(revisions.mode, (), (), (), failure=revisions.failure)

    build_graph(repo_root)
    files = assess_coverage(repo_root, revisions.changed_files)
    rel = relevance(revisions.changed_files)

    failed_paths = {f.path for f in files if f.status == STATUS_FAILED}
    has_unsupported = any(f.status == STATUS_UNSUPPORTED for f in files)

    capabilities: list[CapabilityCoverage] = []
    for capability in CAPABILITIES:
        if not rel[capability.id]:
            status = NOT_APPLICABLE
        elif capability.id == "source_analysis_support":
            status = NOT_SUPPORTED if has_unsupported else CAP_CHECKED
        elif not capability.supported:
            status = NOT_SUPPORTED
        elif _covered_file_failed(capability.covers, failed_paths):
            status = UNKNOWN
        else:
            status = CAP_CHECKED
        capabilities.append(
            CapabilityCoverage(capability.id, label_for(capability.id), status)
        )

    return CoverageReport(
        revisions.mode, revisions.changed_files, files, tuple(capabilities)
    )


def format_coverage_report(report: CoverageReport) -> str:
    if not report.established:
        return (
            "Coverage could not be assessed: the comparison could not be "
            f"established.\n  {report.failure}"
        )

    lines = [f"Changed files: {len(report.changed_files)}"]
    for item in report.files:
        suffix = f" ({item.reason})" if item.reason else ""
        lines.append(f"  {item.path:<40} {item.status}{suffix}")

    shown = [c for c in report.capabilities if c.status != NOT_APPLICABLE]
    if shown:
        lines.append("")
        lines.append("Capabilities on this change:")
        for capability in shown:
            lines.append(f"  {capability.label:<40} {capability.status}")
    return "\n".join(lines)

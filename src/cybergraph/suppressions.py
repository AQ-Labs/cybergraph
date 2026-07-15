"""Finding suppression helpers."""

from __future__ import annotations

from fnmatch import fnmatch

from cybergraph.config import CyberGraphConfig
from cybergraph.graph import Finding

INLINE_MARKER = "cybergraph: ignore"


def is_inline_suppressed(lines: list[str], line_no: int, rule_id: str) -> bool:
    """Return true when a finding line or previous line suppresses the rule."""
    for index in (line_no - 1, line_no - 2):
        if index < 0 or index >= len(lines):
            continue
        marker = _inline_marker_text(lines[index])
        if marker is not None and _matches_rule(marker, rule_id):
            return True
    return False


def filter_suppressed_findings(findings: list[Finding], config: CyberGraphConfig) -> list[Finding]:
    return [finding for finding in findings if not is_config_suppressed(finding, config)]


def is_config_suppressed(finding: Finding, config: CyberGraphConfig) -> bool:
    if finding.rule_id in config.suppressed_rules:
        return True
    return any(fnmatch(finding.file_path, pattern) for pattern in config.suppressed_paths)


def _inline_marker_text(line: str) -> str | None:
    lowered = line.lower()
    marker_at = lowered.find(INLINE_MARKER)
    if marker_at == -1:
        return None
    return lowered[marker_at + len(INLINE_MARKER) :].strip()


def _matches_rule(marker: str, rule_id: str) -> bool:
    if not marker:
        return True
    tokens = {part.strip(" ,") for part in marker.replace(",", " ").split()}
    return "all" in tokens or rule_id.lower() in tokens

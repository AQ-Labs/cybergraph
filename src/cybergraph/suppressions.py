"""Finding suppression helpers."""

from __future__ import annotations

from fnmatch import fnmatch

from cybergraph.config import CyberGraphConfig
from cybergraph.graph import UNVERIFIED_SUFFIX, Finding

INLINE_MARKER = "cybergraph: ignore"


def _rule_aliases(rule_id: str) -> set[str]:
    """The ids a suppression may name to cover this finding, lowercased.

    ``CG-SQL-EXEC-UNVERIFIED`` is the same rule reported at lower confidence,
    not a second rule, so accepting ``CG-SQL-EXEC`` on a line accepts it. The
    relation is deliberately one-way: naming the ``-UNVERIFIED`` id suppresses
    only the abstention, and never hides the confirmed finding it might later
    become.
    """
    lowered = rule_id.lower()
    aliases = {lowered}
    suffix = UNVERIFIED_SUFFIX.lower()
    if lowered.endswith(suffix):
        aliases.add(lowered[: -len(suffix)])
    return aliases


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
    aliases = _rule_aliases(finding.rule_id)
    if any(rule.lower() in aliases for rule in config.suppressed_rules):
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
    return "all" in tokens or bool(tokens & _rule_aliases(rule_id))

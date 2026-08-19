"""Finding suppression helpers."""

from __future__ import annotations

from datetime import date
from fnmatch import fnmatch

from cybergraph.config import CyberGraphConfig, Suppression, SuppressionProblem
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


def filter_suppressed_findings(
    findings: list[Finding], config: CyberGraphConfig, today: date | None = None
) -> list[Finding]:
    return [finding for finding in findings if not is_config_suppressed(finding, config, today)]


def is_config_suppressed(
    finding: Finding, config: CyberGraphConfig, today: date | None = None
) -> bool:
    return _rule_suppresses(finding.rule_id, config, today) or _path_suppresses(
        finding.file_path, config, today
    )


def active_suppressions(config: CyberGraphConfig, today: date | None = None) -> list[Suppression]:
    """Accountable suppressions that are valid right now: not expired.

    ``expires is None`` never expires; otherwise the entry is active through
    its expiry date inclusive (``expires >= today``).
    """
    today = today or date.today()
    return [
        entry
        for entry in config.suppressions
        if entry.expires is None or entry.expires >= today
    ]


def suppression_problems(
    config: CyberGraphConfig, today: date | None = None
) -> list[SuppressionProblem]:
    """Parse-time suppression problems plus one per expired accountable entry."""
    today = today or date.today()
    problems = list(config.suppression_problems)
    for entry in config.suppressions:
        if entry.expires is not None and entry.expires < today:
            message = f"expired on {entry.expires.isoformat()}"
            problems.append(SuppressionProblem(entry.kind, entry.matcher, message))
    return problems


#: Labels for the config keys that can make a finding disappear without a line
#: of code changing. Deliberately the same wording as
#: ``security/review._CONFIG_KEYS``, and deliberately free of the bare
#: ``fixed``/``removed`` tokens: a reader -- or a grep -- must be able to tell a
#: statement about configuration from a claim about code at a glance.
CONFIG_KEY_SUPPRESSED_RULES = "[suppressions] rules"
CONFIG_KEY_SUPPRESSED_PATHS = "[suppressions] paths"
CONFIG_KEY_IGNORED_PATHS = "[ignore] paths"


def config_conceals(
    rule_id: str, file_path: str, config: CyberGraphConfig, today: date | None = None
) -> str | None:
    """Which configuration key, if any, explains a finding's *absence*.

    Returns the key's label, or ``None`` when configuration explains nothing --
    only then is the finding genuinely gone from the code.

    One helper, asked by every surface that reports a disappearance, because
    this exact lie has been repaired twice in ``security/review.py`` and was
    still live in ``history.py``: a scan taken after a ``.cybergraph.toml`` was
    added reported the byte-identical, still-vulnerable file as ``fixed``. A
    second copy of the rule could disagree with the one that does the hiding,
    and the direction it would disagree in is the one that tells a human a live
    vulnerability was repaired.

    ``[ignore] paths`` is answered here too. It hides a finding even harder than
    a suppression does -- the file is never opened, so there is nothing left to
    filter -- and "we did not look" must never render as "it is fixed" either.
    """
    # Imported inside the function: ``cybergraph.analysis`` imports the Python
    # analyzer, which imports this module, so a module-scope import is circular.
    from cybergraph.analysis.collector import is_ignored_path

    if _rule_suppresses(rule_id, config, today):
        return CONFIG_KEY_SUPPRESSED_RULES
    if _path_suppresses(file_path, config, today):
        return CONFIG_KEY_SUPPRESSED_PATHS
    if is_ignored_path(file_path, config.ignored_paths):
        return CONFIG_KEY_IGNORED_PATHS
    return None


def _rule_suppresses(rule_id: str, config: CyberGraphConfig, today: date | None = None) -> bool:
    aliases = _rule_aliases(rule_id)
    if any(rule.lower() in aliases for rule in config.suppressed_rules):
        return True
    return any(
        entry.kind == "rule" and entry.matcher.lower() in aliases
        for entry in active_suppressions(config, today)
    )


def _path_suppresses(file_path: str, config: CyberGraphConfig, today: date | None = None) -> bool:
    if any(fnmatch(file_path, pattern) for pattern in config.suppressed_paths):
        return True
    return any(
        entry.kind == "path" and fnmatch(file_path, entry.matcher)
        for entry in active_suppressions(config, today)
    )


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

"""Suppression-matching invariants: the inline window and the config rule match.

Both were uncaught by the suite: the inline marker's line window and whether a
`[suppressions] rules` entry matches by exact id or by substring. Each is a way
a finding can be silenced -- or fail to be -- without any code changing.
"""

from __future__ import annotations

from cybergraph.config import CyberGraphConfig
from cybergraph.graph import Finding
from cybergraph.suppressions import is_config_suppressed, is_inline_suppressed


def _finding(rule_id: str, file_path: str = "app.py") -> Finding:
    return Finding(
        rule_id=rule_id, severity="high", message="m", file_path=file_path, line_start=1
    )


# --- The inline-marker line window -------------------------------------------
# A `# cybergraph: ignore` suppresses the finding on its own line or the line it
# sits directly above (the finding's own line, and the one before it, in 0-based
# `lines`). It must not reach the line *after* it: widening the window to
# include `line_no` silences the next finding down.


def test_inline_marker_on_the_finding_line_suppresses():
    lines = ["open(name)  # cybergraph: ignore", "next()"]
    assert is_inline_suppressed(lines, 1, "CG-PATH-TRAVERSAL")


def test_inline_marker_on_the_previous_line_suppresses():
    lines = ["# cybergraph: ignore", "open(name)"]
    assert is_inline_suppressed(lines, 2, "CG-PATH-TRAVERSAL")


def test_inline_marker_does_not_suppress_the_next_line():
    """A marker on line N must not suppress a finding on line N+1."""
    # Finding on line 1; the marker is on line 2, *below* it.
    lines = ["open(name)", "# cybergraph: ignore"]
    assert not is_inline_suppressed(lines, 1, "CG-PATH-TRAVERSAL")


# --- The config rule match is exact, not a substring --------------------------
# `[suppressions] rules = ["CG-SQL"]` must not swallow `CG-SQL-EXEC`. Only the
# exact id and its `-UNVERIFIED` alias may match; a substring test would let a
# short prefix hide a whole family of rules.


def test_config_rule_match_is_exact_not_substring():
    finding = _finding("CG-SQL-EXEC")
    # A prefix of the real id must not suppress it.
    assert not is_config_suppressed(finding, CyberGraphConfig(suppressed_rules=("CG-SQL",)))
    assert not is_config_suppressed(finding, CyberGraphConfig(suppressed_rules=("CG-SQL-",)))
    # The exact id does, case-insensitively.
    assert is_config_suppressed(finding, CyberGraphConfig(suppressed_rules=("CG-SQL-EXEC",)))
    assert is_config_suppressed(finding, CyberGraphConfig(suppressed_rules=("cg-sql-exec",)))


def test_config_rule_unverified_alias_is_one_way():
    """Naming the confirmed id suppresses the abstention; not the reverse."""
    unverified = _finding("CG-SQL-EXEC-UNVERIFIED")
    confirmed = _finding("CG-SQL-EXEC")
    # The confirmed id covers its own `-UNVERIFIED` abstention.
    assert is_config_suppressed(unverified, CyberGraphConfig(suppressed_rules=("CG-SQL-EXEC",)))
    # Naming only the `-UNVERIFIED` id must never hide the confirmed finding.
    assert not is_config_suppressed(
        confirmed, CyberGraphConfig(suppressed_rules=("CG-SQL-EXEC-UNVERIFIED",))
    )

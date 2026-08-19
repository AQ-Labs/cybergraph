"""Validity + expiry logic for accountable suppressions (fail-open, injectable `today`)."""

from __future__ import annotations

from datetime import date

from cybergraph.config import CyberGraphConfig, Suppression
from cybergraph.suppressions import _rule_suppresses, active_suppressions, suppression_problems

TODAY = date(2026, 6, 1)


def cfg(*s):
    return CyberGraphConfig(suppressions=tuple(s))


def test_active_accountable_suppresses():
    c = cfg(Suppression("rule", "CG-SQL-EXEC", "x", date(2026, 12, 31), ""))
    assert _rule_suppresses("CG-SQL-EXEC", c, today=TODAY) is True


def test_expired_does_not_suppress():
    c = cfg(Suppression("rule", "CG-SQL-EXEC", "x", date(2026, 1, 1), ""))
    assert _rule_suppresses("CG-SQL-EXEC", c, today=TODAY) is False
    assert any("expired" in p.message.lower() for p in suppression_problems(c, today=TODAY))


def test_expires_equal_to_today_still_active():
    """The boundary is inclusive: an entry expiring today is still active.

    Pins ``entry.expires >= today`` against a future refactor to ``>`` -- an
    entry that says "good through today" must not vanish at midnight before
    the day is over.
    """
    c = cfg(Suppression("rule", "CG-SQL-EXEC", "x", TODAY, ""))
    assert _rule_suppresses("CG-SQL-EXEC", c, today=TODAY) is True
    assert not any("expired" in p.message.lower() for p in suppression_problems(c, today=TODAY))


def test_no_expiry_never_expires():
    c = cfg(Suppression("rule", "CG-SQL-EXEC", "x", None, ""))
    assert _rule_suppresses("CG-SQL-EXEC", c, today=TODAY) is True


def test_legacy_still_suppresses():
    c = CyberGraphConfig(suppressed_rules=("CG-SQL-EXEC",))
    assert _rule_suppresses("CG-SQL-EXEC", c, today=TODAY) is True


def test_unverified_alias_still_covered():
    c = cfg(Suppression("rule", "CG-SQL-EXEC", "x", None, ""))
    assert _rule_suppresses("CG-SQL-EXEC-UNVERIFIED", c, today=TODAY) is True


def test_active_suppressions_excludes_expired():
    active = Suppression("rule", "CG-A", "x", date(2026, 12, 31), "")
    expired = Suppression("rule", "CG-B", "x", date(2026, 1, 1), "")
    no_expiry = Suppression("path", "**/*.py", "x", None, "")
    c = cfg(active, expired, no_expiry)
    result = active_suppressions(c, today=TODAY)
    assert active in result
    assert no_expiry in result
    assert expired not in result


def test_suppression_problems_includes_parse_time_and_expiry():
    from cybergraph.config import SuppressionProblem

    expired = Suppression("path", "**/*.py", "x", date(2026, 1, 1), "")
    parse_problem = SuppressionProblem("rule", "", "missing required 'reason'")
    c = CyberGraphConfig(suppressions=(expired,), suppression_problems=(parse_problem,))
    problems = suppression_problems(c, today=TODAY)
    assert parse_problem in problems
    assert any(
        p.kind == "path" and p.matcher == "**/*.py" and "expired on 2026-01-01" in p.message
        for p in problems
    )


def test_path_suppresses_active_accountable_entry():
    from cybergraph.suppressions import _path_suppresses

    c = cfg(Suppression("path", "src/legacy/*.py", "x", date(2026, 12, 31), ""))
    assert _path_suppresses("src/legacy/old.py", c, today=TODAY) is True
    assert _path_suppresses("src/other/new.py", c, today=TODAY) is False


def test_path_suppresses_does_not_match_expired_entry():
    from cybergraph.suppressions import _path_suppresses

    c = cfg(Suppression("path", "src/legacy/*.py", "x", date(2026, 1, 1), ""))
    assert _path_suppresses("src/legacy/old.py", c, today=TODAY) is False


def test_config_conceals_returns_none_for_expired_entry():
    from cybergraph.suppressions import config_conceals

    c = cfg(Suppression("rule", "CG-SQL-EXEC", "x", date(2026, 1, 1), ""))
    assert config_conceals("CG-SQL-EXEC", "app.py", c, today=TODAY) is None


def test_is_config_suppressed_and_filter_thread_today():
    from cybergraph.graph import Finding
    from cybergraph.suppressions import filter_suppressed_findings, is_config_suppressed

    finding = Finding(
        rule_id="CG-SQL-EXEC", severity="high", message="m", file_path="app.py", line_start=1
    )
    active_cfg = cfg(Suppression("rule", "CG-SQL-EXEC", "x", date(2026, 12, 31), ""))
    expired_cfg = cfg(Suppression("rule", "CG-SQL-EXEC", "x", date(2026, 1, 1), ""))

    assert is_config_suppressed(finding, active_cfg, today=TODAY) is True
    assert is_config_suppressed(finding, expired_cfg, today=TODAY) is False

    assert filter_suppressed_findings([finding], active_cfg, today=TODAY) == []
    assert filter_suppressed_findings([finding], expired_cfg, today=TODAY) == [finding]

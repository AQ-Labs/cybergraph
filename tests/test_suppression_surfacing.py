from datetime import date

from cybergraph.config import CyberGraphConfig, Suppression, SuppressionProblem
from cybergraph.security.policy import Policy, ProtectedSet
from cybergraph.security.policy_report import format_policy_report

TODAY = date(2026, 1, 1)


def test_expired_and_missing_reason_suppressions_are_surfaced():
    config = CyberGraphConfig(
        suppressions=(
            Suppression(
                kind="rule",
                matcher="CG-SQL-EXEC",
                reason="temporary",
                expires=date(2025, 1, 1),
                approver="security-team",
            ),
        ),
        suppression_problems=(
            SuppressionProblem(
                kind="path",
                matcher="legacy/*.py",
                message="missing required 'reason'",
            ),
        ),
    )
    text = format_policy_report(Policy(), ProtectedSet({}, frozenset(), ()), config, TODAY)

    assert "CG-SQL-EXEC" in text
    assert "legacy/*.py" in text
    assert "expired" in text
    assert "reason" in text
    assert "security-team" in text


def test_clean_config_has_no_suppression_section():
    config = CyberGraphConfig()
    text = format_policy_report(Policy(), ProtectedSet({}, frozenset(), ()), config, TODAY)

    assert "Suppression problems" not in text

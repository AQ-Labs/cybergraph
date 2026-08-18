"""Task 9: assurance metric suite (false-ACCEPT primary) + patch-pair harness.

Three layers, each pinned separately:

1. ``Metrics`` carries exactly the five required fields and no blended score.
2. The seeded patch-pairs run the REAL ``check_change`` over temp git repos
   (no mocks) and land on the state the scenario demands.
3. A hand-built confusion matrix pins ``evaluate``'s arithmetic without
   depending on the engine at all.
"""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

from cybergraph.security.verdict import STATE_ACCEPT, STATE_REVIEW

BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmark"
sys.path.insert(0, str(BENCHMARK_DIR))

from change_assurance import (  # noqa: E402
    AUTH_GUARD_REGRESSION,
    POLICY_PRESERVING_REFACTOR,
    TAINTED_SQL_INJECTION,
    CaseOutcome,
    Metrics,
    classify_verdict,
    evaluate,
    run_patch_pair,
)


def test_metrics_has_exactly_the_five_required_fields_and_no_blended_score():
    names = {f.name for f in dataclasses.fields(Metrics)}
    assert names == {
        "false_accept_rate",
        "review_precision",
        "abstention_rate",
        "unsupported_rate",
        "recall",
    }
    for banned in ("score", "overall", "grade", "blended"):
        assert not hasattr(Metrics, banned)


def test_metrics_instance_exposes_all_five_fields():
    metrics = evaluate([])
    assert metrics.false_accept_rate == 0.0
    assert metrics.recall == 1.0
    assert metrics.review_precision == 1.0
    assert metrics.abstention_rate == 0.0
    assert metrics.unsupported_rate == 0.0


# --- Seeded patch-pairs: real engine, real temp git repos --------------------


def test_auth_guard_regression_case_should_review(tmp_path):
    """A route that drops its login check, with the route declared protected
    by `cybergraph.policy.toml`, must land on REVIEW driven by a confirmed
    regression -- this is the case a false-ACCEPT here would be the cardinal
    failure this benchmark exists to catch."""
    verdict = run_patch_pair(AUTH_GUARD_REGRESSION, tmp_path)
    assert verdict.state == STATE_REVIEW
    outcome = classify_verdict(AUTH_GUARD_REGRESSION, verdict)
    assert outcome.confirmed_regression, (
        "the auth-guard regression must be a CONFIRMED regression, not a thin "
        f"abstention; verdict reasons: {verdict.reasons}"
    )


def test_tainted_sql_sink_case_should_review():
    """A head state that interpolates user input into `execute(...)` must
    REVIEW. If this comes back ACCEPT, that is a real false-ACCEPT finding in
    the engine, not a test to weaken."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        verdict = run_patch_pair(TAINTED_SQL_INJECTION, Path(tmp))
    assert verdict.state == STATE_REVIEW


def test_policy_preserving_refactor_case_should_accept(tmp_path):
    """A no-op rename that changes no security-relevant behavior must ACCEPT."""
    verdict = run_patch_pair(POLICY_PRESERVING_REFACTOR, tmp_path)
    assert verdict.state == STATE_ACCEPT


# --- Hand-built confusion matrix: pins the arithmetic, no engine involved ----


def _outcome(name, expected, state, *, confirmed=False, unsupported=False):
    return CaseOutcome(
        name=name, expected=expected, state=state,
        confirmed_regression=confirmed, unsupported=unsupported,
    )


def test_evaluate_arithmetic_on_a_known_confusion_matrix():
    """2 regressions (1 caught, 1 missed), 1 safe case correctly accepted, 1
    safe case sent to REVIEW as an abstention, 1 regression REVIEWed only via
    an unsupported reason (still a caught regression, and also unsupported)."""
    cases = [
        _outcome("reg_caught", "regression", STATE_REVIEW, confirmed=True),
        _outcome("reg_missed", "regression", STATE_ACCEPT),
        _outcome("safe_accepted", "no_regression", STATE_ACCEPT),
        _outcome("safe_abstained", "no_regression", STATE_REVIEW, confirmed=False),
        _outcome(
            "reg_unsupported", "regression", STATE_REVIEW,
            confirmed=False, unsupported=True,
        ),
    ]

    metrics = evaluate(cases)

    # regressions = {reg_caught, reg_missed, reg_unsupported} -> n=3
    # missed (ACCEPT) = {reg_missed} -> 1/3
    assert metrics.false_accept_rate == round(1 / 3, 4)
    # caught (REVIEW) = {reg_caught, reg_unsupported} -> 2/3
    assert metrics.recall == round(2 / 3, 4)
    # reviewed = {reg_caught, safe_abstained, reg_unsupported} -> n=3
    # of those, truly regression = {reg_caught, reg_unsupported} -> 2/3
    assert metrics.review_precision == round(2 / 3, 4)
    # abstentions = REVIEW with confirmed_regression=False, over all 5 cases
    # = {safe_abstained, reg_unsupported} -> 2/5
    assert metrics.abstention_rate == round(2 / 5, 4)
    # unsupported = REVIEW driven by an unsupported reason, over all 5 cases
    # = {reg_unsupported} -> 1/5
    assert metrics.unsupported_rate == round(1 / 5, 4)


def test_evaluate_matches_the_brief_example():
    """2 regressions (1 caught, 1 missed), 1 safe case correctly accepted."""
    cases = [
        _outcome("caught", "regression", STATE_REVIEW, confirmed=True),
        _outcome("missed", "regression", STATE_ACCEPT),
        _outcome("safe", "no_regression", STATE_ACCEPT),
    ]

    metrics = evaluate(cases)

    assert metrics.false_accept_rate == 0.5
    assert metrics.recall == 0.5
    assert metrics.review_precision == 1.0  # the one REVIEW was a true regression
    assert metrics.abstention_rate == 0.0
    assert metrics.unsupported_rate == 0.0


def test_ambiguous_cases_are_excluded_from_every_metric():
    scored = [
        _outcome("caught", "regression", STATE_REVIEW, confirmed=True),
        _outcome("safe", "no_regression", STATE_ACCEPT),
    ]
    ambiguous = [_outcome("weird", "ambiguous", STATE_REVIEW, confirmed=True)]

    assert evaluate(scored) == evaluate(scored + ambiguous)


def test_review_precision_guards_divide_by_zero_when_nothing_is_reviewed():
    cases = [
        _outcome("safe1", "no_regression", STATE_ACCEPT),
        _outcome("safe2", "no_regression", STATE_ACCEPT),
    ]
    metrics = evaluate(cases)
    assert metrics.review_precision == 1.0
    assert metrics.false_accept_rate == 0.0
    assert metrics.recall == 1.0

"""Unit tests for the recall guardrail used to gate noise-reduction steps."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmark"
sys.path.insert(0, str(BENCHMARK_DIR))

metrics = pytest.importorskip("metrics")


def _score(name, tp, fp, fn):
    return metrics.CaseScore(name=name, tp=tp, fp=fp, fn=fn)


def test_guardrail_passes_on_full_recall_no_secure_fp():
    scores = [
        _score("vuln_a", tp=1, fp=0, fn=0),
        _score("vuln_b", tp=1, fp=0, fn=0),
        _score("secure_a", tp=0, fp=0, fn=0),
    ]
    result = metrics.recall_guardrail(scores, secure_cases={"secure_a"})
    assert result.passed
    assert result.recall == 1.0
    assert result.secure_false_positives == 0
    assert result.missed_vulnerable == ()
    assert result.violations == ()


def test_guardrail_fails_when_a_true_positive_is_suppressed():
    # Simulates over-aggressive FP-triage dropping a real vulnerability.
    scores = [
        _score("vuln_a", tp=1, fp=0, fn=0),
        _score("vuln_b", tp=0, fp=0, fn=1),  # missed
    ]
    result = metrics.recall_guardrail(scores, secure_cases=set())
    assert not result.passed
    assert "vuln_b" in result.missed_vulnerable
    assert result.recall < 1.0


def test_guardrail_fails_on_secure_baseline_false_positive():
    scores = [
        _score("vuln_a", tp=1, fp=0, fn=0),
        _score("secure_a", tp=0, fp=1, fn=0),  # false alarm on safe code
    ]
    result = metrics.recall_guardrail(scores, secure_cases={"secure_a"})
    assert not result.passed
    assert result.secure_false_positives == 1


def test_guardrail_respects_min_recall_threshold():
    scores = [_score("vuln_a", tp=1, fp=0, fn=0), _score("vuln_b", tp=0, fp=0, fn=1)]
    # With a relaxed threshold the partial recall (0.5) still fails recall but the
    # missed-case violation is what a reviewer reads; lowering min_recall below 0.5 passes recall.
    lenient = metrics.recall_guardrail(scores, secure_cases=set(), min_recall=0.5)
    # recall is exactly 0.5; >= 0.5 so the recall clause passes, but the missed case still flags.
    assert lenient.recall == 0.5
    assert "vuln_b" in lenient.missed_vulnerable

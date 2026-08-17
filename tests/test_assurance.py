from __future__ import annotations

from cybergraph.security import assurance as A  # noqa: N812


def test_trust_composes_to_the_weaker_factor():
    assert A.effective_trust(A.EVIDENCE_STRONG, A.ASSURANCE_BETA) == A.ASSURANCE_BETA
    assert A.effective_trust(A.EVIDENCE_WEAK, A.ASSURANCE_BENCHMARKED) == A.EVIDENCE_WEAK
    assert A.effective_trust(A.EVIDENCE_STRONG, A.ASSURANCE_BENCHMARKED) == A.EVIDENCE_STRONG


def test_confirmed_language_requires_strong_and_benchmarked():
    assert (
        A.phrase_for(A.STATUS_CONFIRMED, A.EVIDENCE_STRONG, A.ASSURANCE_BENCHMARKED)
        == "confirmed"
    )
    # strong evidence but beta capability -> NOT confirmed
    assert A.phrase_for(A.STATUS_CONFIRMED, A.EVIDENCE_STRONG, A.ASSURANCE_BETA) == "possible"
    assert (
        A.phrase_for(A.STATUS_UNRESOLVED, A.EVIDENCE_PARTIAL, A.ASSURANCE_BENCHMARKED)
        == "could not verify"
    )
    assert (
        A.phrase_for(A.STATUS_UNSUPPORTED, A.EVIDENCE_NONE, A.ASSURANCE_UNSUPPORTED)
        == "not evaluated"
    )


def test_law1_forbidden_upgrade_detected():
    assert A.has_epistemic_upgrade("this is confirmed SQL injection", A.STATUS_UNRESOLVED) is True
    assert A.has_epistemic_upgrade("input may reach a SQL sink", A.STATUS_UNRESOLVED) is False

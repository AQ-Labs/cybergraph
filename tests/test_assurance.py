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


def test_matrix_python_is_benchmarked_others_beta():
    assert A.assurance_for("sql_construction", "python", "fastapi") == A.ASSURANCE_BENCHMARKED
    assert A.assurance_for("sql_construction", "javascript", "express") == A.ASSURANCE_BETA
    assert A.assurance_for("command_execution", "csharp", None) == A.ASSURANCE_BETA
    # unknown capability/lang -> conservative, never benchmarked
    assert A.assurance_for("sql_construction", "rust", None) != A.ASSURANCE_BENCHMARKED


def test_matrix_python_covers_all_documented_frameworks_and_none():
    for framework in ("fastapi", "flask", "django", None):
        assert (
            A.assurance_for("deserialization", "python", framework) == A.ASSURANCE_BENCHMARKED
        )


def test_matrix_beta_languages_cover_all_injection_capabilities():
    for capability_id in (
        "sql_construction",
        "command_execution",
        "code_execution",
        "deserialization",
        "path_access",
    ):
        for language in ("javascript", "typescript", "go", "java", "csharp"):
            assert A.assurance_for(capability_id, language, None) == A.ASSURANCE_BETA


def test_matrix_unknown_capability_is_conservative_not_benchmarked():
    assert A.assurance_for("not_a_real_capability", "python", "fastapi") != A.ASSURANCE_BENCHMARKED
    assert A.assurance_for("cloud_configuration", "python", None) == A.ASSURANCE_INVENTORY
    assert A.assurance_for("totally_unknown", "python", None) == A.ASSURANCE_UNSUPPORTED


def test_law1_lexicon_catches_natural_paraphrases():
    assert A.has_epistemic_upgrade("this component appears vulnerable", A.STATUS_UNRESOLVED)
    assert A.has_epistemic_upgrade("the server was exploited", A.STATUS_UNRESOLVED)
    assert A.has_epistemic_upgrade("attacker can compromise this", A.STATUS_UNRESOLVED)


def test_law1_lexicon_word_boundaries_avoid_false_positives():
    assert A.has_epistemic_upgrade("a willow tree grows nearby", A.STATUS_UNRESOLVED) is False
    assert A.has_epistemic_upgrade("thanks to their goodwill", A.STATUS_UNRESOLVED) is False


def test_law1_lexicon_confirmed_status_always_false():
    for text in (
        "this component appears vulnerable",
        "the server was exploited",
        "attacker can compromise this",
        "this is confirmed SQL injection",
    ):
        assert A.has_epistemic_upgrade(text, A.STATUS_CONFIRMED) is False

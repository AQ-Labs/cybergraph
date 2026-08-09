import pytest

from cybergraph.security.capability import (
    CAPABILITIES,
    FAIL,
    NOT_APPLICABLE,
    NOT_SUPPORTED,
    PASS,
    UNKNOWN,
    CheckResult,
    relevance,
    triggers_review,
)


def test_python_change_makes_python_capabilities_relevant():
    rel = relevance(("app/main.py",))
    assert rel["sql_construction"] is True
    assert rel["client_secret_boundary"] is False


def test_typescript_change_makes_the_web_capability_relevant():
    rel = relevance(("web/page.tsx",))
    assert rel["client_secret_boundary"] is True
    assert rel["sql_construction"] is False


def test_go_change_is_caught_by_general_source_support():
    """Rev.2 accepted a Go-only change because nothing claimed .go files."""
    rel = relevance(("cmd/main.go",))
    assert rel["source_analysis_support"] is True


def test_python_change_also_claims_source_support():
    assert relevance(("app.py",))["source_analysis_support"] is True


def test_readme_change_makes_nothing_relevant():
    assert not any(relevance(("README.md",)).values())


@pytest.mark.parametrize(
    "status,expected",
    [(PASS, False), (NOT_APPLICABLE, False), (FAIL, True), (UNKNOWN, True),
     (NOT_SUPPORTED, True)],
)
def test_review_triggers(status, expected):
    assert triggers_review([CheckResult("sql_construction", status)]) is expected


def test_runtime_exploitability_is_not_a_phase_one_capability():
    """It was listed then special-cased to stop it reviewing everything."""
    assert "runtime_exploitability" not in {c.id for c in CAPABILITIES}


def test_no_capability_claims_everything():
    """A wildcard capability forces a verdict on every change; none should exist."""
    for capability in CAPABILITIES:
        assert capability.covers != ("*",), capability.id
        assert capability.covers and capability.label

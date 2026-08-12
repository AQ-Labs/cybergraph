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
    assert rel["sql_construction"] is True  # the four injection capabilities now cover web too
    assert rel["deserialization"] is False  # still Python-only


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


def test_five_capabilities_cover_csharp():
    from cybergraph.security.capability import CAPABILITIES

    covers = {c.id: c.covers for c in CAPABILITIES}
    for cid in ("sql_construction", "command_execution", "path_access",
                "deserialization", "code_execution"):
        assert "*.cs" in covers[cid], cid


def test_csharp_not_in_verified_globs():
    from cybergraph.security.capability import VERIFIED_GLOBS

    assert "*.cs" not in VERIFIED_GLOBS  # C# stays NOT_SUPPORTED for source_analysis_support

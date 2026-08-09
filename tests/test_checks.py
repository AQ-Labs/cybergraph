from cybergraph.graph import Finding
from cybergraph.security.capability import (
    CAPABILITIES,
    FAIL,
    NOT_APPLICABLE,
    NOT_SUPPORTED,
    PASS,
    UNKNOWN,
)
from cybergraph.security.checks import evaluate_capabilities
from cybergraph.security.coverage import FileCoverage
from cybergraph.security.policy import Policy, PolicyProblem, ProtectedEntity, ProtectedSet

PY = ("app.py",)
ANALYZED = (FileCoverage("app.py", "analyzed"),)


def _entities(*entities):
    return ProtectedSet({e.key: e for e in entities})


def _routes():
    return _entities(ProtectedEntity("app.py::h", "/x", "app.py", 1, True))


def _status(results, capability_id):
    return next(r.status for r in results if r.capability_id == capability_id)


def _run(**overrides):
    kwargs = {
        "changed_files": PY, "findings": [], "coverage": ANALYZED,
        "protected_set": _routes(), "policy": Policy(exists=True), "risk_deltas": [],
    }
    kwargs.update(overrides)
    return evaluate_capabilities(**kwargs)


def test_clean_python_change_passes_the_python_capabilities():
    assert _status(_run(), "sql_construction") == PASS


def test_confirmed_finding_fails_its_capability():
    finding = Finding("CG-SQL-EXEC", "high", "unsafe query", "app.py", 7)
    assert _status(_run(findings=[finding]), "sql_construction") == FAIL


def test_unverified_finding_makes_its_capability_unknown():
    finding = Finding("CG-SQL-EXEC-UNVERIFIED", "medium", "could not confirm", "app.py", 7)
    assert _status(_run(findings=[finding]), "sql_construction") == UNKNOWN


def test_unparseable_file_makes_python_capabilities_unknown():
    """B4: zero findings from a file that never parsed is not evidence."""
    coverage = (FileCoverage("app.py", "failed", "the file could not be read"),)
    assert _status(_run(coverage=coverage), "sql_construction") == UNKNOWN


def test_go_change_is_not_supported():
    """B3: rev.2 accepted a Go-only change."""
    results = _run(changed_files=("main.go",), coverage=(FileCoverage("main.go", "unsupported"),))
    assert _status(results, "source_analysis_support") == NOT_SUPPORTED


def test_python_change_is_supported_source():
    assert _status(_run(), "source_analysis_support") == PASS


def test_login_rules_unknown_when_the_policy_has_problems():
    policy = Policy(problems=(PolicyProblem("mfa", "not supported"),), exists=True)
    assert _status(_run(policy=policy), "declared_login_rules") == UNKNOWN


def test_login_rules_unknown_when_routes_exist_but_no_policy_does():
    assert _status(_run(policy=Policy(exists=False)), "declared_login_rules") == UNKNOWN


def test_reachable_paths_unknown_when_the_graph_has_no_routes():
    """B2/entrypoints: a CLI has no entry surface CyberGraph can see."""
    assert _status(_run(protected_set=_entities()), "reachable_data_paths") == UNKNOWN


def test_reachable_paths_pass_when_routes_exist_and_nothing_regressed():
    assert _status(_run(), "reachable_data_paths") == PASS


def test_git_failure_makes_everything_unknown():
    results = _run(revisions_failure="could not resolve `origin/main`")
    assert all(r.status == UNKNOWN for r in results)


def test_readme_only_change_is_not_applicable_everywhere():
    results = _run(changed_files=("README.md",), coverage=())
    assert {r.status for r in results} == {NOT_APPLICABLE}


def test_every_capability_is_evaluated_or_absent():
    """The rev.2 bug: a capability with no evaluator silently returned PASS."""
    ids = {c.id for c in CAPABILITIES}
    results = _run(changed_files=("app.py", "main.go", "web/p.tsx", "main.tf"))
    assert {r.capability_id for r in results} == ids
    for result in results:
        assert result.status in {PASS, FAIL, NOT_APPLICABLE, UNKNOWN, NOT_SUPPORTED}

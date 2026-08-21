from cybergraph.graph import Finding
from cybergraph.security.capability import (
    CAPABILITIES,
    FAIL,
    NOT_APPLICABLE,
    NOT_SUPPORTED,
    PASS,
    UNKNOWN,
)
from cybergraph.security.checks import (
    backing_finding,
    capability_files,
    escalated_risk_deltas,
    evaluate_capabilities,
)
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


def test_relevant_file_missing_from_coverage_is_unknown_not_pass():
    """A sink capability must not PASS just because nothing was in `coverage`.

    Zero findings from a file that was never even recorded is not evidence --
    it is exactly as uninformative as a recorded parse failure.
    """
    assert _status(_run(coverage=()), "sql_construction") == UNKNOWN


def test_relevant_file_analyzed_with_no_findings_passes():
    """The positive case: a relevant file that was actually analyzed, clean."""
    result = next(r for r in _run() if r.capability_id == "sql_construction")
    assert result.status == PASS
    assert result.evidence_count == 1


def test_unrelated_go_failure_does_not_taint_a_python_capability():
    """LOW: coverage relevance must be scoped per capability, not global.

    A failed `.go` file must not drag an unrelated Python capability to
    UNKNOWN -- only failures within that capability's own declared scope count.
    Uses `deserialization`, which stays Python-only even after Go joined
    `sql_construction`/`command_execution`/`path_access`.
    """
    coverage = (
        FileCoverage("app.py", "analyzed"),
        FileCoverage("main.go", "failed", "the file could not be read"),
    )
    results = _run(changed_files=("app.py", "main.go"), coverage=coverage)
    assert _status(results, "deserialization") == PASS
    assert _status(results, "source_analysis_support") == NOT_SUPPORTED


def test_login_rules_unknown_when_no_entities_exist_to_check():
    """INFO: declared_login_rules must not PASS with zero entities in scope.

    Same zero-evidence shape reachable_data_paths already guards against.
    """
    assert _status(_run(protected_set=_entities()), "declared_login_rules") == UNKNOWN


# --- Task 4 helpers: exposed for `verdict.decide` to derive epistemics -----

def test_backing_finding_prefers_confirmed_over_unverified():
    confirmed = Finding("CG-SQL-EXEC", "high", "unsafe", "app.py", 1)
    unverified = Finding("CG-SQL-EXEC-UNVERIFIED", "medium", "maybe", "app.py", 2)
    assert backing_finding("sql_construction", [unverified, confirmed]) is confirmed


def test_backing_finding_falls_back_to_unverified():
    unverified = Finding("CG-SQL-EXEC-UNVERIFIED", "medium", "maybe", "app.py", 2)
    assert backing_finding("sql_construction", [unverified]) is unverified


def test_backing_finding_is_none_for_capabilities_with_no_finding_rule():
    assert backing_finding("declared_login_rules", [Finding("X", "high", "m", "a.py")]) is None


def test_backing_finding_is_none_when_nothing_matches():
    unrelated = [Finding("CG-CMD-EXEC", "high", "m", "a.py")]
    assert backing_finding("sql_construction", unrelated) is None


def test_capability_files_scopes_to_the_capabilitys_own_globs():
    assert capability_files("deserialization", ("app.py", "main.go")) == ("app.py",)


def test_escalated_risk_deltas_keeps_only_added_or_worsened():
    class _Delta:
        def __init__(self, status):
            self.status = status

    deltas = [_Delta("added"), _Delta("unchanged"), _Delta("worsened"), _Delta("fixed")]
    assert [d.status for d in escalated_risk_deltas(deltas)] == ["added", "worsened"]

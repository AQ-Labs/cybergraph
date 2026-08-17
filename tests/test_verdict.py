from cybergraph.graph import Finding
from cybergraph.security.assurance import (
    ASSURANCE_BENCHMARKED,
    ASSURANCE_BETA,
    ASSURANCE_INVENTORY,
    EVIDENCE_NONE,
    EVIDENCE_PARTIAL,
    EVIDENCE_STRONG,
    EVIDENCE_WEAK,
    REASON_CONFIRMED_REGRESSION,
    REASON_UNRESOLVED,
    REASON_UNSUPPORTED,
    STATUS_CONFIRMED,
    STATUS_UNRESOLVED,
    STATUS_UNSUPPORTED,
)
from cybergraph.security.capability import FAIL, NOT_SUPPORTED, PASS, UNKNOWN, CheckResult
from cybergraph.security.policy import PolicyChange, ProtectedEntity, ProtectedSet
from cybergraph.security.verdict import (
    STATE_ACCEPT,
    STATE_REVIEW,
    Provenance,
    Reason,
    Verdict,
    decide,
    format_verdict,
    verdict_to_dict,
)

PROV = Provenance("0.1.0", "abc123", "def456", "worktree", "hash", ("sql_construction",))
PASSING = [CheckResult("sql_construction", PASS, evidence_count=4)]


def _sample_review_verdict() -> Verdict:
    reason = Reason(
        headline="SQL query built from unsanitized input.",
        file_path="app.py",
        line=3,
        rule_id="sql_construction",
        kind="check_failed",
        status=STATUS_CONFIRMED,
        evidence=EVIDENCE_STRONG,
        assurance=ASSURANCE_BENCHMARKED,
        impact="An attacker could read or modify data.",
        reason_class=REASON_CONFIRMED_REGRESSION,
    )
    return Verdict(
        STATE_REVIEW,
        (reason,),
        (CheckResult("sql_construction", FAIL, "unsafe query"),),
        (),
        PROV,
        primary_reason=REASON_CONFIRMED_REGRESSION,
    )


def test_all_passing_accepts():
    verdict = decide(PASSING, [], PROV)
    assert verdict.state == STATE_ACCEPT
    assert verdict.reasons == ()


def test_fail_reviews():
    verdict = decide([CheckResult("sql_construction", FAIL, "unsafe query")], [], PROV)
    assert verdict.state == STATE_REVIEW
    assert len(verdict.reasons) == 1


def test_one_failing_check_produces_exactly_one_reason():
    """P4: rev.2 emitted a check reason and a finding reason for one vulnerability."""
    checks = [CheckResult("sql_construction", FAIL, "unsafe query", evidence_count=1)]
    assert len(decide(checks, [], PROV).reasons) == 1


def test_unknown_reviews():
    verdict = decide([CheckResult("sql_construction", UNKNOWN, "could not read")], [], PROV)
    assert verdict.state == STATE_REVIEW


def test_not_supported_reviews_and_is_listed():
    verdict = decide([CheckResult("client_secret_boundary", NOT_SUPPORTED)], [], PROV)
    assert verdict.state == STATE_REVIEW
    assert verdict.not_evaluated


def test_policy_weakening_reviews():
    change = PolicyChange("coverage_shrunk", "/admin/x", "no rule covers it any more")
    verdict = decide(PASSING, [change], PROV)
    assert verdict.state == STATE_REVIEW
    assert "/admin/x" in verdict.reasons[0].headline


def test_protection_lost_names_the_rename():
    change = PolicyChange("protection_lost", "/admin/export",
                          "it moved from `/admin/export` to `/export`")
    text = format_verdict(decide(PASSING, [change], PROV))
    assert "/export" in text


def test_policy_problem_is_not_worded_as_a_removal():
    problem = PolicyChange("policy_problem", "mfa", "`require_mfa` is not yet supported")
    removal = PolicyChange("rule_removed", "mfa", "a declared promise was removed")
    assert (decide(PASSING, [problem], PROV).reasons[0].headline
            != decide(PASSING, [removal], PROV).reasons[0].headline)


def test_promise_broken_and_unmet_read_differently():
    broken = decide(PASSING, [PolicyChange("promise_broken", "/a", "x")], PROV)
    unmet = decide(PASSING, [PolicyChange("promise_unmet", "/a", "x")], PROV)
    assert broken.reasons[0].headline != unmet.reasons[0].headline


def test_promise_added_is_not_a_reason():
    assert decide(PASSING, [PolicyChange("promise_added", "new", "")], PROV).reasons == ()


def test_output_never_claims_universal_safety():
    text = format_verdict(decide(PASSING, [], PROV))
    assert "safe to ship" not in text.lower()
    assert "checks CyberGraph ran" in text


def test_output_contains_no_jargon():
    change = PolicyChange("promise_broken", "/admin/x", "Admin is not public.")
    text = format_verdict(decide(PASSING, [change], PROV)).lower()
    for word in ("sink", "taint", "cwe", "sarif", "entrypoint", "attack path"):
        assert word not in text, word


def test_dict_form_carries_provenance():
    payload = verdict_to_dict(decide(PASSING, [], PROV))
    assert payload["provenance"]["policy_hash"] == "hash"
    assert payload["provenance"]["mode"] == "worktree"
    assert payload["state"] == "accept"


def test_load_changed_findings_is_scoped(tmp_path):
    from cybergraph.build import build_graph
    from cybergraph.security.verdict import load_changed_findings

    (tmp_path / "app.py").write_text(
        '@app.route("/x")\ndef h(request):\n'
        '    return db.execute("select " + request.args["q"])\n',
        encoding="utf-8",
    )
    (tmp_path / "other.py").write_text("def noop():\n    return 1\n", encoding="utf-8")
    build_graph(tmp_path)
    assert load_changed_findings(tmp_path, ("app.py",))
    assert load_changed_findings(tmp_path, ("other.py",)) == []
    assert load_changed_findings(tmp_path, ()) == []


def test_load_changed_findings_carries_the_stored_evidence(tmp_path):
    """Regression: the SELECT once dropped the `evidence` column, so every
    finding load_changed_findings reconstructed came back with evidence="" no
    matter what the analyzer resolved and stored in the findings table."""
    from cybergraph.build import build_graph
    from cybergraph.security.verdict import load_changed_findings

    (tmp_path / "app.py").write_text(
        '@app.route("/x")\ndef h(request):\n'
        '    return db.execute("select " + request.args["q"])\n',
        encoding="utf-8",
    )
    build_graph(tmp_path)
    findings = load_changed_findings(tmp_path, ("app.py",))
    assert findings
    assert any(f.evidence for f in findings), findings


def test_confirmed_python_sql_regression_is_strong_end_to_end(tmp_path):
    """The real CLI/MCP path: check_change -> load_changed_findings -> decide.

    The hand-built-Finding tests above construct `Finding(..., evidence=...)`
    directly and never call load_changed_findings, which is exactly how a
    dropped `evidence` column in its SQL slipped past every other test. This
    one goes through the real query.
    """
    import subprocess

    from cybergraph.security.check import check_change

    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    (tmp_path / "README.md").write_text("hi\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base"],
        cwd=tmp_path, check=True,
    )
    (tmp_path / "app.py").write_text(
        '@app.route("/x")\ndef h(request):\n'
        '    return db.execute("select " + request.args["q"])\n',
        encoding="utf-8",
    )

    verdict = check_change(tmp_path)

    confirmed = [r for r in verdict.reasons if r.rule_id == "sql_construction"]
    assert confirmed, verdict.reasons
    assert confirmed[0].status == STATUS_CONFIRMED
    assert confirmed[0].evidence == EVIDENCE_STRONG


def test_verdict_to_dict_is_schema_v2_with_epistemic_blocks():
    v = _sample_review_verdict()  # helper builds a Verdict with one confirmed_regression reason
    d = verdict_to_dict(v)
    assert d["schema_version"] == 2
    assert d["decision"] == d["state"] == "review"
    r = d["reasons"][0]
    for k in ("headline", "status", "evidence", "assurance", "impact", "reason_class"):
        assert k in r
    assert d["primary_reason"] in {rr["reason_class"] for rr in d["reasons"]}


def test_gate_defaults_empty_until_policy_sets_it():
    assert verdict_to_dict(_sample_review_verdict())["gate"] in ("", None)


# --- Task 4: epistemics populated from existing signals --------------------

_SQL_CHECK = [CheckResult("sql_construction", FAIL, "unsafe query", evidence_count=1)]


def test_confirmed_python_sql_regression_is_strong_benchmark_backed():
    """A resolved-path Python finding is CyberGraph's best-established case."""
    finding = Finding("CG-SQL-EXEC", "critical", "unsafe query", "app.py", 7,
                       evidence="app.py:7 -> cursor.execute")
    verdict = decide(_SQL_CHECK, [], PROV, findings=[finding])
    reason = verdict.reasons[0]
    assert reason.status == STATUS_CONFIRMED
    assert reason.evidence == EVIDENCE_STRONG
    assert reason.assurance == ASSURANCE_BENCHMARKED
    assert reason.reason_class == REASON_CONFIRMED_REGRESSION
    assert reason.impact == "critical"


def test_confirmed_js_sql_regression_is_beta():
    """Same rule, same evidence shape, a language CyberGraph has not benchmarked."""
    finding = Finding("CG-SQL-EXEC", "high", "unsafe query", "app.js", 7,
                       evidence="app.js:7 -> db.query")
    verdict = decide(_SQL_CHECK, [], PROV, findings=[finding])
    reason = verdict.reasons[0]
    assert reason.evidence == EVIDENCE_STRONG
    assert reason.assurance == ASSURANCE_BETA


def test_unverified_finding_is_partial_evidence_and_unresolved():
    finding = Finding("CG-SQL-EXEC-UNVERIFIED", "medium", "could not confirm", "app.py", 7)
    checks = [CheckResult("sql_construction", UNKNOWN, "could not confirm", evidence_count=1)]
    verdict = decide(checks, [], PROV, findings=[finding])
    reason = verdict.reasons[0]
    assert reason.status == STATUS_UNRESOLVED
    assert reason.evidence == EVIDENCE_PARTIAL
    assert reason.reason_class == REASON_UNRESOLVED


def test_confirmed_finding_with_no_resolved_path_is_weak_evidence():
    finding = Finding("CG-SQL-EXEC", "high", "unsafe query", "app.py", 7, evidence="")
    verdict = decide(_SQL_CHECK, [], PROV, findings=[finding])
    assert verdict.reasons[0].evidence == EVIDENCE_WEAK


def test_check_with_no_backing_finding_is_evidence_none():
    checks = [CheckResult("declared_login_rules", FAIL, "`/admin/x` has no login check", 1)]
    verdict = decide(checks, [], PROV)
    reason = verdict.reasons[0]
    assert reason.evidence == EVIDENCE_NONE
    assert reason.impact == "critical"


def test_not_supported_change_is_reason_class_unsupported():
    checks = [CheckResult("source_analysis_support", NOT_SUPPORTED, "no analyzer yet for x.rb", 1)]
    verdict = decide(checks, [], PROV)
    reason = verdict.reasons[0]
    assert reason.status == STATUS_UNSUPPORTED
    assert reason.reason_class == REASON_UNSUPPORTED
    assert reason.assurance == ASSURANCE_INVENTORY


def test_primary_reason_prefers_protected_unsupported_over_low_impact_confirmed():
    """Spec §4: a critical unsupported change on a protected boundary can outrank
    a low-impact confirmed regression -- primary_reason is computed, not fixed-order."""
    protected = ProtectedSet(
        {"app.rb::h": ProtectedEntity("app.rb::h", "/x", "app.rb", 1, True)}
    )
    checks = [
        CheckResult("sql_construction", FAIL, "unsafe query", evidence_count=1),
        CheckResult("source_analysis_support", NOT_SUPPORTED, "no analyzer yet for app.rb", 1),
    ]
    low_finding = Finding("CG-SQL-EXEC", "low", "minor", "other.py", 3,
                          evidence="other.py:3 -> cursor.execute")
    verdict = decide(
        checks, [], PROV,
        findings=[low_finding],
        protected_set=protected,
        changed_files=("other.py", "app.rb"),
    )
    assert verdict.primary_reason == REASON_UNSUPPORTED

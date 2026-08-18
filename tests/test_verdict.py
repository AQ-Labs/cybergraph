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
    has_epistemic_upgrade,
)
from cybergraph.security.capability import (
    FAIL,
    NOT_SUPPORTED,
    PASS,
    UNKNOWN,
    CheckResult,
    label_for,
)
from cybergraph.security.policy import PolicyChange, ProtectedEntity, ProtectedSet
from cybergraph.security.review import RiskDelta
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


# --- Task 5: collapsed default projection + claim-language enforcement ------


def _sample_beta_sql_review() -> Verdict:
    """A confirmed finding in a language CyberGraph has not benchmarked: the
    epistemics warrant "possible", never "confirmed" (Laws 1 & 3)."""
    reason = Reason(
        headline=f"{label_for('sql_construction')}: unsafe query built from request input.",
        file_path="app.js",
        line=7,
        rule_id="sql_construction",
        kind="check_failed",
        status=STATUS_CONFIRMED,
        evidence=EVIDENCE_STRONG,
        assurance=ASSURANCE_BETA,
        impact="high",
        reason_class=REASON_CONFIRMED_REGRESSION,
    )
    return Verdict(
        STATE_REVIEW,
        (reason,),
        (CheckResult("sql_construction", FAIL, "unsafe query", evidence_count=1),),
        (),
        PROV,
        primary_reason=REASON_CONFIRMED_REGRESSION,
    )


def _sample_all_unresolved_review() -> Verdict:
    """No confirmed regression -- a thin result naming every unresolved/
    unsupported gap by its own reason string, never a bare status token."""
    reasons = (
        Reason(
            headline="CyberGraph could not check unsafe database queries.",
            rule_id="sql_construction",
            kind="check_unknown",
            status=STATUS_UNRESOLVED,
            evidence=EVIDENCE_PARTIAL,
            assurance=ASSURANCE_BETA,
            impact="critical",
            reason_class=REASON_UNRESOLVED,
        ),
        Reason(
            headline="This change touches things CyberGraph cannot verify yet "
                     "(languages cybergraph can read).",
            rule_id="source_analysis_support",
            kind="check_unsupported",
            status=STATUS_UNSUPPORTED,
            evidence=EVIDENCE_NONE,
            assurance=ASSURANCE_INVENTORY,
            impact="critical",
            reason_class=REASON_UNSUPPORTED,
        ),
    )
    checks = (
        CheckResult("sql_construction", UNKNOWN,
                    "dynamic dispatch prevented call resolution", 1),
        CheckResult("source_analysis_support", NOT_SUPPORTED,
                    "framework authorization pattern not recognized", 1),
    )
    return Verdict(
        STATE_REVIEW,
        reasons,
        checks,
        (label_for("source_analysis_support"),),
        PROV,
        primary_reason=REASON_UNSUPPORTED,
    )


def _line_for(out: str, reason: Reason) -> str:
    """The rendered line that speaks for a given reason -- matched by its
    capability's human label, which appears in every reason line format_verdict
    renders (the claim line and each thin-result bullet alike)."""
    needle = label_for(reason.rule_id)
    for line in out.splitlines():
        if needle in line:
            return line
    return ""


def test_default_projection_is_collapsed_and_language_bounded():
    out = format_verdict(_sample_beta_sql_review())      # beta capability
    assert "possible" in out.lower() and "confirmed" not in out.lower()  # Law 1 + Law 3
    assert out.count("\n") <= 8               # collapsed: headline + reason + top gap + [Why?]
    assert "Why?" in out or "why" in out.lower()


def test_thin_result_names_the_gaps_not_bare_unknown():
    out = format_verdict(_sample_all_unresolved_review())
    assert "could not" in out.lower()
    assert "UNKNOWN" not in out            # never a bare UNKNOWN in the default view


def test_no_forbidden_upgrade_in_any_rendered_reason():
    for v in (_sample_beta_sql_review(), _sample_all_unresolved_review()):
        out = format_verdict(v)
        for r in v.reasons:
            assert not has_epistemic_upgrade(_line_for(out, r), r.status)


def test_verbose_mode_prints_the_full_epistemic_block():
    out = format_verdict(_sample_beta_sql_review(), verbose=True)
    for field in ("Status:", "Evidence:", "Assurance:", "Impact:"):
        assert field in out


def test_verbose_names_not_established_coverage_gaps():
    out = format_verdict(_sample_all_unresolved_review(), verbose=True)
    assert label_for("source_analysis_support") in out


# --- Task 5 fix round 1: headline must honor primary_reason across the FULL
# reason set, not "any confirmed reason wins" ---------------------------------


def test_headline_honors_primary_reason_even_when_a_confirmed_reason_exists():
    """Regression for the priority-inversion bug: decide() ranked a CRITICAL
    unsupported change on a protected boundary above a low-impact confirmed
    SQL finding (see test_primary_reason_prefers_protected_unsupported_over_
    low_impact_confirmed). The rendered HEADLINE must say so too -- a reader
    who reads only the collapsed headline must not be misled into thinking the
    low-impact confirmed finding is the top risk."""
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
    assert verdict.primary_reason == REASON_UNSUPPORTED  # decide()'s ranking (unchanged)

    out = format_verdict(verdict)
    lines = out.splitlines()
    headline = lines[2]  # after the count line and its trailing blank line

    assert label_for("source_analysis_support") in headline
    assert "not evaluated" in headline.lower()
    assert label_for("sql_construction") not in headline
    assert "confirmed" not in headline.lower()

    # Nothing is dropped (Law 5): the low-impact confirmed reason still
    # surfaces in the body, just not as the headline.
    assert label_for("sql_construction") in out


# --- Task 5 fix round 2: ranking is TRUST-FIRST, not impact-first, once
# protected_boundary ties -------------------------------------------------


def test_headline_prefers_confirmed_benchmarked_over_inventory_possible_of_higher_impact():
    """Checkpoint regression: three reasons fire on the same tainted execute() --
    a benchmark-backed CONFIRMED sql_construction (impact=high), an
    inventory-grade CONFIRMED reachable_data_paths (impact=critical), and an
    inventory-grade UNRESOLVED declared_login_rules (impact=critical). None of
    these sit on a protected boundary, so trust must break the tie: the
    substantiated confirmed SQL finding leads, never collapsed behind a
    merely-inventory "possible"/"could not verify" reason of higher nominal
    impact."""
    sql_finding = Finding("CG-SQL-EXEC", "high", "unsafe query", "app.py", 7,
                          evidence="app.py:7 -> cursor.execute")
    risk_deltas = [
        RiskDelta("added", "sig", "entry", "sink", 90, "critical", True, ("app.py",))
    ]
    checks = [
        CheckResult("sql_construction", FAIL, "unsafe query", evidence_count=1),
        CheckResult("reachable_data_paths", FAIL, "new route reaches sensitive code", 1),
        CheckResult("declared_login_rules", UNKNOWN, "could not resolve the guard", 1),
    ]
    verdict = decide(checks, [], PROV, findings=[sql_finding], risk_deltas=risk_deltas)
    assert verdict.primary_reason == REASON_CONFIRMED_REGRESSION

    out = format_verdict(verdict)
    headline = out.splitlines()[2]  # after the count line and its trailing blank line

    assert "Confirmed" in headline
    assert label_for("sql_construction") in headline
    assert label_for("reachable_data_paths") not in headline

    # Present in the collapsed default view, not only behind [Why?].
    assert label_for("sql_construction") in out
    assert "[Why?]" in out


def test_protected_boundary_still_outranks_trust():
    """Trust must NOT override protected_boundary: a critical unsupported
    change on a protected boundary still headlines over a benchmark-backed
    confirmed regression elsewhere (no regression on the existing ranking
    guarantee -- see test_primary_reason_prefers_protected_unsupported_over_
    low_impact_confirmed for the decide()-level assertion)."""
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

    out = format_verdict(verdict)
    headline = out.splitlines()[2]
    assert label_for("source_analysis_support") in headline
    assert label_for("sql_construction") not in headline


def test_trust_outranks_impact_when_neither_reason_is_protected():
    """Edge case named by the checkpoint review: a benchmark-backed CONFIRMED
    LOW-impact reason vs. an inventory-grade CONFIRMED CRITICAL-impact reason,
    neither on a protected boundary -- trust wins before impact."""
    low_finding = Finding("CG-SQL-EXEC", "low", "minor", "app.py", 3,
                          evidence="app.py:3 -> cursor.execute")
    risk_deltas = [
        RiskDelta("added", "sig", "entry", "sink", 90, "critical", True, ("app.py",))
    ]
    checks = [
        CheckResult("sql_construction", FAIL, "unsafe query", evidence_count=1),
        CheckResult("reachable_data_paths", FAIL, "new route reaches sensitive code", 1),
    ]
    verdict = decide(checks, [], PROV, findings=[low_finding], risk_deltas=risk_deltas)
    assert verdict.primary_reason == REASON_CONFIRMED_REGRESSION

    out = format_verdict(verdict)
    headline = out.splitlines()[2]
    assert "Confirmed" in headline
    assert label_for("sql_construction") in headline
    assert label_for("reachable_data_paths") not in headline

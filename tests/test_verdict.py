from cybergraph.security.capability import FAIL, NOT_SUPPORTED, PASS, UNKNOWN, CheckResult
from cybergraph.security.policy import PolicyChange
from cybergraph.security.verdict import (
    STATE_ACCEPT,
    STATE_REVIEW,
    Provenance,
    decide,
    format_verdict,
    verdict_to_dict,
)

PROV = Provenance("0.1.0", "abc123", "def456", "worktree", "hash", ("sql_construction",))
PASSING = [CheckResult("sql_construction", PASS, evidence_count=4)]


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

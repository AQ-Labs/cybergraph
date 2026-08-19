"""Task 7: the policy/enforcement gate.

Law 7: policy sets the ``gate`` (block/warn/info); it NEVER mutates the
decision. No config value may launder a REVIEW into an ACCEPT. These tests
are the point of the task -- they must fail if any code path lets a config
value flip ``verdict.state``.
"""

from cybergraph.security.assurance import (
    REASON_CONFIRMED_REGRESSION,
    REASON_UNRESOLVED,
    REASON_UNSUPPORTED,
)
from cybergraph.security.capability import FAIL, NOT_SUPPORTED, UNKNOWN, CheckResult
from cybergraph.security.policy_gate import (
    GATE_BLOCK,
    GATE_INFO,
    GATE_WARN,
    VerificationConfig,
    gate_for,
)
from cybergraph.security.verdict import STATE_REVIEW, Provenance, Reason, Verdict

PROV = Provenance("0.1.0", "abc123", "def456", "worktree", "hash", ("sql_construction",))


def _sample_review_verdict() -> Verdict:
    reason = Reason(
        headline="SQL query built from unsanitized input.",
        file_path="app.py",
        line=3,
        rule_id="sql_construction",
        kind="check_failed",
        status="confirmed",
        evidence="strong",
        assurance="benchmarked",
        impact="critical",
        reason_class=REASON_CONFIRMED_REGRESSION,
        protected=False,
    )
    return Verdict(
        STATE_REVIEW,
        (reason,),
        (CheckResult("sql_construction", FAIL, "unsafe query"),),
        (),
        PROV,
        primary_reason=REASON_CONFIRMED_REGRESSION,
    )


def _sample_unsupported_on_protected_route() -> Verdict:
    reason = Reason(
        headline="This change touches things CyberGraph cannot verify yet (login checks).",
        file_path="admin.py",
        line=1,
        rule_id="declared_login_rules",
        kind="check_unsupported",
        status="unsupported",
        evidence="none",
        assurance="inventory",
        impact="critical",
        reason_class=REASON_UNSUPPORTED,
        protected=True,
    )
    return Verdict(
        STATE_REVIEW,
        (reason,),
        (CheckResult("declared_login_rules", NOT_SUPPORTED, "no analyzer yet"),),
        (),
        PROV,
        primary_reason=REASON_UNSUPPORTED,
    )


def _sample_unresolved_non_protected() -> Verdict:
    reason = Reason(
        headline="CyberGraph could not check unsafe database queries.",
        file_path="misc.py",
        line=9,
        rule_id="sql_construction",
        kind="check_unknown",
        status="unresolved",
        evidence="partial",
        assurance="beta",
        impact="critical",
        reason_class=REASON_UNRESOLVED,
        protected=False,
    )
    return Verdict(
        STATE_REVIEW,
        (reason,),
        (CheckResult("sql_construction", UNKNOWN, "dynamic dispatch"),),
        (),
        PROV,
        primary_reason=REASON_UNRESOLVED,
    )


def test_policy_sets_gate_never_decision():
    v = _sample_review_verdict()
    g = gate_for(v, VerificationConfig(block_confirmed_regressions=True))
    assert g == GATE_BLOCK
    assert v.state == "review"            # decision unchanged by policy

    # no config can turn review into accept:
    g2 = gate_for(v, VerificationConfig(block_confirmed_regressions=False,
                                        block_general_unknown=False))
    assert g2 in (GATE_WARN, GATE_INFO)   # advisory, but still review
    assert v.state == "review"


def test_unsupported_on_protected_boundary_blocks_when_configured():
    v = _sample_unsupported_on_protected_route()
    assert gate_for(v, VerificationConfig(block_unknown_on_protected_routes=True)) == GATE_BLOCK


def test_general_unknown_is_advisory_by_default():
    v = _sample_unresolved_non_protected()
    assert gate_for(v, VerificationConfig()) in (GATE_WARN, GATE_INFO)


def test_general_unknown_blocks_when_explicitly_configured():
    v = _sample_unresolved_non_protected()
    assert gate_for(v, VerificationConfig(block_general_unknown=True)) == GATE_BLOCK
    assert v.state == "review"


def test_unsupported_on_protected_boundary_is_advisory_when_not_configured_to_block():
    v = _sample_unsupported_on_protected_route()
    g = gate_for(v, VerificationConfig(block_unknown_on_protected_routes=False,
                                       block_confirmed_regressions=False,
                                       block_general_unknown=False))
    assert g in (GATE_WARN, GATE_INFO)
    assert v.state == "review"


def test_accept_verdict_gates_info():
    from cybergraph.security.verdict import STATE_ACCEPT

    empty = Verdict(STATE_ACCEPT, (), (), (), PROV)
    assert gate_for(empty, VerificationConfig()) == GATE_INFO


def test_gate_for_never_reads_or_writes_verdict_state():
    """gate_for is a pure function of (verdict, config) -> str; it must never
    itself decide accept/review -- that already happened in decide()."""
    v = _sample_review_verdict()
    before = v.state
    gate_for(v, VerificationConfig())
    assert v.state == before


def test_no_config_combination_ever_implies_accept():
    v = _sample_review_verdict()
    for bcr in (True, False):
        for bupr in (True, False):
            for bgu in (True, False):
                gate_for(v, VerificationConfig(bcr, bupr, bgu))
                assert v.state == STATE_REVIEW


def test_verification_config_defaults():
    config = VerificationConfig()
    assert config.block_confirmed_regressions is True
    assert config.block_unknown_on_protected_routes is True
    assert config.block_general_unknown is False


def test_load_verification_config_defaults_when_no_policy_file(tmp_path):
    from cybergraph.security.policy_gate import load_verification_config

    config = load_verification_config(tmp_path)
    assert config == VerificationConfig()


def test_load_verification_config_reads_the_verification_table(tmp_path):
    from cybergraph.security.policy import POLICY_FILE
    from cybergraph.security.policy_gate import load_verification_config

    (tmp_path / POLICY_FILE).write_text(
        "version = 1\n\n"
        "[verification]\n"
        "block_confirmed_regressions = false\n"
        "block_unknown_on_protected_routes = false\n"
        "block_general_unknown = true\n",
        encoding="utf-8",
    )
    config = load_verification_config(tmp_path)
    assert config.block_confirmed_regressions is False
    assert config.block_unknown_on_protected_routes is False
    assert config.block_general_unknown is True


def test_load_verification_config_defaults_when_table_absent(tmp_path):
    from cybergraph.security.policy import POLICY_FILE
    from cybergraph.security.policy_gate import load_verification_config

    (tmp_path / POLICY_FILE).write_text("version = 1\n", encoding="utf-8")
    assert load_verification_config(tmp_path) == VerificationConfig()


def test_gate_constants_are_the_single_canonical_source():
    """FIX 1: ``policy_gate``'s gate constants must be the SAME objects as
    ``verdict``'s canonical ones, not a separately-maintained duplicate that
    could drift and cause ``format_verdict`` to misjudge a blocking gate as
    non-blocking (false reassurance on the exact axis this branch protects)."""
    from cybergraph.security import verdict as verdict_module

    assert GATE_BLOCK is verdict_module.GATE_BLOCK == "block"
    assert GATE_WARN is verdict_module.GATE_WARN == "warn"
    assert GATE_INFO is verdict_module.GATE_INFO == "info"


def test_load_verification_config_ignores_unknown_keys(tmp_path):
    from cybergraph.security.policy import POLICY_FILE
    from cybergraph.security.policy_gate import load_verification_config

    (tmp_path / POLICY_FILE).write_text(
        "version = 1\n\n[verification]\nsome_future_flag = true\n",
        encoding="utf-8",
    )
    assert load_verification_config(tmp_path) == VerificationConfig()

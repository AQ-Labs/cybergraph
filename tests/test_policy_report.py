from cybergraph.security.policy import (
    Policy,
    PolicyProblem,
    PolicyRule,
    PolicyViolation,
    ProtectedSet,
)
from cybergraph.security.policy_report import format_policy_report


def _policy(rules=(), problems=(), exists=True):
    return Policy(version=1, rules=tuple(rules), problems=tuple(problems),
                  source_hash="0" * 64, exists=exists)


def test_absent_policy_says_so_and_names_no_verdict():
    text = format_policy_report(_policy(exists=False), ProtectedSet({}, frozenset(), ()))
    assert "No policy" in text
    assert "clean" not in text.lower()
    assert "accept" not in text.lower()


def test_rules_and_problems_are_both_shown():
    policy = _policy(
        rules=[PolicyRule("admin-login", "require_auth", ("/admin/*",), "because")],
        problems=[PolicyProblem("mfa", "kind 'require_mfa' is not supported")],
    )
    text = format_policy_report(policy, ProtectedSet({}, frozenset(), ()))
    assert "admin-login" in text and "require_auth" in text and "/admin/*" in text
    assert "require_mfa" in text


def test_unprotected_entities_are_listed():
    policy = _policy(rules=[PolicyRule("a", "require_auth", ("/admin/*",), "b")])
    violation = PolicyViolation(
        "a", "/admin/export", "app.py::export", "app.py", 4, "no login check"
    )
    pset = ProtectedSet({}, frozenset({"app.py::export"}), (violation,))
    text = format_policy_report(policy, pset)
    assert "1 unprotected" in text
    assert "app.py::export" in text

from cybergraph.config import CyberGraphConfig, Suppression
from cybergraph.security.policy import (
    Policy,
    PolicyProblem,
    PolicyRule,
    PolicyViolation,
    ProtectedEntity,
    ProtectedSet,
    diff_configs,
    diff_policies,
)

RULE = PolicyRule("admin", "require_auth", ("/admin/*",), "Admin is not public.")


def _entity(key, route, guarded=True):
    return ProtectedEntity(key, route, "app.py", 1, guarded)


def _set(entities, constrained=(), unprotected=()):
    return ProtectedSet(
        {e.key: e for e in entities}, frozenset(constrained), tuple(unprotected)
    )


def _kinds(*args):
    return {change.kind for change in diff_policies(*args)}


def test_no_change_is_clean():
    policy = Policy(rules=(RULE,), exists=True)
    state = _set([_entity("app.py::x", "/admin/x")], ["app.py::x"])
    assert diff_policies(policy, state, policy, state) == ()


def test_policy_deleted_is_flagged():
    base = Policy(rules=(RULE,), exists=True)
    state = _set([_entity("app.py::x", "/admin/x")], ["app.py::x"])
    kinds = _kinds(base, state, Policy(exists=False), _set([_entity("app.py::x", "/admin/x")]))
    assert "policy_deleted" in kinds


def test_rule_removed_is_flagged():
    base = Policy(rules=(RULE,), exists=True)
    entity = _entity("app.py::x", "/admin/x")
    kinds = _kinds(
        base, _set([entity], ["app.py::x"]), Policy(rules=(), exists=True), _set([entity])
    )
    assert "rule_removed" in kinds


def test_narrowing_a_pattern_shrinks_coverage():
    """`/admin/*` -> `/admin/legacy/*` reads as stricter and protects less."""
    base = Policy(rules=(RULE,), exists=True)
    narrowed = PolicyRule("admin", "require_auth", ("/admin/legacy/*",), "")
    entities = [_entity("app.py::x", "/admin/x"), _entity("app.py::y", "/admin/legacy/y")]
    kinds = _kinds(
        base, _set(entities, ["app.py::x", "app.py::y"]),
        Policy(rules=(narrowed,), exists=True), _set(entities, ["app.py::y"]),
    )
    assert "coverage_shrunk" in kinds


def test_deleting_a_route_is_not_a_weakening():
    policy = Policy(rules=(RULE,), exists=True)
    before = _set(
        [_entity("app.py::x", "/admin/x"), _entity("app.py::gone", "/admin/gone")],
        ["app.py::x", "app.py::gone"],
    )
    after = _set([_entity("app.py::x", "/admin/x")], ["app.py::x"])
    assert "coverage_shrunk" not in _kinds(policy, before, policy, after)


def test_renaming_a_route_out_of_scope_is_caught():
    """The C1 escape: /admin/export -> /export with the guard dropped."""
    policy = Policy(rules=(RULE,), exists=True)
    before = _set([_entity("app.py::export", "/admin/export", True)], ["app.py::export"])
    after = _set([_entity("app.py::export", "/export", False)])
    assert "protection_lost" in _kinds(policy, before, policy, after)


def test_dropping_a_guard_without_renaming_is_caught():
    policy = Policy(rules=(RULE,), exists=True)
    before = _set([_entity("app.py::x", "/admin/x", True)], ["app.py::x"])
    violation = PolicyViolation("admin", "/admin/x", "app.py::x", "app.py", 1, "")
    after = _set([_entity("app.py::x", "/admin/x", False)], ["app.py::x"], [violation])
    assert "promise_broken" in _kinds(policy, before, policy, after)


def test_pre_existing_debt_does_not_review_an_unrelated_change():
    policy = Policy(rules=(RULE,), exists=True)
    violation = PolicyViolation("admin", "/admin/x", "app.py::x", "app.py", 1, "")
    state = _set([_entity("app.py::x", "/admin/x", False)], ["app.py::x"], [violation])
    assert _kinds(policy, state, policy, state) == set()


def test_added_rule_that_is_already_violated_is_unmet_not_broken():
    new_rule = PolicyRule("new", "require_auth", ("/pay/*",), "")
    entity = _entity("app.py::pay", "/pay/x", False)
    violation = PolicyViolation("new", "/pay/x", "app.py::pay", "app.py", 1, "")
    kinds = _kinds(
        Policy(rules=(), exists=True), _set([entity]),
        Policy(rules=(new_rule,), exists=True), _set([entity], ["app.py::pay"], [violation]),
    )
    assert "promise_unmet" in kinds
    assert "promise_broken" not in kinds


def test_version_downgrade_is_flagged():
    entity = _entity("app.py::x", "/admin/x")
    state = _set([entity], ["app.py::x"])
    kinds = _kinds(
        Policy(version=2, rules=(RULE,), exists=True), state,
        Policy(version=1, rules=(RULE,), exists=True), state,
    )
    assert "version_downgraded" in kinds


def test_rule_that_became_unsupported_is_not_also_removed():
    """A same-id kind change to an unsupported kind is a problem, not a removal."""
    base = Policy(rules=(RULE,), exists=True)
    current = Policy(
        rules=(),
        problems=(PolicyProblem("admin", "`require_role` is not yet supported"),),
        exists=True,
    )
    entity = _entity("app.py::x", "/admin/x")
    changes = diff_policies(
        base, _set([entity], ["app.py::x"]), current, _set([entity])
    )
    kinds_for_admin = {change.kind for change in changes if change.subject == "admin"}
    assert kinds_for_admin == {"policy_problem"}


def test_genuinely_removed_rule_is_still_flagged():
    """An id absent from both current rules and current problems is a real removal."""
    base = Policy(rules=(RULE,), exists=True)
    current = Policy(rules=(), exists=True)
    entity = _entity("app.py::x", "/admin/x")
    kinds = _kinds(base, _set([entity], ["app.py::x"]), current, _set([entity]))
    assert "rule_removed" in kinds


def test_policy_problems_get_their_own_kind():
    """An unsupported rule is not a removed rule."""
    current = Policy(
        rules=(), problems=(PolicyProblem("mfa", "`require_mfa` is not yet supported"),),
        exists=True,
    )
    kinds = _kinds(Policy(exists=True), _set([]), current, _set([]))
    assert kinds == {"policy_problem"}


def test_config_deltas():
    assert diff_configs(CyberGraphConfig(), CyberGraphConfig()) == ()
    assert {c.kind for c in diff_configs(
        CyberGraphConfig(), CyberGraphConfig(suppressed_rules=("CG-SQL-EXEC",))
    )} == {"suppression_added"}
    assert {c.kind for c in diff_configs(
        CyberGraphConfig(), CyberGraphConfig(ignored_paths=("src/*",))
    )} == {"ignored_path_added"}
    assert {c.kind for c in diff_configs(
        CyberGraphConfig(auth_markers=("verify_jwt",)), CyberGraphConfig()
    )} == {"auth_marker_removed"}
    assert {c.kind for c in diff_configs(
        CyberGraphConfig(validation_markers=("clean",)), CyberGraphConfig()
    )} == {"validation_marker_removed"}
    assert {c.kind for c in diff_configs(
        CyberGraphConfig(custom_sinks=("send_money",)), CyberGraphConfig()
    )} == {"custom_sink_removed"}
    assert diff_configs(CyberGraphConfig(), CyberGraphConfig(auth_markers=("x",))) == ()


def test_declared_accountable_suppression_is_flagged():
    """A newly-declared `[[suppressions.rule]]` is a weakening at declaration time.

    Expiry is deliberately irrelevant here: even a suppression that expires
    tomorrow is flagged, because it was declared today.
    """
    base = CyberGraphConfig()
    current = CyberGraphConfig(
        suppressions=(Suppression("rule", "CG-SQL-EXEC", "fixture only", None, ""),)
    )
    changes = diff_configs(base, current)
    assert {c.kind for c in changes} == {"suppression_added"}
    assert any(c.subject == "CG-SQL-EXEC" for c in changes)


def test_declared_accountable_path_suppression_is_flagged():
    base = CyberGraphConfig()
    current = CyberGraphConfig(
        suppressions=(Suppression("path", "legacy/**", "fixture only", None, ""),)
    )
    changes = diff_configs(base, current)
    assert {c.kind for c in changes} == {"suppression_added"}
    assert any(c.subject == "legacy/**" for c in changes)


def test_accountable_suppression_present_on_both_sides_is_not_flagged():
    entry = Suppression("rule", "CG-SQL-EXEC", "fixture only", None, "")
    base = CyberGraphConfig(suppressions=(entry,))
    current = CyberGraphConfig(suppressions=(entry,))
    assert diff_configs(base, current) == ()


def test_expired_accountable_suppression_is_still_flagged_when_newly_declared():
    """Declaration, not activity, drives this: an expired entry still counts."""
    from datetime import date

    base = CyberGraphConfig()
    current = CyberGraphConfig(
        suppressions=(Suppression("rule", "CG-SQL-EXEC", "x", date(2000, 1, 1), ""),)
    )
    assert {c.kind for c in diff_configs(base, current)} == {"suppression_added"}

from pathlib import Path

from cybergraph.security.policy import KIND_REQUIRE_AUTH, POLICY_FILE, load_policy

GOOD = """
version = 1

[rule.admin-requires-login]
kind = "require_auth"
patterns = ["/admin/*", "/internal/*"]
because = "Admin pages show data that is not meant to be public."
"""


def test_missing_file_yields_empty_policy(tmp_path: Path):
    policy = load_policy(tmp_path)
    assert policy.is_empty()
    assert policy.problems == ()
    assert policy.exists is False


def test_loads_rules_and_records_a_hash(tmp_path: Path):
    (tmp_path / POLICY_FILE).write_text(GOOD, encoding="utf-8")
    policy = load_policy(tmp_path)
    assert policy.exists is True
    assert len(policy.rules) == 1
    rule = policy.rules[0]
    assert rule.id == "admin-requires-login"
    assert rule.kind == KIND_REQUIRE_AUTH
    assert rule.patterns == ("/admin/*", "/internal/*")
    assert len(policy.source_hash) == 64


def test_unknown_kind_becomes_a_visible_problem(tmp_path: Path):
    (tmp_path / POLICY_FILE).write_text(
        'version = 1\n\n[rule.mfa]\nkind = "require_mfa"\npatterns = ["/pay/*"]\n',
        encoding="utf-8",
    )
    policy = load_policy(tmp_path)
    assert policy.rules == ()
    assert len(policy.problems) == 1
    assert "require_mfa" in policy.problems[0].message


def test_authz_is_rejected_rather_than_faked(tmp_path: Path):
    (tmp_path / POLICY_FILE).write_text(
        'version = 1\n\n[rule.a]\nkind = "require_authz"\npatterns = ["/admin/*"]\n',
        encoding="utf-8",
    )
    policy = load_policy(tmp_path)
    assert policy.rules == ()
    assert policy.problems, "authorization must not be silently treated as authentication"


def test_secret_server_only_is_marked_unsupported_not_ignored(tmp_path: Path):
    (tmp_path / POLICY_FILE).write_text(
        'version = 1\n\n[rule.s]\nkind = "secret_server_only"\npatterns = ["STRIPE_KEY"]\n',
        encoding="utf-8",
    )
    policy = load_policy(tmp_path)
    assert policy.rules == ()
    assert any("not yet" in problem.message.lower() for problem in policy.problems)


def test_missing_patterns_is_a_problem(tmp_path: Path):
    (tmp_path / POLICY_FILE).write_text(
        'version = 1\n\n[rule.a]\nkind = "require_auth"\n', encoding="utf-8"
    )
    assert load_policy(tmp_path).problems


def test_future_version_is_a_problem(tmp_path: Path):
    (tmp_path / POLICY_FILE).write_text("version = 99\n", encoding="utf-8")
    assert load_policy(tmp_path).problems


def test_flat_parser_shape_is_normalised():
    from cybergraph.security.policy import _rule_sections

    nested = {"rule": {"a": {"kind": "require_auth", "patterns": ["/x"]}}}
    flat = {"rule.a": {"kind": "require_auth", "patterns": ["/x"]}}
    assert _rule_sections(nested) == _rule_sections(flat)

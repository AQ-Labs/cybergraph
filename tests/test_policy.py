from pathlib import Path

from cybergraph.build import build_graph
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


UNGUARDED = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/admin/export")
def admin_export():
    return {"ok": True}
'''

GUARDED = '''
from fastapi import FastAPI, Depends
app = FastAPI()

def require_login():
    return True

@app.get("/admin/export")
def admin_export(user=Depends(require_login)):
    return {"ok": True}
'''

AUTH_POLICY = (
    'version = 1\n\n[rule.admin]\nkind = "require_auth"\n'
    'patterns = ["/admin/*"]\nbecause = "Admin pages are not public."\n'
)


def _setup(tmp_path: Path, source: str, policy_text: str = AUTH_POLICY):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    (tmp_path / POLICY_FILE).write_text(policy_text, encoding="utf-8")
    build_graph(tmp_path)
    return load_policy(tmp_path)


def test_unguarded_route_is_unprotected(tmp_path: Path):
    from cybergraph.security.policy import evaluate_policy

    result = evaluate_policy(tmp_path, _setup(tmp_path, UNGUARDED))
    assert len(result.unprotected) == 1
    assert result.unprotected[0].rule_id == "admin"
    assert result.unprotected[0].because == "Admin pages are not public."


def test_guarded_route_is_constrained_but_protected(tmp_path: Path):
    from cybergraph.security.policy import evaluate_policy

    result = evaluate_policy(tmp_path, _setup(tmp_path, GUARDED))
    assert result.unprotected == ()
    assert len(result.constrained) == 1


def test_entities_are_keyed_by_function_not_route(tmp_path: Path):
    """Function keys survive a route rename; route strings do not."""
    from cybergraph.security.policy import evaluate_policy

    result = evaluate_policy(tmp_path, _setup(tmp_path, GUARDED))
    key = next(iter(result.entities))
    assert "admin_export" in key
    assert result.entities[key].route == "/admin/export"
    assert result.entities[key].guarded is True


def test_empty_policy_constrains_nothing(tmp_path: Path):
    from cybergraph.security.policy import Policy, evaluate_policy

    (tmp_path / "app.py").write_text(UNGUARDED, encoding="utf-8")
    build_graph(tmp_path)
    result = evaluate_policy(tmp_path, Policy())
    assert result.constrained == frozenset()
    assert result.unprotected == ()
    assert result.entities, "entities are recorded even with no policy"


MIXED = '''
from fastapi import FastAPI, Depends
app = FastAPI()

def require_login():
    return True

@app.get("/admin/export")
def admin_export(user=Depends(require_login)):
    return {"ok": True}

@app.get("/public/ping")
def ping():
    return {"ok": True}
'''


def test_baseline_promises_only_what_is_already_guarded(tmp_path: Path):
    from cybergraph.security.policy import extract_baseline

    (tmp_path / "app.py").write_text(MIXED, encoding="utf-8")
    build_graph(tmp_path)
    draft = extract_baseline(tmp_path)
    assert "/admin/export" in draft
    assert "/public/ping" not in draft
    assert 'kind = "require_auth"' in draft


def test_baseline_is_loadable_and_problem_free(tmp_path: Path):
    from cybergraph.security.policy import extract_baseline

    (tmp_path / "app.py").write_text(MIXED, encoding="utf-8")
    build_graph(tmp_path)
    (tmp_path / POLICY_FILE).write_text(extract_baseline(tmp_path), encoding="utf-8")
    policy = load_policy(tmp_path)
    assert not policy.is_empty()
    assert policy.problems == ()


def test_baseline_with_no_guards_is_still_valid(tmp_path: Path):
    from cybergraph.security.policy import extract_baseline

    (tmp_path / "app.py").write_text(UNGUARDED, encoding="utf-8")
    build_graph(tmp_path)
    (tmp_path / POLICY_FILE).write_text(extract_baseline(tmp_path), encoding="utf-8")
    assert load_policy(tmp_path).is_empty()

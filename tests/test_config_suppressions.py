import sys
from datetime import date

import pytest

import cybergraph.config
from cybergraph.config import Suppression, load_config

# Array-of-tables ([[suppressions.rule]]) can only be parsed via `tomllib`,
# which is stdlib on Python 3.11+. On 3.10 the hand-rolled fallback parser
# has no notion of array-of-tables, so it correctly yields no accountable
# entries instead of crashing (see config._parse_suppressions docstring) —
# these three tests need a real TOML parser to exercise that behavior.
requires_tomllib = pytest.mark.skipif(
    sys.version_info < (3, 11),
    reason="array-of-tables suppressions require tomllib (Python 3.11+)",
)


def _write(tmp_path, body):
    (tmp_path / ".cybergraph.toml").write_text(body, encoding="utf-8")
    return tmp_path


@requires_tomllib
def test_accountable_rule_parsed(tmp_path):
    cfg = load_config(_write(tmp_path, '''
[[suppressions.rule]]
id = "CG-SQL-EXEC"
reason = "fixture only"
expires = "2026-12-31"
approver = "security-team"
'''))
    assert cfg.suppressions == (
        Suppression("rule", "CG-SQL-EXEC", "fixture only", date(2026, 12, 31), "security-team"),
    )
    assert cfg.suppression_problems == ()


@requires_tomllib
def test_missing_reason_is_a_problem_not_a_suppression(tmp_path):
    cfg = load_config(_write(tmp_path, '[[suppressions.rule]]\nid = "CG-SQL-EXEC"\n'))
    assert cfg.suppressions == ()
    assert any(
        p.matcher == "CG-SQL-EXEC" and "reason" in p.message.lower()
        for p in cfg.suppression_problems
    )


@requires_tomllib
def test_malformed_expires_is_a_problem(tmp_path):
    body = '[[suppressions.rule]]\nid="CG-SQL-EXEC"\nreason="x"\nexpires="not-a-date"\n'
    cfg = load_config(_write(tmp_path, body))
    assert cfg.suppressions == ()
    assert any("expires" in p.message.lower() for p in cfg.suppression_problems)


def test_legacy_flat_lists_still_parse(tmp_path):
    body = '[suppressions]\nrules = ["CG-SQL-EXEC"]\npaths = ["legacy/**"]\n'
    cfg = load_config(_write(tmp_path, body))
    assert cfg.suppressed_rules == ("CG-SQL-EXEC",)
    assert cfg.suppressed_paths == ("legacy/**",)
    assert cfg.suppressions == ()  # flat lists are not accountable objects


def test_fallback_surfaces_a_problem_not_silence(tmp_path, monkeypatch):
    """On the 3.10 fallback, an accountable entry must be surfaced, not silent.

    This is deterministic on every Python version: it forces the fallback
    path via monkeypatch instead of relying on the interpreter actually being
    3.10, so it always runs (no skipif).
    """
    monkeypatch.setattr(cybergraph.config, "tomllib", None)
    body = '[[suppressions.rule]]\nid="CG-SQL-EXEC"\nreason="x"\n'
    cfg = load_config(_write(tmp_path, body))
    assert cfg.suppressions == ()
    assert any("3.11" in p.message for p in cfg.suppression_problems)


@requires_tomllib
def test_accountable_path_parsed(tmp_path):
    cfg = load_config(_write(tmp_path, '''
[[suppressions.path]]
pattern = "legacy/**"
reason = "fixture only"
'''))
    assert cfg.suppressions == (
        Suppression("path", "legacy/**", "fixture only", None, ""),
    )
    assert cfg.suppression_problems == ()


@requires_tomllib
def test_missing_matcher_is_a_problem_not_a_suppression(tmp_path):
    cfg = load_config(_write(tmp_path, '[[suppressions.rule]]\nreason = "x"\n'))
    assert cfg.suppressions == ()
    assert any("id" in p.message.lower() for p in cfg.suppression_problems)

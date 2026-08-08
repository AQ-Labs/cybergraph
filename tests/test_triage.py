"""Tests for graph-grounded LLM false-positive triage (opt-in, guardrailed)."""

from __future__ import annotations

import json
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph import Finding
from cybergraph.security import triage as tri


# --- mock clients (no network) ----------------------------------------------
class _Client:
    def __init__(self, verdict, evidence="", reason="mock"):
        self._payload = json.dumps({"verdict": verdict, "reason": reason, "evidence": evidence})

    def complete(self, system: str, user: str) -> str:
        return self._payload


def _finding():
    return Finding(rule_id="CG-SQL-EXEC", severity="medium", message="reaches sink",
                   file_path="app.py", line_start=3, evidence="db.execute('select '+q)")


# --- pure guardrail logic ----------------------------------------------------
def test_should_suppress_only_on_grounded_false_positive():
    slice_text = "def list_users(): return db.execute('select ' + q)  # validated by allowlist"
    assert tri.should_suppress(tri.VERDICT_FALSE_POSITIVE, "validated by allowlist", slice_text)
    # false positive but evidence NOT in slice -> keep (faithfulness guard)
    assert not tri.should_suppress(tri.VERDICT_FALSE_POSITIVE, "sanitized upstream", slice_text)
    # false positive with empty/too-short evidence -> keep
    assert not tri.should_suppress(tri.VERDICT_FALSE_POSITIVE, "", slice_text)
    # non-FP verdicts never suppress
    assert not tri.should_suppress(tri.VERDICT_TRUE_POSITIVE, "validated by allowlist", slice_text)
    assert not tri.should_suppress(tri.VERDICT_UNCERTAIN, "validated by allowlist", slice_text)


def test_parse_verdict_defaults_to_uncertain_on_garbage():
    assert tri._parse_verdict("not json at all")[0] == tri.VERDICT_UNCERTAIN
    assert tri._parse_verdict('{"verdict": "bogus"}')[0] == tri.VERDICT_UNCERTAIN
    assert (
        tri._parse_verdict('{"verdict": "false_positive", "evidence": "x"}')[0]
        == tri.VERDICT_FALSE_POSITIVE
    )


def test_abstain_when_no_client_keeps_everything():
    results = tri.triage_findings(Path("."), findings=[_finding()], client=None)
    assert len(results) == 1
    assert results[0].suppressed is False
    assert results[0].verdict == tri.VERDICT_UNCERTAIN


# --- integration on a real built graph --------------------------------------
def _build(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/users')\n"
        "def list_users(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    build_graph(repo)
    return repo


def test_findings_load_and_grounded_fp_is_suppressed(tmp_path: Path):
    repo = _build(tmp_path)
    findings = tri.load_findings(repo)
    assert findings, "expected at least one finding from the vulnerable app"

    # FP verdict citing a token that really appears in the slice ('select') -> suppressed.
    sup = tri.triage_findings(
        repo, findings=findings, client=_Client(tri.VERDICT_FALSE_POSITIVE, "select")
    )
    assert any(r.suppressed for r in sup)


def test_recall_guard_keeps_findings_on_ungrounded_or_uncertain_verdicts(tmp_path: Path):
    repo = _build(tmp_path)
    findings = tri.load_findings(repo)

    # FP but hallucinated evidence (not in slice) -> nothing suppressed.
    halluc = tri.triage_findings(
        repo, findings=findings, client=_Client(tri.VERDICT_FALSE_POSITIVE, "zzzz_not_present")
    )
    assert not any(r.suppressed for r in halluc)

    # uncertain and true_positive -> nothing suppressed.
    unc = tri.triage_findings(repo, findings=findings, client=_Client(tri.VERDICT_UNCERTAIN))
    tp = tri.triage_findings(
        repo, findings=findings, client=_Client(tri.VERDICT_TRUE_POSITIVE, "select")
    )
    assert not any(r.suppressed for r in unc)
    assert not any(r.suppressed for r in tp)

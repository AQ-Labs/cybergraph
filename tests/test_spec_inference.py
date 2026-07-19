"""Tests for LLM-inferred taint specs (opt-in, validated, default-off)."""

from __future__ import annotations

import json
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.security import spec_inference as si


# --- mock client (no network) -----------------------------------------------
class _Client:
    def __init__(self, **buckets):
        payload = {k: buckets.get(k, []) for k in ("sinks", "sources", "sanitizers", "secrets")}
        self._payload = json.dumps(payload)

    def complete(self, system: str, user: str) -> str:
        return self._payload


# --- pure validation guardrail ----------------------------------------------
def test_validate_keeps_only_grounded_and_novel():
    calls = ["run_report_sql", "fetch_remote", "execute", "scrub_html"]
    proposals = {
        "sink": ["run_report_sql", "execute", "ghost_sink"],
        "sanitizer": ["scrub_html"],
    }
    specs = si.validate_proposals(proposals, calls)

    # grounded + novel -> accepted
    assert "run_report_sql" in specs.sinks
    assert "scrub_html" in specs.sanitizers
    # "execute" is grounded but already in SINK_KEYWORDS -> rejected (not novel)
    assert "execute" not in specs.sinks
    # "ghost_sink" is novel but not in call sites -> rejected (not grounded)
    assert "ghost_sink" not in specs.sinks
    assert len(specs.rejected) == 2


def test_validate_dedupes_and_lowercases():
    specs = si.validate_proposals({"sink": ["RunSql", "runsql"]}, ["runsql"])
    assert specs.sinks == ("runsql",)


def test_abstain_when_no_client_returns_empty():
    specs = si.propose_specs(Path("."), client=None)
    assert specs.total_accepted == 0
    assert specs.rejected == ()


def test_propose_with_client_validates_against_supplied_calls():
    calls = ["fetch_remote", "scrub_html", "execute"]
    client = _Client(sinks=["fetch_remote", "execute"], sanitizers=["scrub_html"], sources=["nope_src"])
    specs = si.propose_specs(Path("."), client=client, calls=calls)

    assert specs.sinks == ("fetch_remote",)          # grounded + novel
    assert specs.sanitizers == ("scrub_html",)       # grounded + novel
    assert "execute" not in specs.sinks              # not novel
    assert specs.sources == ()                       # "nope_src" not grounded


def test_propose_empty_calls_abstains():
    specs = si.propose_specs(Path("."), client=_Client(sinks=["x"]), calls=[])
    assert specs.total_accepted == 0


# --- integration: candidate_calls reads the real graph ----------------------
def test_candidate_calls_reflects_real_call_sites(tmp_path: Path):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "def handler(request):\n"
        "    q = request.query['q']\n"
        "    return run_report_sql('select ' + q)\n",
        encoding="utf-8",
    )
    build_graph(repo)

    calls = si.candidate_calls(repo)
    assert "run_report_sql" in calls

    # End-to-end: a client proposing the real, novel call name yields a validated sink.
    specs = si.propose_specs(repo, client=_Client(sinks=["run_report_sql"]))
    assert "run_report_sql" in specs.sinks

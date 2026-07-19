from pathlib import Path

from cybergraph.orchestrator import run_full_analysis
from cybergraph.report_model import AnalysisResult


def _build_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/users')\n"
        "def list_users(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    return repo


def test_run_full_analysis_builds_once_and_populates(tmp_path: Path):
    repo = _build_repo(tmp_path)
    result = run_full_analysis(repo)
    assert isinstance(result, AnalysisResult)
    assert result.counts["nodes"] > 0
    assert result.layers  # summarize_layers always returns the ontology layers
    assert "build" in result.timings
    assert result.errors == {}  # nothing failed on a clean run


def test_one_failing_stage_is_isolated(tmp_path: Path, monkeypatch):
    repo = _build_repo(tmp_path)
    import cybergraph.orchestrator as orch

    def _boom(_repo):
        raise RuntimeError("stage down")

    monkeypatch.setattr(orch, "find_secret_exposures", _boom)
    result = run_full_analysis(repo)
    assert "secret_exposures" in result.errors
    assert result.secret_exposures == []
    assert result.counts["nodes"] > 0  # run still completed


def test_build_stage_failure_isolated_and_run_completes(tmp_path: Path, monkeypatch):
    from cybergraph.report_model import to_json

    repo = _build_repo(tmp_path)
    import cybergraph.orchestrator as orch

    def _boom(_repo):
        raise RuntimeError("build down")

    monkeypatch.setattr(orch, "build_graph", _boom)
    result = run_full_analysis(repo)
    assert "build" in result.errors
    assert result.counts == {"nodes": 0, "edges": 0, "findings": 0}
    import json

    json.dumps(to_json(result))  # still valid JSON even when the build stage failed


def test_truncated_flag_reflects_report_node_cap(tmp_path: Path, monkeypatch):
    repo = _build_repo(tmp_path)
    import cybergraph.orchestrator as orch

    monkeypatch.setattr(
        orch,
        "build_graph",
        lambda _repo: {"nodes": orch.REPORT_NODE_CAP + 1, "edges": 0, "findings": 0},
    )
    result = run_full_analysis(repo)
    assert result.truncated is True

    monkeypatch.setattr(
        orch,
        "build_graph",
        lambda _repo: {"nodes": orch.REPORT_NODE_CAP, "edges": 0, "findings": 0},
    )
    result = run_full_analysis(repo)
    assert result.truncated is False

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

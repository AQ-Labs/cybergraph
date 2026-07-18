from pathlib import Path

from cybergraph.cli import main


def test_config_show_reports_llm_and_graph_state(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("CYBERGRAPH_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("CYBERGRAPH_LLM_API_KEY", raising=False)
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / ".cybergraph.toml").write_text(
        "[security]\nsinks = [\"run_report\"]\n", encoding="utf-8"
    )
    code = main(["config", "show", str(repo)])
    out = capsys.readouterr().out
    assert code == 0
    assert "LLM configured: no" in out
    assert "Graph built: no" in out
    assert "run_report" in out  # effective custom sink shown


def test_read_command_without_graph_prints_guidance(tmp_path, capsys):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    code = main(["layers", "--repo", str(repo)])
    out = capsys.readouterr().out
    assert code == 0
    assert "cybergraph build" in out  # tells the user to build first

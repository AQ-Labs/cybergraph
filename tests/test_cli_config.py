from pathlib import Path

import pytest

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


@pytest.mark.parametrize("command", ["ask", "explain", "paths", "sca"])
def test_guidance_printed_for_each_read_command(tmp_path, capsys, command):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    argv = [command]
    if command in ("ask", "explain"):
        argv.append("is there a vulnerability?")
    if command == "sca":
        argv.append(str(repo))  # sca takes repo as a positional, not --repo
    else:
        argv += ["--repo", str(repo)]
    code = main(argv)
    out = capsys.readouterr().out
    assert code == 0
    assert "cybergraph build" in out


def test_build_and_analyze_not_short_circuited_when_unbuilt(tmp_path, capsys):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    code = main(["build", str(repo)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Built security graph" in out  # actually built, not the guidance branch
    assert "cybergraph build" not in out

    repo2 = tmp_path / "app2"
    repo2.mkdir()
    (repo2 / "app2.py").write_text("y = 2\n", encoding="utf-8")
    code = main(["analyze", str(repo2), "--no-color", "--no-report"])
    out = capsys.readouterr().out
    assert code == 0
    assert "CyberGraph analysis" in out  # analyze actually ran, not the guidance branch


def test_config_show_llm_configured_yes(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CYBERGRAPH_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("CYBERGRAPH_LLM_API_KEY", "sk-test")
    repo = tmp_path / "app"
    repo.mkdir()
    code = main(["config", "show", str(repo)])
    out = capsys.readouterr().out
    assert code == 0
    assert "LLM configured: yes" in out
    assert "Ignored paths:" in out
    assert "Suppressed rules:" in out
    assert "Suppressed paths:" in out

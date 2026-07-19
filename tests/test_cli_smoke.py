
from cybergraph.cli import main


def test_existing_command_unaffected_by_dotenv_startup_hook(tmp_path, capsys, monkeypatch):
    """Regression guard for the global .env startup hook (cli.main).

    A .env present in cwd must not break an existing command end-to-end, and
    its keys must actually be loaded into the environment.
    """
    monkeypatch.delenv("CYBERGRAPH_LLM_PROVIDER", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("CYBERGRAPH_LLM_PROVIDER=anthropic\n", encoding="utf-8")

    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

    code = main(["build", str(repo)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Built security graph" in out

    import os

    assert os.environ["CYBERGRAPH_LLM_PROVIDER"] == "anthropic"
    os.environ.pop("CYBERGRAPH_LLM_PROVIDER", None)

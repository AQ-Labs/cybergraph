from pathlib import Path

from cybergraph.env import load_dotenv


def test_load_dotenv_sets_absent_and_ignores_comments(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("CYBERGRAPH_LLM_API_KEY", raising=False)
    monkeypatch.delenv("CYBERGRAPH_LLM_PROVIDER", raising=False)
    (tmp_path / ".env").write_text(
        "# a comment\n"
        "\n"
        'CYBERGRAPH_LLM_API_KEY="sk-abc123"\n'
        "CYBERGRAPH_LLM_PROVIDER=anthropic\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    n = load_dotenv(tmp_path)
    assert n == 2
    import os
    assert os.environ["CYBERGRAPH_LLM_API_KEY"] == "sk-abc123"  # quotes stripped
    assert os.environ["CYBERGRAPH_LLM_PROVIDER"] == "anthropic"
    # load_dotenv sets os.environ directly (by design, so the values persist for
    # the rest of the process); monkeypatch's own undo-stack does not reliably
    # revert a key it saw as absent and then observes changed out-of-band, so
    # pop the keys directly to avoid leaking into other tests in the session.
    os.environ.pop("CYBERGRAPH_LLM_API_KEY", None)
    os.environ.pop("CYBERGRAPH_LLM_PROVIDER", None)


def test_load_dotenv_never_overrides_existing_env(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # avoid picking up a real .env at the repo cwd
    monkeypatch.setenv("CYBERGRAPH_LLM_PROVIDER", "openai")
    (tmp_path / ".env").write_text("CYBERGRAPH_LLM_PROVIDER=anthropic\n", encoding="utf-8")
    load_dotenv(tmp_path)
    import os
    assert os.environ["CYBERGRAPH_LLM_PROVIDER"] == "openai"  # real env wins


def test_load_dotenv_noop_when_absent(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # avoid picking up a real .env at the repo cwd
    assert load_dotenv(tmp_path) == 0

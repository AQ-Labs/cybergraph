from pathlib import Path

from cybergraph.env import _parse, load_dotenv


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


def test_parse_key_equals_value_variants():
    assert _parse("KEY=")["KEY"] == ""
    assert _parse("X=a=b")["X"] == "a=b"
    assert _parse(" K = v ") == {"K": "v"}


def test_parse_strips_utf8_bom(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("CYBERGRAPH_LLM_API_KEY", raising=False)
    (tmp_path / ".env").write_bytes(
        "CYBERGRAPH_LLM_API_KEY=sk-bom\n".encode("utf-8-sig")
    )
    monkeypatch.chdir(tmp_path)
    n = load_dotenv(tmp_path)
    import os

    assert n == 1
    assert os.environ["CYBERGRAPH_LLM_API_KEY"] == "sk-bom"
    assert "﻿CYBERGRAPH_LLM_API_KEY" not in os.environ
    os.environ.pop("CYBERGRAPH_LLM_API_KEY", None)


def test_parse_handles_crlf_and_blank_lines():
    text = "# comment\r\n\r\nFOO=bar\r\n\r\nBAZ=qux\r\n"
    assert _parse(text) == {"FOO": "bar", "BAZ": "qux"}


def test_parse_strips_export_prefix():
    assert _parse("export FOO=bar\n") == {"FOO": "bar"}
    # a key that merely starts with "export" (no following space) is untouched
    assert _parse("exported=1\n") == {"exported": "1"}


def test_parse_strips_inline_comment_only_after_whitespace():
    assert _parse("K=v # comment\n")["K"] == "v"
    # no whitespace before '#' -> not treated as a comment
    assert _parse("K=v#nocomment\n")["K"] == "v#nocomment"
    # '#' inside quotes is preserved even with leading whitespace
    assert _parse('K="a #b"\n')["K"] == "a #b"


def test_load_dotenv_prefers_repo_root_over_cwd_and_dedups(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("CYBERGRAPH_LLM_PROVIDER", raising=False)
    repo_root = tmp_path / "repo"
    cwd = tmp_path / "cwd"
    repo_root.mkdir()
    cwd.mkdir()
    (repo_root / ".env").write_text("CYBERGRAPH_LLM_PROVIDER=repo-root\n", encoding="utf-8")
    (cwd / ".env").write_text("CYBERGRAPH_LLM_PROVIDER=cwd\n", encoding="utf-8")
    monkeypatch.chdir(cwd)
    n = load_dotenv(repo_root)
    import os

    assert n == 1  # the cwd's duplicate key is not double-applied
    assert os.environ["CYBERGRAPH_LLM_PROVIDER"] == "repo-root"
    os.environ.pop("CYBERGRAPH_LLM_PROVIDER", None)

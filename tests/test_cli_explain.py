"""CLI and MCP surface tests for grounded answering."""

from __future__ import annotations

from pathlib import Path

import pytest

from cybergraph.cli import main


def _build(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/users')\n"
        "def list_users(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    main(["build", str(repo)])
    return repo


def test_explain_prints_cited_answer(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = _build(tmp_path)
    capsys.readouterr()  # drop build output

    exit_code = main(["explain", "Which routes reach SQL execution?", "--repo", str(repo)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Confidence:" in out
    assert "app.py" in out
    assert "Evidence:" in out


def test_explain_llm_without_config_falls_back(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CYBERGRAPH_LLM_PROVIDER", raising=False)
    repo = _build(tmp_path)
    capsys.readouterr()

    main(["explain", "Which routes reach SQL execution?", "--repo", str(repo), "--llm"])
    out = capsys.readouterr().out

    assert "No LLM configured" in out
    assert "Confidence:" in out


def test_mcp_server_registers_grounded_tool() -> None:
    pytest.importorskip("fastmcp")
    from cybergraph import mcp_server

    assert mcp_server.mcp is not None
    # The grounded answer tool function is defined at module import. The old
    # right-hand disjunct restated the line above, so the whole assertion held
    # even if the tool were never registered; pin the tool itself.
    assert hasattr(mcp_server, "grounded_security_answer_tool")
    assert callable(mcp_server.grounded_security_answer_tool)

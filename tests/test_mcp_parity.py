import pytest


def test_mcp_exposes_full_workflow_tools():
    pytest.importorskip("fastmcp")
    from cybergraph import mcp_server

    # The new orchestrator-backed tool functions are defined at import time.
    for name in [
        "analyze_repo_tool",
        "top_risks_tool",
        "secret_exposures_tool",
        "prioritize_dependencies_tool",
        "iac_attack_paths_tool",
    ]:
        assert hasattr(mcp_server, name), f"missing MCP tool: {name}"


def test_analyze_repo_tool_returns_versioned_json(tmp_path):
    pytest.importorskip("fastmcp")
    from cybergraph import mcp_server

    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/x')\ndef h(request):\n    return db.execute(request.query['q'])\n",
        encoding="utf-8",
    )
    doc = mcp_server.analyze_repo_tool(str(repo))
    assert doc["schema"] == "cybergraph.analysis/1"
    assert doc["counts"]["nodes"] > 0

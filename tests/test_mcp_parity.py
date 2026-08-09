import json

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
        "import_scanner_report_tool",
        "import_vulnerabilities_tool",
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


def _built_repo(tmp_path):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/x')\ndef h(request):\n    return db.execute(request.query['q'])\n",
        encoding="utf-8",
    )
    from cybergraph.build import build_graph

    build_graph(repo)
    return repo


def test_component_tools_return_shapes(tmp_path):
    pytest.importorskip("fastmcp")
    from cybergraph import mcp_server

    repo = _built_repo(tmp_path)

    top_risks = mcp_server.top_risks_tool(str(repo))
    assert isinstance(top_risks["top_risks"], list)

    secrets = mcp_server.secret_exposures_tool(str(repo))
    assert isinstance(secrets["count"], int)
    assert isinstance(secrets["text"], str)

    deps = mcp_server.prioritize_dependencies_tool(str(repo))
    assert isinstance(deps["count"], int)
    assert isinstance(deps["text"], str)

    iac = mcp_server.iac_attack_paths_tool(str(repo))
    assert isinstance(iac["count"], int)
    assert isinstance(iac["text"], str)


def test_import_scanner_report_tool_imports_findings(tmp_path):
    pytest.importorskip("fastmcp")
    from cybergraph import mcp_server

    repo = _built_repo(tmp_path)
    report = tmp_path / "semgrep.json"
    report.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.lang.security.sql-injection",
                        "path": "app.py",
                        "start": {"line": 3},
                        "end": {"line": 3},
                        "extra": {"severity": "ERROR", "message": "SQL injection"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = mcp_server.import_scanner_report_tool(str(report), str(repo))
    assert result == {"imported": 1}


def test_import_vulnerabilities_tool_imports_records(tmp_path):
    pytest.importorskip("fastmcp")
    from cybergraph import mcp_server

    repo = _built_repo(tmp_path)
    (repo / "requirements.txt").write_text("fastapi==0.110.0\n", encoding="utf-8")
    report = tmp_path / "osv.json"
    report.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "packages": [
                            {
                                "package": {
                                    "name": "fastapi",
                                    "version": "0.110.0",
                                    "ecosystem": "PyPI",
                                },
                                "vulnerabilities": [
                                    {"id": "GHSA-demo", "summary": "Demo vulnerability"}
                                ],
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = mcp_server.import_vulnerabilities_tool(str(report), str(repo))
    assert result["vulnerabilities"] == 1
    assert "matched_dependencies" in result


def test_check_change_tool_is_exposed():
    pytest.importorskip("fastmcp")
    from cybergraph import mcp_server

    assert hasattr(mcp_server, "check_change_tool")


def test_check_change_tool_and_cli_agree(tmp_path):
    """Two surfaces over one orchestrator must never disagree."""
    pytest.importorskip("fastmcp")
    import contextlib
    import io
    import json as _json
    import subprocess

    from cybergraph import mcp_server
    from cybergraph.cli import main

    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "b"],
        cwd=tmp_path, check=True,
    )

    tool_result = mcp_server.check_change_tool(str(tmp_path))
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        main(["check", str(tmp_path), "--json"])
    assert tool_result == _json.loads(buffer.getvalue())


def test_mcp_server_does_not_import_from_the_cli():
    """C6: the MCP surface must not reach into CLI internals."""
    from pathlib import Path

    source = Path("src/cybergraph/mcp_server.py").read_text(encoding="utf-8")
    assert "from .cli import" not in source
    assert "from cybergraph.cli import" not in source

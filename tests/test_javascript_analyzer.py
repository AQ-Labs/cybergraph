from pathlib import Path

from cybergraph.analysis.javascript import analyze_javascript_file


def test_javascript_analyzer_detects_express_routes_and_sinks(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.js"
    app.write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.post('/login', async (req, res) => {\n"
        "  const token = process.env.API_TOKEN;\n"
        "  const rows = await db.query(req.body.name);\n"
        "  res.json(rows);\n"
        "});\n",
        encoding="utf-8",
    )

    nodes, edges, findings = analyze_javascript_file(app, repo)

    assert any(node.kind == "Entrypoint" and node.name == "/login" for node in nodes)
    assert any(edge.kind == "EXPOSES_ENTRYPOINT" for edge in edges)
    assert any(edge.kind == "REACHES_SINK" for edge in edges)
    assert any(edge.kind == "USES_SECRET" for edge in edges)
    assert any(finding.rule_id == "CG-JS-SINK-CALL" for finding in findings)

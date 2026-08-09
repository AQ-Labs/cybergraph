from pathlib import Path

from cybergraph.analysis.javascript import analyze_javascript_file
from cybergraph.analysis.resolve import EDGE_CALLS_RESOLVED, resolve_calls


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


def test_javascript_analyzer_respects_inline_finding_suppression(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.js"
    app.write_text(
        "function handler(req) {\n"
        "  // cybergraph: ignore CG-JS-SINK-CALL accepted fixture query\n"
        "  return db.query(req.body.name);\n"
        "}\n",
        encoding="utf-8",
    )

    _nodes, edges, findings = analyze_javascript_file(app, repo)

    assert any(edge.kind == "REACHES_SINK" for edge in edges)
    assert findings == []


def test_javascript_analyzer_respects_bare_inline_finding_suppression(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.js"
    app.write_text(
        "function handler(req) {\n"
        "  // cybergraph: ignore\n"
        "  return db.query(req.body.name);\n"
        "}\n",
        encoding="utf-8",
    )

    _nodes, edges, findings = analyze_javascript_file(app, repo)

    assert any(edge.kind == "REACHES_SINK" for edge in edges)
    assert findings == []


def test_javascript_analyzer_detects_bare_eval_sink(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.js"
    app.write_text(
        "function handler(req) {\n"
        "  return eval(req.query.code);\n"
        "}\n",
        encoding="utf-8",
    )

    _nodes, edges, findings = analyze_javascript_file(app, repo)

    assert any(edge.kind == "CALLS" and edge.target == "eval" for edge in edges)
    assert any(edge.kind == "REACHES_SINK" and edge.target == "eval" for edge in edges)
    assert any(finding.rule_id == "CG-JS-SINK-CALL" for finding in findings)


def test_javascript_analyzer_emits_calls_for_named_express_handlers(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.js"
    app.write_text(
        "app.get('/users', listUsers);\n"
        "function listUsers(req, res) {\n"
        "  return serviceQuery(req.query.name);\n"
        "}\n"
        "function serviceQuery(name) {\n"
        "  return db.query(name);\n"
        "}\n",
        encoding="utf-8",
    )

    nodes, edges, _findings = analyze_javascript_file(app, repo)
    resolved = resolve_calls(nodes, edges)

    assert any(
        edge.kind == "CALLS"
        and edge.source.startswith("app.js::route:/users")
        and edge.target == "listUsers"
        for edge in edges
    )
    assert any(
        edge.kind == "CALLS"
        and edge.source == "app.js::listUsers"
        and edge.target == "serviceQuery"
        for edge in edges
    )
    assert any(
        edge.kind == EDGE_CALLS_RESOLVED
        and edge.source == "app.js::listUsers"
        and edge.target == "app.js::serviceQuery"
        for edge in resolved
    )


def _input_nodes(nodes: list) -> list:
    return [n for n in nodes if n.kind == "Input"]


def test_javascript_marker_in_comment_or_string_is_not_a_source(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.js"
    app.write_text(
        "function h() {\n"
        "  const note = 'see req.body docs';  // req.query note\n"
        "  const t = `plain req.params text`;\n"
        "  return note + t;\n"
        "}\n",
        encoding="utf-8",
    )
    nodes, edges, _findings = analyze_javascript_file(app, repo)
    assert _input_nodes(nodes) == []
    assert not any(edge.kind == "READS_INPUT" for edge in edges)


def test_javascript_genuine_source_still_detected_and_reaches_sink(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.js"
    app.write_text(
        "function handler(req) {\n"
        "  const name = req.query.name;\n"
        "  return db.query(name);\n"
        "}\n",
        encoding="utf-8",
    )
    nodes, edges, findings = analyze_javascript_file(app, repo)
    assert _input_nodes(nodes), "genuine req.query must create an Input source"
    assert any(edge.kind == "READS_INPUT" for edge in edges)
    assert any(edge.kind == "TAINTS" for edge in edges)
    assert any(f.rule_id == "CG-JS-SINK-CALL" for f in findings)


def test_javascript_template_interpolation_source_is_detected(tmp_path: Path) -> None:
    # A real source inside a `${...}` hole must survive stripping.
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.js"
    app.write_text(
        "function handler(req) {\n"
        "  const q = `name=${req.query.name}`;\n"
        "  return q;\n"
        "}\n",
        encoding="utf-8",
    )
    nodes, _edges, _findings = analyze_javascript_file(app, repo)
    assert _input_nodes(nodes)


def test_javascript_genuine_source_beside_string_marker_still_detected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.js"
    app.write_text(
        "function handler(req) {\n"
        "  const name = req.query.name + ' see req.body here';\n"
        "  return db.query(name);\n"
        "}\n",
        encoding="utf-8",
    )
    nodes, edges, _findings = analyze_javascript_file(app, repo)
    assert _input_nodes(nodes)
    assert any(edge.kind == "TAINTS" for edge in edges)

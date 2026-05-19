from pathlib import Path

from cybergraph.analysis.python import analyze_python_file


def test_python_analyzer_maps_routes_guards_and_sanitizers(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text(
        "def login_required(fn):\n"
        "    return fn\n\n"
        "def validate_name(value):\n"
        "    return value\n\n"
        "@app.post('/users')\n"
        "@login_required\n"
        "def create_user(request):\n"
        "    name = validate_name(request.json['name'])\n"
        "    return db.execute('insert into users values (?)', [name])\n",
        encoding="utf-8",
    )

    nodes, edges, findings = analyze_python_file(app, repo)

    create = next(node for node in nodes if node.name == "create_user")
    assert create.properties["entrypoint"] is True
    assert create.properties["route"]["path"] == "/users"
    assert any(edge.kind == "EXPOSES_ENTRYPOINT" for edge in edges)
    assert any(edge.kind == "GUARDS" for edge in edges)
    assert any(edge.kind == "SANITIZES" for edge in edges)
    assert any(finding.rule_id == "CG-SINK-CALL" for finding in findings)


def test_python_analyzer_respects_inline_finding_suppression(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text(
        "def handler():\n"
        "    # cybergraph: ignore CG-SINK-CALL accepted in test fixture\n"
        "    return db.execute('select 1')\n",
        encoding="utf-8",
    )

    _nodes, edges, findings = analyze_python_file(app, repo)

    assert any(edge.kind == "REACHES_SINK" for edge in edges)
    assert findings == []

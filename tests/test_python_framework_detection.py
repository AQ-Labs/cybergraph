from pathlib import Path

from cybergraph.analysis.python import analyze_python_file

# A route whose query really is unsafe, so a suppression test cannot pass by
# accident. The earlier fixture used `db.execute('select 1')`, which the sink
# predicates now correctly clear — the test would have gone on "passing" while
# testing nothing at all.
UNSAFE_ROUTE = (
    "@app.get('/u')\n"
    "def handler(uid):\n"
    "{comment}"
    "    return db.execute('select ' + uid)\n"
)


def _analyze(tmp_path: Path, source: str):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text(source, encoding="utf-8")
    return analyze_python_file(app, repo)


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
    # The query is parameterized, so the sink is inventory and not a finding.
    assert any(edge.kind == "REACHES_SINK" and edge.target == "db.execute" for edge in edges)
    assert findings == [], [finding.rule_id for finding in findings]


def test_python_analyzer_reports_the_registry_rule_for_an_unsafe_route(tmp_path: Path) -> None:
    _nodes, _edges, findings = _analyze(tmp_path, UNSAFE_ROUTE.format(comment=""))

    assert [finding.rule_id for finding in findings] == ["CG-SQL-EXEC"]


def test_python_analyzer_respects_inline_finding_suppression(tmp_path: Path) -> None:
    _nodes, edges, findings = _analyze(
        tmp_path,
        UNSAFE_ROUTE.format(comment="    # cybergraph: ignore CG-SQL-EXEC accepted in fixture\n"),
    )

    assert any(edge.kind == "REACHES_SINK" for edge in edges)
    assert findings == []


def test_python_analyzer_respects_bare_inline_suppression(tmp_path: Path) -> None:
    _nodes, edges, findings = _analyze(
        tmp_path, UNSAFE_ROUTE.format(comment="    # cybergraph: ignore\n")
    )

    assert any(edge.kind == "REACHES_SINK" for edge in edges)
    assert findings == []


def test_python_analyzer_maps_fastapi_depends_guards(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text(
        "from fastapi import Depends\n\n"
        "def require_admin():\n"
        "    return True\n\n"
        "@app.get('/admin')\n"
        "def admin_panel(allowed = Depends(require_admin)):\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )

    _nodes, edges, _findings = analyze_python_file(app, repo)

    assert any(edge.kind == "GUARDS" and edge.target == "require_admin" for edge in edges)


# A route whose query the analyser can neither clear nor confirm, so it reports
# the derived `-UNVERIFIED` id rather than the registry one. Accepting the rule
# has to cover both, or a repository that suppressed `CG-SQL-EXEC` on a line
# gets a fresh medium on that same line the moment the shape drifts into
# abstention.
UNVERIFIED_ROUTE = (
    "@app.get('/u')\n"
    "def handler(uid):\n"
    "{comment}"
    "    return db.execute(build(uid))\n"
)


def test_python_analyzer_reports_the_unverified_rule_when_it_cannot_confirm(
    tmp_path: Path,
) -> None:
    _nodes, _edges, findings = _analyze(tmp_path, UNVERIFIED_ROUTE.format(comment=""))

    assert [finding.rule_id for finding in findings] == ["CG-SQL-EXEC-UNVERIFIED"]


def test_inline_suppression_of_a_rule_covers_its_unverified_variant(tmp_path: Path) -> None:
    _nodes, edges, findings = _analyze(
        tmp_path,
        UNVERIFIED_ROUTE.format(comment="    # cybergraph: ignore CG-SQL-EXEC accepted\n"),
    )

    assert findings == [], [finding.rule_id for finding in findings]
    assert any(edge.kind == "REACHES_SINK" for edge in edges)


def test_inline_suppression_of_the_unverified_variant_does_not_hide_the_confirmed_rule(
    tmp_path: Path,
) -> None:
    """The relation is one-way on purpose.

    Accepting an abstention is a statement about a value the analyser could not
    read. It must not carry over to the day it *can* read it and finds the
    injection.
    """
    _nodes, _edges, findings = _analyze(
        tmp_path,
        UNSAFE_ROUTE.format(comment="    # cybergraph: ignore CG-SQL-EXEC-UNVERIFIED\n"),
    )

    assert [finding.rule_id for finding in findings] == ["CG-SQL-EXEC"]

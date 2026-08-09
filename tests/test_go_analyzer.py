"""Tests for the Go security analyzer."""

from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.go import analyze_go_file
from cybergraph.build import build_graph
from cybergraph.graph import GraphStore
from cybergraph.security.attack_paths import find_attack_paths


def _edge_kinds(repo: Path) -> dict[str, int]:
    store = GraphStore.open_for_repo(repo)
    try:
        rows = store.conn.execute("SELECT kind, COUNT(*) AS n FROM edges GROUP BY kind").fetchall()
        return {row["kind"]: row["n"] for row in rows}
    finally:
        store.close()


def test_go_net_http_route_and_sql_sink(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "main.go").write_text(
        "package main\n"
        "import (\n"
        "    \"database/sql\"\n"
        "    \"net/http\"\n"
        ")\n"
        "func listUsers(w http.ResponseWriter, r *http.Request) {\n"
        "    name := r.URL.Query().Get(\"name\")\n"
        "    db.Query(\"select * from users where name = '\" + name + \"'\")\n"
        "}\n"
        "func main() {\n"
        "    http.HandleFunc(\"/users\", listUsers)\n"
        "}\n",
        encoding="utf-8",
    )
    counts = build_graph(repo)
    kinds = _edge_kinds(repo)

    assert counts["findings"] >= 1  # the SQL sink
    assert kinds.get("EXPOSES_ENTRYPOINT", 0) >= 1  # http.HandleFunc("/users", ...)
    assert kinds.get("REACHES_SINK", 0) >= 1  # db.Query

    # The route links to its handler, so the path connects route -> handler -> sink.
    paths = find_attack_paths(repo)
    assert any("main.go::listUsers" in p.nodes and p.sink.lower().startswith("db") for p in paths)


def test_go_gin_route_and_command_sink(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "server.go").write_text(
        "package main\n"
        "import (\n"
        "    \"os/exec\"\n"
        "    \"github.com/gin-gonic/gin\"\n"
        ")\n"
        "func runCmd(c *gin.Context) {\n"
        "    cmd := c.Query(\"cmd\")\n"
        "    exec.Command(\"sh\", \"-c\", cmd)\n"
        "}\n"
        "func main() {\n"
        "    r := gin.Default()\n"
        "    r.POST(\"/run\", runCmd)\n"
        "}\n",
        encoding="utf-8",
    )
    build_graph(repo)
    kinds = _edge_kinds(repo)

    assert kinds.get("EXPOSES_ENTRYPOINT", 0) >= 1  # r.POST("/run", ...)
    assert kinds.get("REACHES_SINK", 0) >= 1  # exec.Command


def test_go_secret_access_detected(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "config.go").write_text(
        "package main\n"
        "import \"os\"\n"
        "func loadConfig() string {\n"
        "    return os.Getenv(\"API_TOKEN\")\n"
        "}\n",
        encoding="utf-8",
    )
    build_graph(repo)
    kinds = _edge_kinds(repo)

    assert kinds.get("USES_SECRET", 0) >= 1


def test_go_secure_file_has_no_sink_findings(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "safe.go").write_text(
        "package main\n"
        "import \"fmt\"\n"
        "func greet(name string) string {\n"
        "    return fmt.Sprint(\"hello \", name)\n"
        "}\n",
        encoding="utf-8",
    )
    counts = build_graph(repo)
    # fmt.Sprint is not a configured sink; a benign helper yields no sink findings.
    store = GraphStore.open_for_repo(repo)
    try:
        sink_findings = store.conn.execute(
            "SELECT COUNT(*) FROM findings WHERE rule_id = 'CG-GO-SINK-CALL'"
        ).fetchone()[0]
    finally:
        store.close()
    assert sink_findings == 0
    assert counts["nodes"] >= 1  # File + function node still produced


def _input_nodes(nodes: list) -> list:
    return [n for n in nodes if n.kind == "Input"]


def test_go_marker_in_comment_or_string_is_not_a_source(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "safe.go").write_text(
        "package main\n"
        "func h() {\n"
        '    host := "see .body docs"    // r.URL.Query() note\n'
        "    _ = host\n"
        "}\n",
        encoding="utf-8",
    )
    nodes, edges, _findings = analyze_go_file(repo / "safe.go", repo)
    assert _input_nodes(nodes) == []
    assert not any(e.kind == "READS_INPUT" for e in edges)


def test_go_genuine_source_still_detected_and_reaches_sink(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "main.go").write_text(
        "package main\n"
        "func listUsers(w http.ResponseWriter, r *http.Request) {\n"
        '    name := r.URL.Query().Get("name")\n'
        '    db.Query("select * from users where n = \'" + name + "\'")\n'
        "}\n"
        "func main() {\n"
        '    http.HandleFunc("/users", listUsers)\n'
        "}\n",
        encoding="utf-8",
    )
    nodes, edges, _findings = analyze_go_file(repo / "main.go", repo)
    assert _input_nodes(nodes), "genuine r.URL.Query() must create an Input source"
    assert any(e.kind == "READS_INPUT" for e in edges)
    assert any(e.kind == "TAINTS" for e in edges)


def test_go_genuine_source_beside_string_marker_still_detected(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    # A real request read on the same line as a string that contains a marker.
    (repo / "mixed.go").write_text(
        "package main\n"
        "func h(w http.ResponseWriter, r *http.Request) {\n"
        '    name := r.URL.Query().Get("see .body docs")\n'
        '    db.Query("select * from t where n = \'" + name + "\'")\n'
        "}\n",
        encoding="utf-8",
    )
    nodes, edges, _findings = analyze_go_file(repo / "mixed.go", repo)
    assert _input_nodes(nodes)
    assert any(e.kind == "TAINTS" for e in edges)

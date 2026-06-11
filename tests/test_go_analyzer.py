"""Tests for the Go security analyzer."""

from __future__ import annotations

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph import GraphStore


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

"""Tests for the Java (Spring) and C# (ASP.NET Core) analyzers."""

from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.java import analyze_java_file
from cybergraph.build import build_graph
from cybergraph.graph import GraphStore
from cybergraph.security.attack_paths import find_attack_paths


def _input_nodes(nodes: list) -> list:
    return [n for n in nodes if n.kind == "Input"]


def _edge_kinds(repo: Path) -> dict[str, int]:
    store = GraphStore.open_for_repo(repo)
    try:
        rows = store.conn.execute("SELECT kind, COUNT(*) AS n FROM edges GROUP BY kind").fetchall()
        return {row["kind"]: row["n"] for row in rows}
    finally:
        store.close()


def test_java_spring_route_and_jdbc_sink(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "UserController.java").write_text(
        "package demo;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class UserController {\n"
        "    @GetMapping(\"/users\")\n"
        "    public String listUsers(@RequestParam String name) {\n"
        "        return statement.executeQuery(\"select * from users where n='\" + name + \"'\");\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    counts = build_graph(repo)
    kinds = _edge_kinds(repo)

    assert kinds.get("EXPOSES_ENTRYPOINT", 0) >= 1  # @GetMapping
    assert kinds.get("REACHES_SINK", 0) >= 1  # executeQuery
    assert counts["findings"] >= 1


def test_java_route_links_to_handler_method(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "C.java").write_text(
        "public class C {\n"
        "    @PostMapping(\"/run\")\n"
        "    public void run(String cmd) {\n"
        "        Runtime.getRuntime().exec(cmd);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    build_graph(repo)
    kinds = _edge_kinds(repo)
    # Route node links to the handler method via a CALLS edge.
    assert kinds.get("CALLS", 0) >= 1
    assert kinds.get("REACHES_SINK", 0) >= 1
    # Sink attributed to the handler method, so route -> method -> sink connects.
    paths = find_attack_paths(repo)
    assert any("C.java::run" in p.nodes for p in paths)


def test_csharp_attribute_route_and_sql_sink(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "UsersController.cs").write_text(
        "using Microsoft.AspNetCore.Mvc;\n"
        "public class UsersController : ControllerBase {\n"
        "    [HttpGet(\"/users\")]\n"
        "    public IActionResult List(string name) {\n"
        "        var cmd = new SqlCommand(\"select * from users where n='\" + name + \"'\");\n"
        "        return Ok(cmd.ExecuteReader());\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    counts = build_graph(repo)
    kinds = _edge_kinds(repo)

    assert kinds.get("EXPOSES_ENTRYPOINT", 0) >= 1  # [HttpGet]
    assert kinds.get("REACHES_SINK", 0) >= 1  # SqlCommand / ExecuteReader
    assert counts["findings"] >= 1


def test_csharp_minimal_api_route(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "Program.cs").write_text(
        "var app = WebApplication.Create();\n"
        "app.MapGet(\"/health\", () => \"ok\");\n"
        "app.Run();\n",
        encoding="utf-8",
    )
    build_graph(repo)
    assert _edge_kinds(repo).get("EXPOSES_ENTRYPOINT", 0) >= 1


def test_csharp_secret_access(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "Config.cs").write_text(
        "public class Config {\n"
        "    public string Token() {\n"
        "        return Environment.GetEnvironmentVariable(\"API_TOKEN\");\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    build_graph(repo)
    assert _edge_kinds(repo).get("USES_SECRET", 0) >= 1


def test_java_marker_in_comment_string_or_textblock_is_not_a_source(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "C.java").write_text(
        "public class C {\n"
        "    public String h() {\n"
        '        String host = "see getParameter docs";  // @RequestParam note\n'
        '        String block = """\n'
        "            request.getHeader inside block\n"
        '            """;\n'
        "        return host + block;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    nodes, edges, _findings = analyze_java_file(repo / "C.java", repo)
    assert _input_nodes(nodes) == []
    assert not any(e.kind == "READS_INPUT" for e in edges)


def test_java_genuine_source_still_detected_and_reaches_sink(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "C.java").write_text(
        "public class C {\n"
        "    public String h() {\n"
        '        String name = request.getParameter("name");\n'
        '        return statement.executeQuery("select * from t where n=\'" + name + "\'");\n'
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    nodes, edges, findings = analyze_java_file(repo / "C.java", repo)
    assert _input_nodes(nodes), "genuine getParameter must create an Input source"
    assert any(e.kind == "READS_INPUT" for e in edges)
    assert any(e.kind == "TAINTS" for e in edges)
    assert any(f.rule_id == "CG-JAVA-SINK-CALL" for f in findings)


def test_java_genuine_source_beside_string_marker_still_detected(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "C.java").write_text(
        "public class C {\n"
        "    public String h() {\n"
        '        String name = request.getParameter("see getParameter docs");\n'
        '        return statement.executeQuery("select * from t where n=\'" + name + "\'");\n'
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    nodes, edges, _findings = analyze_java_file(repo / "C.java", repo)
    assert _input_nodes(nodes)
    assert any(e.kind == "TAINTS" for e in edges)

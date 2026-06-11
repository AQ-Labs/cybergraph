"""Tests for the Java (Spring) and C# (ASP.NET Core) analyzers."""

from __future__ import annotations

from pathlib import Path

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

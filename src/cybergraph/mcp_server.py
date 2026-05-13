"""Optional MCP server for CyberGraph."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .build import build_graph
from .rag import answer_question
from .security import find_attack_paths, format_attack_paths

try:
    from fastmcp import FastMCP
except ImportError:  # pragma: no cover - optional dependency
    FastMCP = None  # type: ignore[assignment]


if FastMCP is not None:
    mcp = FastMCP(
        "cybergraph",
        instructions=(
            "Cybersecurity knowledge graph for code review. Build the graph, ask security "
            "questions, and inspect potential entrypoint-to-sink attack paths."
        ),
    )

    @mcp.tool()
    def build_security_graph_tool(repo_root: str = ".") -> dict[str, Any]:
        """Build the local CyberGraph database for a repository."""
        return build_graph(Path(repo_root).resolve())

    @mcp.tool()
    def query_security_graph_tool(question: str, repo_root: str = ".") -> dict[str, str]:
        """Ask a security-review question and return evidence-backed text."""
        return {"answer": answer_question(Path(repo_root).resolve(), question)}

    @mcp.tool()
    def explain_attack_path_tool(repo_root: str = ".", max_depth: int = 5) -> dict[str, str]:
        """Explain possible entrypoint-to-sensitive-sink paths."""
        paths = find_attack_paths(Path(repo_root).resolve(), max_depth=max_depth)
        return {"answer": format_attack_paths(paths)}
else:
    mcp = None


def main() -> None:
    if mcp is None:
        raise SystemExit("Install cybergraph[mcp] to run the MCP server.")
    mcp.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()

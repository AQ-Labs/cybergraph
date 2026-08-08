"""Optional MCP server for CyberGraph."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .build import build_graph
from .graph import GraphStore
from .rag import answer_grounded, answer_question, format_grounded_answer
from .security import find_attack_paths, format_attack_paths, load_scanner_findings

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
        # Explanation surface: this tool exists so a reviewer can trace the real
        # code path, so it reports suppressed paths too.
        paths = find_attack_paths(
            Path(repo_root).resolve(), max_depth=max_depth, apply_suppressions=False
        )
        return {"answer": format_attack_paths(paths)}

    @mcp.tool()
    def grounded_security_answer_tool(question: str, repo_root: str = ".") -> dict[str, Any]:
        """Answer a security question with cited, confidence-scored graph evidence.

        Local-only: returns structured evidence and an explicit confidence level
        (high/medium/low/insufficient) without contacting any external LLM.
        """
        answer = answer_grounded(Path(repo_root).resolve(), question)
        return {
            "answer": format_grounded_answer(answer),
            "category": answer.category,
            "confidence": answer.confidence,
            "citations": list(answer.citations),
        }

    @mcp.tool()
    def analyze_repo_tool(repo_root: str = ".", limit: int = 10) -> dict[str, Any]:
        """Build the graph and run every analysis; return the full result as JSON."""
        from .orchestrator import run_full_analysis
        from .report_model import to_json

        return to_json(run_full_analysis(Path(repo_root).resolve(), limit=limit))

    @mcp.tool()
    def top_risks_tool(repo_root: str = ".", limit: int = 10) -> dict[str, Any]:
        """Return the ranked top security risks across all graph layers."""
        from .security.investigate import collect_top_risks

        risks = collect_top_risks(Path(repo_root).resolve(), limit=limit)
        return {"top_risks": [
            {"category": r.category, "title": r.title, "risk_score": r.risk_score,
             "risk_label": r.risk_label, "detail": r.detail}
            for r in risks
        ]}

    @mcp.tool()
    def secret_exposures_tool(repo_root: str = ".") -> dict[str, Any]:
        """Return prioritized secret-exposure paths (reachable secret -> sink)."""
        from .security.secrets import find_secret_exposures, format_secret_exposures

        exposures = find_secret_exposures(Path(repo_root).resolve())
        return {"count": len(exposures), "text": format_secret_exposures(exposures)}

    @mcp.tool()
    def prioritize_dependencies_tool(repo_root: str = ".") -> dict[str, Any]:
        """Return dependency vulnerabilities ranked by severity x reachability."""
        from .security.sca import format_sca, prioritize_vulnerabilities

        priorities = prioritize_vulnerabilities(Path(repo_root).resolve())
        return {"count": len(priorities), "text": format_sca(priorities)}

    @mcp.tool()
    def iac_attack_paths_tool(repo_root: str = ".", max_depth: int = 6) -> dict[str, Any]:
        """Return cloud attack paths (public exposure -> privileged IaC resource)."""
        from .security.iac_paths import find_iac_attack_paths, format_iac_attack_paths

        paths = find_iac_attack_paths(Path(repo_root).resolve(), max_depth=max_depth)
        return {"count": len(paths), "text": format_iac_attack_paths(paths)}

    @mcp.tool()
    def import_scanner_report_tool(report_path: str, repo_root: str = ".") -> dict[str, Any]:
        """Import findings from a Semgrep, SARIF, or Gitleaks JSON report into the graph."""
        store = GraphStore.open_for_repo(Path(repo_root).resolve())
        findings = load_scanner_findings(Path(report_path).resolve())
        store.add_findings(findings)
        store.close()
        return {"imported": len(findings)}

    @mcp.tool()
    def import_vulnerabilities_tool(report_path: str, repo_root: str = ".") -> dict[str, Any]:
        """Import an OSV Scanner or npm audit vulnerability JSON report into the graph."""
        from .security.vulnerabilities import import_vulnerability_report

        return import_vulnerability_report(Path(repo_root).resolve(), Path(report_path).resolve())
else:
    mcp = None


def main() -> None:
    if mcp is None:
        raise SystemExit("Install cybergraph[mcp] to run the MCP server.")
    mcp.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()

"""Command-line interface for CyberGraph."""

from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .build import build_graph, scan_repo
from .graph import GraphStore
from .rag import answer_question
from .security import find_attack_paths, format_attack_paths, load_scanner_findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybergraph",
        description="Build and query a cybersecurity knowledge graph for a codebase.",
    )
    parser.add_argument("--version", action="version", version=f"cybergraph {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="Build the local security knowledge graph")
    build.add_argument("repo", nargs="?", default=".", help="Repository root to analyze")

    scan = sub.add_parser("scan", help="Run built-in lightweight security analyzers")
    scan.add_argument("repo", nargs="?", default=".", help="Repository root to scan")

    import_report = sub.add_parser("import-report", help="Import findings from Semgrep, SARIF, or Gitleaks JSON")
    import_report.add_argument("report", help="Path to scanner report JSON")
    import_report.add_argument("--repo", default=".", help="Repository root containing the graph")

    ask = sub.add_parser("ask", help="Ask a security question against the graph")
    ask.add_argument("question", help="Security review question")
    ask.add_argument("--repo", default=".", help="Repository root containing the graph")

    paths = sub.add_parser("paths", help="Explain entrypoint-to-sink attack paths")
    paths.add_argument("--repo", default=".", help="Repository root containing the graph")
    paths.add_argument("--max-depth", type=int, default=5, help="Maximum traversal depth")

    review = sub.add_parser("review", help="Review security impact of a change set")
    review.add_argument("--base", default="HEAD~1", help="Git base ref for comparison")
    review.add_argument("--repo", default=".", help="Repository root to review")

    visualize = sub.add_parser("visualize", help="Print graph summary for now")
    visualize.add_argument("repo", nargs="?", default=".", help="Repository root containing the graph")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = Path(getattr(args, "repo", ".")).resolve()

    if args.command == "build":
        counts = build_graph(repo)
        print(f"Built security graph for {repo}")
        print(f"Nodes: {counts['nodes']} | Edges: {counts['edges']} | Findings: {counts['findings']}")
    elif args.command == "scan":
        counts = scan_repo(repo)
        print(f"Scanned {repo}")
        print(f"Nodes: {counts['nodes']} | Edges: {counts['edges']} | Findings: {counts['findings']}")
    elif args.command == "import-report":
        store = GraphStore.open_for_repo(repo)
        findings = load_scanner_findings(Path(args.report).resolve())
        store.add_findings(findings)
        store.close()
        print(f"Imported {len(findings)} finding(s) into {repo / '.cybergraph' / 'graph.db'}")
    elif args.command == "ask":
        print(answer_question(repo, args.question))
    elif args.command == "paths":
        print(format_attack_paths(find_attack_paths(repo, max_depth=args.max_depth)))
    elif args.command == "review":
        print(f"Review security delta from {args.base}: {repo}")
    elif args.command == "visualize":
        store = GraphStore.open_for_repo(repo)
        counts = store.counts()
        store.close()
        print(f"CyberGraph summary for {repo}")
        print(f"Nodes: {counts['nodes']} | Edges: {counts['edges']} | Findings: {counts['findings']}")
    else:
        parser.error(f"Unknown command: {args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())





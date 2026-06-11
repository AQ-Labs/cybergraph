"""Command-line interface for CyberGraph."""

from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .build import build_graph, scan_repo
from .doctor import format_doctor, run_doctor
from .graph import GraphStore
from .init_project import format_init_result, init_project
from .pr_comment import write_pr_comment
from .rag import answer_question, answer_grounded, format_grounded_answer
from .security import (
    find_attack_paths,
    format_attack_paths,
    load_scanner_findings,
)
from .security.review import format_security_review, review_security_delta
from .security.layers import format_layer_summary, summarize_layers
from .security.vulnerabilities import import_vulnerability_report
from .sarif import export_sarif
from .graph_export import export_graph_json
from .visualize import generate_html_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybergraph",
        description="Build and query a cybersecurity knowledge graph for a codebase.",
    )
    parser.add_argument("--version", action="version", version=f"cybergraph {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Create CyberGraph config and GitHub Actions workflow")
    init.add_argument("repo", nargs="?", default=".", help="Repository root to initialize")
    init.add_argument("--force", action="store_true", help="Overwrite existing CyberGraph files")

    doctor = sub.add_parser("doctor", help="Check CyberGraph setup health")
    doctor.add_argument("repo", nargs="?", default=".", help="Repository root to check")

    build = sub.add_parser("build", help="Build the local security knowledge graph")
    build.add_argument("repo", nargs="?", default=".", help="Repository root to analyze")

    scan = sub.add_parser("scan", help="Run built-in lightweight security analyzers")
    scan.add_argument("repo", nargs="?", default=".", help="Repository root to scan")

    import_report = sub.add_parser("import-report", help="Import findings from Semgrep, SARIF, or Gitleaks JSON")
    import_report.add_argument("report", help="Path to scanner report JSON")
    import_report.add_argument("--repo", default=".", help="Repository root containing the graph")

    import_vulns = sub.add_parser("import-vulns", help="Import OSV Scanner or npm audit vulnerability JSON")
    import_vulns.add_argument("report", help="Path to vulnerability report JSON")
    import_vulns.add_argument("--repo", default=".", help="Repository root containing the graph")

    ask = sub.add_parser("ask", help="Ask a security question against the graph")
    ask.add_argument("question", help="Security review question")
    ask.add_argument("--repo", default=".", help="Repository root containing the graph")

    explain = sub.add_parser(
        "explain", help="Answer a security question with cited, confidence-scored graph evidence"
    )
    explain.add_argument("question", help="Security review question")
    explain.add_argument("--repo", default=".", help="Repository root containing the graph")
    explain.add_argument(
        "--llm",
        action="store_true",
        help="Phrase the answer with a configured LLM (CYBERGRAPH_LLM_* env), grounded in evidence",
    )
    explain.add_argument("--limit", type=int, default=8, help="Maximum evidence records to retrieve")

    paths = sub.add_parser("paths", help="Explain entrypoint-to-sink attack paths")
    paths.add_argument("--repo", default=".", help="Repository root containing the graph")
    paths.add_argument("--max-depth", type=int, default=5, help="Maximum traversal depth")

    layers = sub.add_parser("layers", help="Summarize detected security layers")
    layers.add_argument("--repo", default=".", help="Repository root containing the graph")

    review = sub.add_parser("review", help="Review security impact of a change set")
    review.add_argument("--base", default="HEAD~1", help="Git base ref for comparison")
    review.add_argument("--repo", default=".", help="Repository root to review")

    comment = sub.add_parser("pr-comment", help="Generate a markdown PR security review comment")
    comment.add_argument("--base", default="HEAD~1", help="Git base ref for comparison")
    comment.add_argument("--repo", default=".", help="Repository root to review")
    comment.add_argument("--output", default="cybergraph-pr-comment.md", help="Output markdown path")

    sarif = sub.add_parser("sarif", help="Export CyberGraph findings as SARIF")
    sarif.add_argument("--repo", default=".", help="Repository root containing the graph")
    sarif.add_argument("--output", default="cybergraph.sarif", help="Output SARIF path")

    visualize = sub.add_parser("visualize", help="Generate a self-contained HTML security report")
    visualize.add_argument("repo", nargs="?", default=".", help="Repository root containing the graph")
    visualize.add_argument("--output", help="Output HTML path. Defaults to .cybergraph/report.html")

    export_json = sub.add_parser("export-json", help="Export the security graph as Cytoscape JSON")
    export_json.add_argument("repo", nargs="?", default=".", help="Repository root containing the graph")
    export_json.add_argument("--output", help="Output JSON path. Defaults to .cybergraph/graph.json")
    export_json.add_argument("--max-nodes", type=int, default=600, help="Maximum nodes to include")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = Path(getattr(args, "repo", ".")).resolve()

    if args.command == "init":
        print(format_init_result(init_project(repo, force=args.force)))
    elif args.command == "doctor":
        print(format_doctor(run_doctor(repo)))
    elif args.command == "build":
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
    elif args.command == "import-vulns":
        counts = import_vulnerability_report(repo, Path(args.report).resolve())
        print(
            f"Imported {counts['vulnerabilities']} vulnerabilit(y/ies); "
            f"matched {counts['matched_dependencies']} dependency node(s)"
        )
    elif args.command == "ask":
        print(answer_question(repo, args.question))
    elif args.command == "explain":
        client = None
        use_llm = bool(args.llm)
        if use_llm:
            from .llm import build_client, load_llm_config_from_env

            config = load_llm_config_from_env()
            if config is None:
                print("No LLM configured (set CYBERGRAPH_LLM_*); using evidence-only answer.")
                use_llm = False
            else:
                client = build_client(config)
        answer = answer_grounded(
            repo, args.question, client=client, use_llm=use_llm, limit=args.limit
        )
        print(format_grounded_answer(answer))
    elif args.command == "paths":
        print(format_attack_paths(find_attack_paths(repo, max_depth=args.max_depth)))
    elif args.command == "layers":
        print(format_layer_summary(summarize_layers(repo)))
    elif args.command == "review":
        print(format_security_review(review_security_delta(repo, base=args.base)))
    elif args.command == "pr-comment":
        output = write_pr_comment(repo, Path(args.output).resolve(), base=args.base)
        print(f"Wrote PR comment markdown: {output}")
    elif args.command == "sarif":
        output = export_sarif(repo, Path(args.output).resolve())
        print(f"Wrote SARIF report: {output}")
    elif args.command == "visualize":
        output = generate_html_report(repo, Path(args.output).resolve() if args.output else None)
        print(f"Wrote CyberGraph HTML report: {output}")
    elif args.command == "export-json":
        output = Path(args.output).resolve() if args.output else repo / ".cybergraph" / "graph.json"
        export_graph_json(repo, output, max_nodes=args.max_nodes)
        print(f"Wrote CyberGraph graph JSON: {output}")
    else:
        parser.error(f"Unknown command: {args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())





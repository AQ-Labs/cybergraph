"""Command-line interface for CyberGraph."""

from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__


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

    ask = sub.add_parser("ask", help="Ask a security question against the graph")
    ask.add_argument("question", help="Security review question")
    ask.add_argument("--repo", default=".", help="Repository root containing the graph")

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
        print(f"Build security graph: {repo}")
    elif args.command == "scan":
        print(f"Run security analyzers: {repo}")
    elif args.command == "ask":
        print(f"Question: {args.question}")
        print(f"Graph repo: {repo}")
    elif args.command == "review":
        print(f"Review security delta from {args.base}: {repo}")
    elif args.command == "visualize":
        print(f"Visualize graph summary: {repo}")
    else:
        parser.error(f"Unknown command: {args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

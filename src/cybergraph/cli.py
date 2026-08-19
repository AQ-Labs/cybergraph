"""Command-line interface for CyberGraph."""

from __future__ import annotations

import argparse
import json as _json
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

from . import __version__
from .build import build_graph, scan_repo
from .doctor import format_doctor, run_doctor
from .graph import GraphStore
from .graph_export import export_graph_json
from .init_project import format_init_result, init_project
from .pr_comment import write_pr_comment
from .rag import answer_grounded, answer_question, format_grounded_answer
from .sarif import export_sarif
from .security import (
    find_attack_paths,
    format_attack_paths,
    load_scanner_findings,
)
from .security.check import check_change
from .security.layers import format_layer_summary, summarize_layers
from .security.ontology import EDGE_EXPOSES_ENTRYPOINT, EDGE_REACHES_SINK
from .security.policy import POLICY_FILE, extract_baseline
from .security.policy_gate import GATE_BLOCK, gate_for, load_verification_config
from .security.review import format_security_review, review_security_delta
from .security.verdict import STATE_REVIEW, Verdict, format_verdict, verdict_to_dict
from .security.vulnerabilities import import_vulnerability_report
from .visualize import generate_html_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybergraph",
        description="Build and query a cybersecurity knowledge graph for a codebase.",
    )
    parser.add_argument("--version", action="version", version=f"cybergraph {__version__}")

    # Not required: a bare path (or no argument at all) is a valid invocation
    # too -- ``main`` routes those to ``_run_start`` before argparse ever sees
    # them, but this also keeps ``cybergraph`` with only ``--version``/``-h``
    # (no subcommand) from becoming a "command is required" error.
    sub = parser.add_subparsers(dest="command", required=False)

    init = sub.add_parser("init", help="Create CyberGraph config and GitHub Actions workflow")
    init.add_argument("repo", nargs="?", default=".", help="Repository root to initialize")
    init.add_argument("--force", action="store_true", help="Overwrite existing CyberGraph files")

    doctor = sub.add_parser("doctor", help="Check CyberGraph setup health")
    doctor.add_argument("repo", nargs="?", default=".", help="Repository root to check")

    build = sub.add_parser("build", help="Build the local security knowledge graph")
    build.add_argument("repo", nargs="?", default=".", help="Repository root to analyze")

    scan = sub.add_parser("scan", help="Run built-in lightweight security analyzers")
    scan.add_argument("repo", nargs="?", default=".", help="Repository root to scan")

    import_report = sub.add_parser(
        "import-report", help="Import findings from Semgrep, SARIF, or Gitleaks JSON"
    )
    import_report.add_argument("report", help="Path to scanner report JSON")
    import_report.add_argument("--repo", default=".", help="Repository root containing the graph")
    import_report.add_argument(
        "repo_pos", nargs="?", default=None,
        help="Repository root containing the graph (optional positional; alias for --repo)",
    )

    import_vulns = sub.add_parser(
        "import-vulns", help="Import OSV Scanner or npm audit vulnerability JSON"
    )
    import_vulns.add_argument("report", help="Path to vulnerability report JSON")
    import_vulns.add_argument("--repo", default=".", help="Repository root containing the graph")
    import_vulns.add_argument(
        "repo_pos", nargs="?", default=None,
        help="Repository root containing the graph (optional positional; alias for --repo)",
    )

    import_strix = sub.add_parser(
        "import-strix",
        help="Import PoC-validated findings from a Strix AI pentest run into the graph",
    )
    import_strix.add_argument(
        "run", help="Path to a Strix run directory or its vulnerabilities.json"
    )
    import_strix.add_argument("--repo", default=".", help="Repository root containing the graph")
    import_strix.add_argument(
        "repo_pos", nargs="?", default=None,
        help="Repository root containing the graph (optional positional; alias for --repo)",
    )

    enrich_vulns = sub.add_parser(
        "enrich-vulns",
        help="Merge offline advisory intelligence (EPSS/KEV/CVSS/exploit data)"
             " into vulnerabilities",
    )
    enrich_vulns.add_argument("report", help="Path to advisory enrichment JSON")
    enrich_vulns.add_argument("--repo", default=".", help="Repository root containing the graph")
    enrich_vulns.add_argument(
        "repo_pos", nargs="?", default=None,
        help="Repository root containing the graph (optional positional; alias for --repo)",
    )

    ask = sub.add_parser("ask", help="Ask a security question against the graph")
    ask.add_argument("question", help="Security review question")
    ask.add_argument("--repo", default=".", help="Repository root containing the graph")
    ask.add_argument(
        "repo_pos", nargs="?", default=None,
        help="Repository root containing the graph (optional positional; alias for --repo)",
    )

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
    explain.add_argument(
        "--limit", type=int, default=8, help="Maximum evidence records to retrieve"
    )
    explain.add_argument(
        "repo_pos", nargs="?", default=None,
        help="Repository root containing the graph (optional positional; alias for --repo)",
    )

    paths = sub.add_parser("paths", help="Explain entrypoint-to-sink attack paths")
    paths.add_argument("--repo", default=".", help="Repository root containing the graph")
    paths.add_argument("--max-depth", type=int, default=8, help="Maximum traversal depth")
    paths.add_argument(
        "--shallow",
        action="store_true",
        help="Disable interprocedural traversal (intra-function only; for ablation)",
    )
    paths.add_argument(
        "repo_pos", nargs="?", default=None,
        help="Repository root containing the graph (optional positional; alias for --repo)",
    )

    layers = sub.add_parser("layers", help="Summarize detected security layers")
    layers.add_argument("--repo", default=".", help="Repository root containing the graph")
    layers.add_argument(
        "repo_pos", nargs="?", default=None,
        help="Repository root containing the graph (optional positional; alias for --repo)",
    )

    secrets = sub.add_parser(
        "secrets",
        help="Prioritize secret exposure paths to logs, responses, network calls, and processes",
    )
    secrets.add_argument("repo", nargs="?", default=".", help="Repository root to analyze")

    strix_plan = sub.add_parser(
        "strix-plan",
        help="Generate a targeted Strix instruction file from reachable attack paths",
    )
    strix_plan.add_argument("repo", nargs="?", default=".", help="Repository root to analyze")
    strix_plan.add_argument(
        "--output", help="Output Markdown path. Defaults to .cybergraph/strix-plan.md"
    )
    strix_plan.add_argument("--limit", type=int, default=15, help="Maximum paths to include")

    strix_run = sub.add_parser(
        "strix-run",
        help="Run Strix scoped to reachable paths and import validated findings"
             " (needs Docker + strix)",
    )
    strix_run.add_argument("repo", nargs="?", default=".", help="Repository root to analyze")
    strix_run.add_argument(
        "--scan-mode", default="quick", choices=["quick", "standard", "deep"],
        help="Strix scan depth"
    )
    strix_run.add_argument(
        "--limit", type=int, default=15, help="Maximum paths to include in scope"
    )

    review = sub.add_parser("review", help="Review security impact of a change set")
    review.add_argument("--base", default="HEAD~1", help="Git base ref for comparison")
    review.add_argument("--repo", default=".", help="Repository root to review")
    review.add_argument(
        "repo_pos", nargs="?", default=None,
        help="Repository root to review (optional positional; alias for --repo)",
    )

    check = sub.add_parser(
        "check",
        help="Check whether a change preserves the guarantees CyberGraph can verify",
    )
    check.add_argument("repo", nargs="?", default=".", help="Repository root to check")
    check.add_argument("--base", default=None, help="Git ref, or A..B for a commit range")
    check.add_argument(
        "--mode", choices=["worktree", "merge-base", "range", "staged"], default=None,
        help="Comparison mode. Detected from the working tree when omitted"
             " (staged = the git index)",
    )
    check.add_argument(
        "--init-policy", action="store_true",
        help="Write a baseline cybergraph.policy.toml from routes that already require login",
    )
    check.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    check.add_argument(
        "--fail-on-review", action="store_true",
        help="Exit 1 when the verdict is review (for CI gating; off by default)",
    )

    hook = sub.add_parser("hook", help="Install/inspect CyberGraph client hooks")
    hsub = hook.add_subparsers(dest="hook_action", required=True)

    for action, helptext in (
        ("install", "Install a CyberGraph hook"),
        ("uninstall", "Remove a CyberGraph hook"),
    ):
        p = hsub.add_parser(action, help=helptext)
        p.add_argument("target", choices=["claude-code", "pre-commit"])
        p.add_argument("--repo", default=".", help="Repository root")
        if action == "install":
            p.add_argument("--strict", action="store_true",
                           help="A REVIEW blocks (commit / agent turn) instead of warning")
            p.add_argument("--force", action="store_true",
                           help="Back up and replace a foreign pre-commit hook")

    st = hsub.add_parser("status", help="Show which hooks are installed")
    st.add_argument("--repo", default=".", help="Repository root")

    run_p = hsub.add_parser("run", help="(internal) run a hook; invoked by the installed hook")
    run_p.add_argument("target", choices=["claude-code"])
    run_p.add_argument("--strict", action="store_true")
    run_p.add_argument("--repo", default=".")

    comment = sub.add_parser("pr-comment", help="Generate a markdown PR security review comment")
    comment.add_argument("--base", default="HEAD~1", help="Git base ref for comparison")
    comment.add_argument("--repo", default=".", help="Repository root to review")
    comment.add_argument(
        "--output", default="cybergraph-pr-comment.md", help="Output markdown path"
    )
    comment.add_argument(
        "repo_pos", nargs="?", default=None,
        help="Repository root to review (optional positional; alias for --repo)",
    )

    sarif = sub.add_parser("sarif", help="Export CyberGraph findings as SARIF")
    sarif.add_argument("--repo", default=".", help="Repository root containing the graph")
    sarif.add_argument("--output", default="cybergraph.sarif", help="Output SARIF path")
    sarif.add_argument(
        "repo_pos", nargs="?", default=None,
        help="Repository root containing the graph (optional positional; alias for --repo)",
    )

    visualize = sub.add_parser("visualize", help="Generate a self-contained HTML security report")
    visualize.add_argument(
        "repo", nargs="?", default=".", help="Repository root containing the graph"
    )
    visualize.add_argument("--output", help="Output HTML path. Defaults to .cybergraph/report.html")
    visualize.add_argument(
        "--with-source", action="store_true", help="Embed (secret-redacted) source snippets"
    )
    visualize.add_argument(
        "--max-nodes",
        type=int,
        default=600,
        help="Maximum nodes to include in the graph explorer (default: 600)",
    )

    top_risks = sub.add_parser(
        "top-risks", help="Show the highest-priority risks across graph layers"
    )
    top_risks.add_argument(
        "repo", nargs="?", default=".", help="Repository root containing the graph"
    )
    top_risks.add_argument("--limit", type=int, default=10, help="Maximum risks to show")

    investigate = sub.add_parser("investigate", help="Export a Markdown investigation summary")
    investigate.add_argument(
        "repo", nargs="?", default=".", help="Repository root containing the graph"
    )
    investigate.add_argument(
        "--output", help="Output Markdown path. Defaults to .cybergraph/investigation.md"
    )
    investigate.add_argument("--limit", type=int, default=10, help="Maximum risks to include")

    export_json = sub.add_parser("export-json", help="Export the security graph as Cytoscape JSON")
    export_json.add_argument(
        "repo", nargs="?", default=".", help="Repository root containing the graph"
    )
    export_json.add_argument(
        "--output", help="Output JSON path. Defaults to .cybergraph/graph.json"
    )
    export_json.add_argument("--max-nodes", type=int, default=600, help="Maximum nodes to include")

    triage = sub.add_parser(
        "triage", help="Triage findings; with --llm, suppress graph-grounded false positives"
    )
    triage.add_argument("repo", nargs="?", default=".", help="Repository root to triage")
    triage.add_argument(
        "--llm",
        action="store_true",
        help="Use a configured LLM (CYBERGRAPH_LLM_*) to refute false positives,"
             " grounded in graph evidence",
    )

    infer_specs = sub.add_parser(
        "infer-specs",
        help="Infer taint specs; with --llm, propose graph-grounded custom sinks/sources",
    )
    infer_specs.add_argument("repo", nargs="?", default=".", help="Repository root to analyze")
    infer_specs.add_argument(
        "--llm",
        action="store_true",
        help="Use a configured LLM (CYBERGRAPH_LLM_*) to propose specs,"
             " validated against real call sites",
    )

    sca = sub.add_parser(
        "sca", help="Prioritize imported dependency vulnerabilities by severity x reachability"
    )
    sca.add_argument("repo", nargs="?", default=".", help="Repository root to analyze")

    iac_paths = sub.add_parser(
        "iac-paths", help="Trace cloud attack paths (public exposure -> privileged IaC resource)"
    )
    iac_paths.add_argument("repo", nargs="?", default=".", help="Repository root to analyze")
    iac_paths.add_argument(
        "--max-depth", type=int, default=6, help="Maximum reference-traversal depth"
    )

    cloud_code = sub.add_parser(
        "cloud-code", help="Correlate public IaC resources with application code paths"
    )
    cloud_code.add_argument("repo", nargs="?", default=".", help="Repository root to analyze")

    opengraph = sub.add_parser(
        "opengraph", help="Export the graph as BloodHound OpenGraph JSON for attack-path interop"
    )
    opengraph.add_argument(
        "repo", nargs="?", default=".", help="Repository root containing the graph"
    )
    opengraph.add_argument(
        "--output", help="Output JSON path. Defaults to .cybergraph/opengraph.json"
    )
    opengraph.add_argument("--max-nodes", type=int, default=5000, help="Maximum nodes to include")

    analyze = sub.add_parser(
        "analyze", help="Build the graph and run every analysis, then print top risks"
    )
    analyze.add_argument("repo", nargs="?", default=".", help="Repository root to analyze")
    analyze.add_argument("--json", action="store_true", help="Emit the result as JSON")
    analyze.add_argument("--limit", type=int, default=10, help="Maximum top risks to show")
    analyze.add_argument("--no-color", action="store_true", help="Disable coloured output")
    analyze.add_argument("--no-report", action="store_true", help="Skip writing the HTML report")

    config_cmd = sub.add_parser("config", help="Inspect CyberGraph configuration")
    config_sub = config_cmd.add_subparsers(dest="config_action", required=True)
    config_show = config_sub.add_parser("show", help="Show the effective configuration")
    config_show.add_argument("repo", nargs="?", default=".", help="Repository root")

    history = sub.add_parser(
        "history", help="Show recorded scan history and changes since last scan"
    )
    history.add_argument("repo", nargs="?", default=".", help="Repository root")
    history.add_argument("--limit", type=int, default=20, help="Maximum scans to list")

    coverage = sub.add_parser(
        "coverage",
        help="Report which changed files were analyzed and which checks are blind",
    )
    coverage.add_argument("--base", default=None, help="Git base ref for comparison")
    coverage.add_argument(
        "--mode", default=None, choices=["worktree", "merge_base", "range"],
        help="Comparison mode; inferred when omitted",
    )
    coverage.add_argument("--repo", default=".", help="Repository root")

    policy_cmd = sub.add_parser(
        "policy",
        help="Show the declared security policy and which entities it protects",
    )
    policy_cmd.add_argument("--repo", default=".", help="Repository root")
    policy_cmd.add_argument(
        "--baseline", action="store_true",
        help="Print a proposed policy baseline (TOML) to stdout; writes nothing",
    )

    quickstart = sub.add_parser(
        "quickstart", help="Zero-to-report: init, build, analyze, and open the HTML report"
    )
    quickstart.add_argument("repo", nargs="?", default=".", help="Repository root")
    quickstart.add_argument("--yes", action="store_true", help="Run non-interactively")
    quickstart.add_argument(
        "--no-open", action="store_true", help="Do not open the report in a browser"
    )
    quickstart.add_argument(
        "--with-source", action="store_true",
        help="Embed (secret-redacted) source snippets in the report",
    )

    return parser


def _graph_built(repo: Path) -> bool:
    return (repo / ".cybergraph" / "graph.db").is_file()


def _validate_json_report(path: Path) -> str | None:
    """Return a human-readable error if ``path`` is not a readable JSON file.

    Import commands take a scanner/advisory report path; a missing file or
    truncated/invalid JSON is a common user mistake that should produce a clear
    message and a non-zero exit code rather than a raw Python traceback.
    """
    if not path.exists():
        return f"Report file not found: {path}"
    if path.is_dir():
        return f"Expected a JSON file but got a directory: {path}"
    try:
        import json as _json

        _json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        return f"Could not parse JSON report {path}: {exc}"
    except OSError as exc:
        return f"Could not read report {path}: {exc}"
    return None


def _record_history(
    repo: Path, *, top_risk_score: int = 0, top_risk_label: str = "", quiet: bool = False
):
    """Best-effort scan recording; never fails the calling command.

    ``quiet=True`` (used by ``analyze --json``) suppresses the on-error warning so
    it can never corrupt machine-readable stdout."""
    try:
        from .history import record_scan

        return record_scan(repo, top_risk_score=top_risk_score, top_risk_label=top_risk_label)
    except Exception as exc:  # history is a side benefit, not a hard requirement
        if not quiet:
            print(f"(history not recorded: {exc})")
        return None


def _resolve_repo(args: argparse.Namespace) -> Path:
    """Resolve the target repo consistently across commands.

    Preference order: an optional positional ``repo_pos`` (added to commands
    that were previously ``--repo``-only), then ``--repo``/an existing
    positional ``repo`` (both share the ``repo`` dest), then ``"."``.
    """
    repo_pos = getattr(args, "repo_pos", None)
    if repo_pos:
        return Path(repo_pos).resolve()
    repo_flag = getattr(args, "repo", None)
    if repo_flag:
        return Path(repo_flag).resolve()
    return Path(".").resolve()


def _run_check(args) -> int:
    repo = Path(args.repo).resolve()

    if args.init_policy:
        target = repo / POLICY_FILE
        if target.exists():
            print(f"{POLICY_FILE} already exists. Edit it, or delete it to regenerate.")
            return 2
        build_graph(repo)
        target.write_text(extract_baseline(repo), encoding="utf-8")
        print(f"Wrote {POLICY_FILE}. Review every line, then commit it.")
        return 0

    verdict = check_change(repo, base=args.base, mode=args.mode)
    config = load_verification_config(repo)
    verdict = replace(verdict, gate=gate_for(verdict, config))
    print(
        _json.dumps(verdict_to_dict(verdict), indent=2) if args.json
        else format_verdict(verdict)
    )
    # Gate-driven, not state-driven (Law 7): a REVIEW policy chose not to
    # block must exit 0 even with --fail-on-review, and a config can never
    # turn this into a laundered accept -- verdict.state above is untouched.
    return 1 if (args.fail_on_review and verdict.gate == GATE_BLOCK) else 0


def _command_names(parser: argparse.ArgumentParser) -> set[str]:
    """The registered top-level subcommand names (``init``, ``check``, ...).

    Used by ``main`` to tell an existing subcommand apart from a bare path
    *before* handing argv to argparse -- argparse's subparsers action treats
    an unrecognized first token as an error regardless of ``required``.
    """
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    return set()


# Framework labels analyzers stamp directly onto route nodes/edges (JS, C#,
# Java, Django, Terraform) or that a matching dependency name implies.
_FRAMEWORK_LABELS = {
    "fastapi": "FastAPI",
    "flask": "Flask",
    "django": "Django",
    "express": "Express",
    "nextjs": "Next.js",
    "aspnet": "ASP.NET",
    "spring": "Spring",
    "terraform": "Terraform",
}

# Declared dependency names that reveal the framework for languages (Python)
# whose route decorators don't self-report one the way the JS/C#/Java/Django
# analyzers already do on the route node/edge itself.
_FRAMEWORK_DEPENDENCY_NAMES = {
    "fastapi": "fastapi",
    "flask": "flask",
    "django": "django",
    "express": "express",
    "next": "nextjs",
    "spring-boot-starter-web": "spring",
}


# Last-resort signal for languages (Python) whose route decorators don't
# self-report a framework and that declare no dependency manifest CyberGraph
# parses: a literal import keyword in the entrypoint-bearing source file
# itself. Order matters -- checked in this sequence, first match wins.
_FRAMEWORK_IMPORT_HINTS = (
    ("fastapi", "fastapi"),
    ("flask", "flask"),
    ("django", "django"),
)


def _detect_framework(repo: Path, store: GraphStore) -> str | None:
    """Best-effort framework name for the ``cybergraph .`` start summary.

    Reuses the ``framework`` property analyzers already attach to route nodes
    (JS/C#/Java/Django/Terraform) and to FastAPI's ``Depends()`` guard edges,
    then a declared dependency name, then -- because a repo with neither of
    those two signals is common for Python -- a literal import keyword read
    straight from the entrypoint-bearing source files the graph already
    identified. Returns ``None`` only when none of these find anything; the
    caller renders that as ``unknown``, never a false "no framework" claim.
    """
    tags: Counter[str] = Counter()
    for row in store.conn.execute(
        "SELECT properties FROM nodes WHERE kind IN ('Entrypoint', 'Function')"
    ):
        framework = _json.loads(row["properties"] or "{}").get("framework")
        if framework:
            tags[framework] += 1
    for row in store.conn.execute("SELECT properties FROM edges WHERE kind = 'GUARDS'"):
        framework = _json.loads(row["properties"] or "{}").get("framework")
        if framework:
            tags[framework] += 1
    if not tags:
        for row in store.conn.execute("SELECT name FROM nodes WHERE kind = 'Dependency'"):
            mapped = _FRAMEWORK_DEPENDENCY_NAMES.get(row["name"].lower())
            if mapped:
                tags[mapped] += 1
    if not tags:
        tags.update(_framework_hints_from_entrypoint_sources(repo, store))
    if not tags:
        return None
    key = tags.most_common(1)[0][0]
    return _FRAMEWORK_LABELS.get(key, key.capitalize())


def _framework_hints_from_entrypoint_sources(repo: Path, store: GraphStore) -> Counter[str]:
    hits: Counter[str] = Counter()
    rows = store.conn.execute(
        "SELECT DISTINCT source FROM edges WHERE kind = ?", (EDGE_EXPOSES_ENTRYPOINT,)
    ).fetchall()
    for row in rows:
        try:
            text = (repo / row["source"]).read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        for needle, key in _FRAMEWORK_IMPORT_HINTS:
            if needle in text:
                hits[key] += 1
                break
    return hits


def _start_summary(repo: Path) -> str:
    """One line: detected framework, route count, sink count -- all counted
    straight off the graph ``check_change``/the scan just (re)built, never
    invented. ``framework: unknown`` when detection genuinely finds nothing --
    never a false "no framework" claim on a repo that plainly has one."""
    store = GraphStore.open_for_repo(repo)
    try:
        routes = store.conn.execute(
            "SELECT COUNT(*) FROM edges WHERE kind = ?", (EDGE_EXPOSES_ENTRYPOINT,)
        ).fetchone()[0]
        sinks = store.conn.execute(
            "SELECT COUNT(*) FROM edges WHERE kind = ?", (EDGE_REACHES_SINK,)
        ).fetchone()[0]
        framework = _detect_framework(repo, store)
    finally:
        store.close()
    label = f"Framework: {framework}" if framework else "Framework: unknown"
    return f"{label} | {routes} route(s) | {sinks} sink(s)"


def _next_step_suggestion(verdict: Verdict) -> str:
    if verdict.state == STATE_REVIEW:
        return (
            'Next: cybergraph explain "why does this need review?" for cited evidence, '
            "or cybergraph visualize for the full report."
        )
    return (
        "Next: cybergraph visualize for the full report, or "
        'cybergraph explain "<question>" to dig into specific findings.'
    )


def _scan_next_step_suggestion(result) -> str:
    if result.top_risks:
        return (
            'Next: cybergraph explain "<question>" for cited evidence on a specific risk, '
            "or cybergraph visualize for the full report."
        )
    return (
        "Next: cybergraph visualize for the full report. Make a change and re-run "
        "cybergraph . to get a change verdict for just that diff."
    )


def _scan_coverage_note(result) -> str:
    """Named explicitly so a scan can never be mistaken for a change verdict
    (Laws 1 & 5): this ran CyberGraph's analyzers over the code as committed,
    not a diff, and says so instead of implying a clean bill of health."""
    lines = [
        "This is a standing-code scan, not a change verdict -- there was no "
        "pending change to check against, so CyberGraph analyzed the code as "
        "committed instead. The risks above are what its analyzers found; "
        "run `cybergraph check` again after your next change for a "
        "change-scoped verdict.",
    ]
    if result.errors:
        lines.append(
            "Some analyses could not run and are not reflected above: "
            + ", ".join(sorted(result.errors)) + "."
        )
    return "\n".join(lines)


def _has_pending_change(repo: Path) -> bool:
    """Whether there is a change for ``check_change`` to actually verify.

    ``check_change`` compares the worktree/HEAD to a base; on a clean tree
    with nothing to diff against (or no git history at all) that comparison
    is HEAD-against-itself, which prints a bare ACCEPT that reads as "your
    code is secure" even when the *existing* code was never checked. Fail
    toward the honest answer: treat "could not establish a diff" the same as
    "no diff" -- both mean there is nothing to verify a change *against*, so
    ``_run_start`` scans the standing code instead.
    """
    from .security.revisions import resolve_revisions

    return bool(resolve_revisions(repo).changed_files)


def _run_start_change(repo: Path) -> int:
    """A pending change exists: run the same change-verdict `check` runs,
    collapsed to its default view."""
    verdict = check_change(repo)
    config = load_verification_config(repo)
    verdict = replace(verdict, gate=gate_for(verdict, config))
    print(f"Verdict: {verdict.state.upper()}")
    print(format_verdict(verdict))
    print()
    print(_start_summary(repo))
    print()
    print(_next_step_suggestion(verdict))
    return 0


def _run_start_scan(repo: Path) -> int:
    """No pending change to verify: scan the standing code and rank its real
    risks instead of printing a false "nothing changed" ACCEPT (the exact
    false-reassurance the verdict layer exists to forbid)."""
    from .orchestrator import run_full_analysis
    from .output import render_text, should_color

    result = run_full_analysis(repo)
    print("No pending change to verify -- scanned the current code instead:")
    print()
    print(render_text(result, color=should_color()))
    print()
    print(_scan_coverage_note(result))
    print()
    print(_start_summary(repo))
    print()
    print(_scan_next_step_suggestion(result))
    return 0


def _run_start(repo: Path) -> int:
    """``cybergraph .`` / ``cybergraph <path>`` / ``cybergraph`` (cwd): the
    golden-path, no-subcommand entry point.

    Dispatches on whether there is a pending change: a change gets the
    collapsed change-verdict (``check_change``); a clean tree (or no base to
    diff against) gets a standing-code risk scan instead, because a
    HEAD-against-itself "diff" is empty by construction and printing that as
    ACCEPT would claim the existing code was verified when it never was.

    Advisory by default, matching the hook's default: a REVIEW never fails
    this exit code on its own, since there is no ``--fail-on-review`` to opt
    into on a bare invocation.
    """
    if not repo.is_dir():
        print(f"Not a directory: {repo}", file=sys.stderr)
        return 1
    if not _graph_built(repo):
        build_graph(repo)
    if _has_pending_change(repo):
        return _run_start_change(repo)
    return _run_start_scan(repo)


def _run_hook(args) -> int:
    import sys as _sys

    from .hooks import TARGETS, resolve_target

    if args.hook_action == "run":
        from .hooks import claude_code
        return claude_code.run(args.strict, _sys.stdin.read())

    if args.hook_action == "status":
        repo = Path(args.repo).resolve()
        for name, target in TARGETS.items():
            res = target.status(repo)
            print(f"{name:<12} {res.message}")
        return 0

    repo = Path(args.repo).resolve()
    target = resolve_target(args.target)
    if args.hook_action == "install":
        res = target.install(repo, strict=args.strict, force=args.force)
    else:
        res = target.uninstall(repo)
    print(res.message)
    return 0 if res.ok else 1


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    # A bare path (or no argument at all) is not one of the registered
    # subcommands -- route it to `_run_start` before argparse ever sees it,
    # since argparse's subparsers action rejects an unrecognized first token
    # as an error regardless of `required`. An existing subcommand name
    # (`check`, `build`, ...) always still routes to that subcommand.
    first_positional = next((token for token in argv if not token.startswith("-")), None)
    is_bare_path = first_positional is not None and first_positional not in _command_names(parser)
    if not argv or is_bare_path:
        return _run_start(Path(first_positional or ".").resolve())

    args = parser.parse_args(argv)
    repo = _resolve_repo(args)

    # Resolved AFTER the repo argument is known so a repo other than cwd gets
    # its own .env picked up (load_dotenv also checks cwd on top of repo_root).
    from .env import load_dotenv
    load_dotenv(repo)

    read_commands = {"explain", "paths", "layers", "sca", "ask"}
    if args.command in read_commands and not _graph_built(repo):
        print(f"No graph found at {repo / '.cybergraph' / 'graph.db'}. "
              f"Run 'cybergraph build {repo}' first (or 'cybergraph analyze {repo}').")
        return 0

    if args.command == "init":
        print(format_init_result(init_project(repo, force=args.force)))
    elif args.command == "doctor":
        print(format_doctor(run_doctor(repo)))
    elif args.command == "build":
        counts = build_graph(repo)
        print(f"Built security graph for {repo}")
        print(
            f"Nodes: {counts['nodes']} | Edges: {counts['edges']}"
            f" | Findings: {counts['findings']}"
        )
        _record_history(repo)
    elif args.command == "scan":
        counts = scan_repo(repo)
        print(f"Scanned {repo}")
        print(
            f"Nodes: {counts['nodes']} | Edges: {counts['edges']}"
            f" | Findings: {counts['findings']}"
        )
        _record_history(repo)
    elif args.command == "import-report":
        report_path = Path(args.report).resolve()
        error = _validate_json_report(report_path)
        if error:
            parser.exit(2, f"{error}\n")
        store = GraphStore.open_for_repo(repo)
        findings = load_scanner_findings(report_path)
        store.add_findings(findings)
        store.close()
        print(f"Imported {len(findings)} finding(s) into {repo / '.cybergraph' / 'graph.db'}")
    elif args.command == "import-vulns":
        report_path = Path(args.report).resolve()
        error = _validate_json_report(report_path)
        if error:
            parser.exit(2, f"{error}\n")
        counts = import_vulnerability_report(repo, report_path)
        print(
            f"Imported {counts['vulnerabilities']} vulnerabilit(y/ies); "
            f"matched {counts['matched_dependencies']} dependency node(s)"
        )
    elif args.command == "import-strix":
        from .security import load_strix_findings

        store = GraphStore.open_for_repo(repo)
        findings = load_strix_findings(Path(args.run).resolve())
        store.add_findings(findings)
        store.close()
        print(
            f"Imported {len(findings)} PoC-validated Strix finding(s) into "
            f"{repo / '.cybergraph' / 'graph.db'}"
        )
    elif args.command == "enrich-vulns":
        from .security.vulnerabilities import enrich_vulnerabilities

        report_path = Path(args.report).resolve()
        error = _validate_json_report(report_path)
        if error:
            parser.exit(2, f"{error}\n")
        counts = enrich_vulnerabilities(repo, report_path)
        print(
            f"Loaded {counts['advisories']} advisory record(s); "
            f"enriched {counts['matched_vulnerabilities']} vulnerabilit(y/ies)"
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
        print(
            format_attack_paths(
                find_attack_paths(
                    repo, max_depth=args.max_depth, interprocedural=not args.shallow
                )
            )
        )
    elif args.command == "layers":
        print(format_layer_summary(summarize_layers(repo)))
    elif args.command == "secrets":
        from .security.secrets import find_secret_exposures, format_secret_exposures

        build_graph(repo)
        print(format_secret_exposures(find_secret_exposures(repo)))
    elif args.command == "strix-plan":
        from .security.strix_plan import write_strix_instructions

        build_graph(repo)
        output = (
            Path(args.output).resolve() if args.output else repo / ".cybergraph" / "strix-plan.md"
        )
        written = write_strix_instructions(repo, output, limit=args.limit)
        print(f"Wrote Strix instruction file: {written}")
    elif args.command == "strix-run":
        from .security.strix_runner import run_strix

        build_graph(repo)
        result = run_strix(repo, scan_mode=args.scan_mode, limit=args.limit)
        print(result.message)
        return 0 if result.ran else 1
    elif args.command == "review":
        print(format_security_review(review_security_delta(repo, base=args.base)))
    elif args.command == "check":
        return _run_check(args)
    elif args.command == "hook":
        return _run_hook(args)
    elif args.command == "pr-comment":
        output = write_pr_comment(repo, Path(args.output).resolve(), base=args.base)
        print(f"Wrote PR comment markdown: {output}")
    elif args.command == "sarif":
        output = export_sarif(repo, Path(args.output).resolve())
        print(f"Wrote SARIF report: {output}")
    elif args.command == "visualize":
        output = generate_html_report(
            repo,
            Path(args.output).resolve() if args.output else None,
            with_source=args.with_source,
            max_nodes=args.max_nodes,
        )
        print(f"Wrote CyberGraph HTML report: {output}")
    elif args.command == "top-risks":
        from .security.investigate import collect_top_risks, format_top_risks

        build_graph(repo)
        print(format_top_risks(collect_top_risks(repo, limit=args.limit)))
    elif args.command == "investigate":
        from .security.investigate import export_investigation_markdown

        build_graph(repo)
        output = (
            Path(args.output).resolve()
            if args.output
            else repo / ".cybergraph" / "investigation.md"
        )
        print(
            "Wrote CyberGraph investigation: "
            f"{export_investigation_markdown(repo, output, limit=args.limit)}"
        )
    elif args.command == "export-json":
        output = Path(args.output).resolve() if args.output else repo / ".cybergraph" / "graph.json"
        export_graph_json(repo, output, max_nodes=args.max_nodes)
        print(f"Wrote CyberGraph graph JSON: {output}")
    elif args.command == "triage":
        from .security.triage import format_triage, load_findings, triage_findings

        build_graph(repo)
        findings = load_findings(repo)
        client = None
        if args.llm:
            from .llm import build_client, load_llm_config_from_env

            config = load_llm_config_from_env()
            if config is None:
                print("No LLM configured (set CYBERGRAPH_LLM_*); keeping all findings (no triage).")
            else:
                client = build_client(config)
        print(format_triage(triage_findings(repo, findings=findings, client=client)))
    elif args.command == "infer-specs":
        from .security.spec_inference import format_specs, propose_specs

        build_graph(repo)
        client = None
        if args.llm:
            from .llm import build_client, load_llm_config_from_env

            config = load_llm_config_from_env()
            if config is None:
                print("No LLM configured (set CYBERGRAPH_LLM_*); no specs inferred.")
            else:
                client = build_client(config)
        print(format_specs(propose_specs(repo, client=client)))
    elif args.command == "sca":
        from .security.sca import format_sca, prioritize_vulnerabilities

        # Read the existing graph (do NOT rebuild — that would clear the
        # vulnerabilities imported via 'import-vulns'). Flow: build -> import-vulns -> sca.
        print(format_sca(prioritize_vulnerabilities(repo)))
    elif args.command == "iac-paths":
        from .security.iac_paths import find_iac_attack_paths, format_iac_attack_paths

        build_graph(repo)
        print(format_iac_attack_paths(find_iac_attack_paths(repo, max_depth=args.max_depth)))
    elif args.command == "cloud-code":
        from .security.cloud import find_cloud_code_paths, format_cloud_code_paths

        build_graph(repo)
        print(format_cloud_code_paths(find_cloud_code_paths(repo)))
    elif args.command == "opengraph":
        from .opengraph_export import export_opengraph

        build_graph(repo)
        output = (
            Path(args.output).resolve() if args.output else repo / ".cybergraph" / "opengraph.json"
        )
        export_opengraph(repo, output, max_nodes=args.max_nodes)
        print(f"Wrote BloodHound OpenGraph JSON: {output}")
    elif args.command == "analyze":
        import json as _json

        from .orchestrator import run_full_analysis
        from .output import render_text, should_color
        from .report_model import to_json

        result = run_full_analysis(repo, limit=args.limit)
        if args.json:
            print(_json.dumps(to_json(result), indent=2, sort_keys=True))
        else:
            color = (not args.no_color) and should_color()
            print(render_text(result, color=color))
            if not args.no_report:
                output = generate_html_report(repo, repo / ".cybergraph" / "report.html")
                print(f"\nHTML report: {output}")
        top = result.top_risks[0] if result.top_risks else None
        hist = _record_history(
            repo,
            top_risk_score=(top.risk_score if top else 0),
            top_risk_label=(top.risk_label if top else ""),
            quiet=args.json,
        )
        if not args.json and hist is not None and not hist.is_first:
            # ASCII only: a non-cp1252 char here crashes real Windows consoles.
            line = (f"Changes since last scan: +{len(hist.new)} new, "
                    f"-{len(hist.fixed)} fixed, {len(hist.regressed)} regressed")
            if hist.hidden_by_config:
                # Configuration, not a code change; none of it is a fix.
                line += (f", {len(hist.hidden_by_config)} hidden by config "
                         "(hidden, not fixed)")
            print(line)
    elif args.command == "config":
        from .config import load_config
        from .llm import load_llm_config_from_env

        cfg = load_config(repo)
        print(f"Repo: {repo}")
        print(f"LLM configured: {'yes' if load_llm_config_from_env() is not None else 'no'}")
        print(f"Graph built: {'yes' if _graph_built(repo) else 'no'}")
        print(f"Ignored paths: {list(cfg.ignored_paths)}")
        print(f"Custom sinks: {list(cfg.custom_sinks)}")
        print(f"Suppressed rules: {list(cfg.suppressed_rules)}")
        print(f"Suppressed paths: {list(cfg.suppressed_paths)}")
    elif args.command == "history":
        from .history import format_history, list_scans, scan_delta

        rows = list_scans(repo, limit=args.limit)
        print(format_history(rows, scan_delta(repo)))
    elif args.command == "coverage":
        from .security.coverage_report import build_coverage_report, format_coverage_report

        report = build_coverage_report(
            Path(args.repo).resolve(), base=args.base, mode=args.mode
        )
        print(format_coverage_report(report))
        if not report.established:
            return 1
    elif args.command == "policy":
        from .security.policy import evaluate_policy, extract_baseline, load_policy
        from .security.policy_report import format_policy_report

        repo = Path(args.repo).resolve()
        if not repo.is_dir():
            print(f"Not a directory: {repo}", file=sys.stderr)
            return 1
        build_graph(repo)
        if args.baseline:
            print(extract_baseline(repo))
            return 0
        policy = load_policy(repo)
        protected = evaluate_policy(repo, policy)
        print(format_policy_report(policy, protected))
        return 0
    elif args.command == "quickstart":
        import os
        import webbrowser

        from .quickstart import run_quickstart

        result = run_quickstart(repo, with_source=args.with_source)
        for step in result.steps:
            print(step)
        can_open = (not args.no_open) and sys.stdout.isatty() and not os.environ.get("CI")
        if can_open:
            try:
                webbrowser.open(result.report_path.as_uri())
            except Exception:
                pass
        print(f"\nOpen the report: {result.report_path}")
    elif args.command is None:
        # Defense in depth: `main`'s own argv pre-check routes every bare-path
        # or no-argument invocation to `_run_start` before argparse runs, so
        # this only fires if some other caller hands `build_parser()` an argv
        # that still leaves `command` unset.
        return _run_start(repo)
    else:
        parser.error(f"Unknown command: {args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())





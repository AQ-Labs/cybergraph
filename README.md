# CyberGraph

Security review for codebases, powered by knowledge graphs.

CyberGraph maps a repository into a cybersecurity knowledge graph so developers can inspect security layers, risky code paths, scanner findings, and evidence-backed answers without reading the whole codebase by hand.

## Why this exists

Security scanners are useful, but their output is usually flat: a file, a line, a rule, and a warning. Developers still have to answer the hard questions:

- Is this issue reachable from production code?
- Is there authentication before this sensitive action?
- Did this pull request affect a security boundary?
- Which scanner findings matter first?

CyberGraph is designed to connect those dots.

## Current capabilities

- Builds a local SQLite graph in `.cybergraph/graph.db`.
- Extracts Python files, functions, calls, route-like entrypoints, and sensitive sink calls.
- Extracts JavaScript/TypeScript Express and Next.js-style entrypoints and common sinks.
- Maps dependency manifests from `package.json`, `requirements.txt`, and `pyproject.toml`.
- Imports OSV Scanner and npm audit vulnerability reports into dependency graph nodes.
- Stores built-in findings with file and line evidence.
- Imports Semgrep JSON, SARIF, and Gitleaks JSON reports.
- Answers basic security questions from graph evidence.
- Exposes optional MCP tools for AI coding assistants.

## Quick start

```bash
python -m pip install -e ".[dev]"
cybergraph init .
cybergraph doctor .
cybergraph build path/to/repo
cybergraph ask "Which functions reach SQL execution?" --repo path/to/repo
cybergraph paths --repo path/to/repo
cybergraph layers --repo path/to/repo
cybergraph review --base main --repo path/to/repo
cybergraph pr-comment --base main --repo path/to/repo --output cybergraph-pr-comment.md
cybergraph visualize path/to/repo
cybergraph sarif --repo path/to/repo --output cybergraph.sarif
```

Import scanner results:

```bash
cybergraph import-report semgrep.json --repo path/to/repo
cybergraph import-vulns osv-results.json --repo path/to/repo
cybergraph ask "Which high severity findings involve secrets?" --repo path/to/repo
```

## Example questions

```text
Which endpoints can reach SQL execution?
What changed in this PR that affects authentication?
Where are secrets loaded and passed into network clients?
Which vulnerable dependency is reachable from production code?
Are there route handlers that reach shell or file writes?
```

## Try the demo

```bash
cybergraph build examples/vulnerable-fastapi
cybergraph ask "Which routes reach SQL execution?" --repo examples/vulnerable-fastapi
cybergraph visualize examples/vulnerable-fastapi --output cybergraph-report.html
```

## MCP tools

Install with the optional MCP extra and run the server:

```bash
python -m pip install -e ".[mcp]"
cybergraph-mcp
```

Initial tools:

- `build_security_graph_tool`
- `query_security_graph_tool`
- `explain_attack_path_tool`

## Project direction

CyberGraph is intentionally security-first. It is not trying to be a general code graph with security keywords sprinkled on top. The goal is to model controls, attack paths, trust boundaries, scanner findings, and code evidence as one graph.

See:

- [Architecture](docs/architecture.md)
- [Getting started](docs/getting-started.md)
- [Security ontology](docs/security-ontology.md)
- [Product plan](docs/product-plan.md)
- [GitHub Action](docs/github-action.md)

## Status

Private bootstrap. The first version is small on purpose: it establishes the package, graph store, Python analyzer, scanner import path, evidence retrieval, and MCP surface.

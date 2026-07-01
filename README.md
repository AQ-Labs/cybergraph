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
- Analyzes **five languages**: Python (FastAPI/Flask/Django), JavaScript/TypeScript (Express/Next.js), Go (net/http, Gin, Echo), Java (Spring), and C# (ASP.NET Core) — through a shared analyzer contract with graceful fallback for the rest.
- Extracts functions, calls, route entrypoints, auth/authz guards, validators, user-input/data-flow edges, secret access/exposure, cloud resources, and sensitive sink calls.
- **Cross-file, interprocedural attack paths** (route → service → repository → sink) with confidence, sanitizer-barrier flags, taint/data-reachability, risk scores, and fix guidance; a `--shallow` mode reproduces intra-function traversal for comparison.
- **Interactive, offline graph explorer** in the HTML report: top risks, security-typed styling, search, layer/severity filters, a details panel, and entrypoint→sink path highlighting (Cytoscape.js, fully inlined).
- **Evidence-grounded answers** (`cybergraph explain`) with file/line/rule/path citations, attack-path narratives, remediation guidance, and a high/medium/low/insufficient confidence level — never claims a vulnerability without supporting evidence, and works with no LLM.
- Optional, **local-only by default** LLM phrasing via configurable providers (Anthropic Claude, OpenAI, Kimi 2.6) constrained to retrieved evidence.
- Maps dependency manifests and lockfiles across npm, Python, Go, Maven/Gradle, and .NET ecosystems.
- Imports OSV Scanner, npm audit, Semgrep JSON, SARIF, and Gitleaks reports into the same graph; enriches vulnerabilities from offline EPSS/KEV/CVSS/advisory JSON; exports findings as SARIF.
- Correlates Terraform resources to application code references so public cloud exposure can be connected to reachable routes, sinks, and dependency risk.
- Exposes MCP tools for AI coding assistants.

## Install

```bash
# From PyPI (once published):
pipx install cybergraph                 # isolated CLI install
python -m pip install cybergraph        # or into the current environment

# Optional extras:
python -m pip install "cybergraph[mcp]" # MCP server for AI assistants
python -m pip install "cybergraph[llm]" # Anthropic / OpenAI / Kimi providers
python -m pip install "cybergraph[all]" # everything optional

# From a clone (development):
python -m pip install -e ".[dev]"
```

Supported Python: 3.10, 3.11, 3.12.

## Quick start

```bash
cybergraph init .
cybergraph doctor .
cybergraph build path/to/repo
cybergraph ask "Which functions reach SQL execution?" --repo path/to/repo
cybergraph explain "Which routes reach SQL execution?" --repo path/to/repo
cybergraph paths --repo path/to/repo
cybergraph layers --repo path/to/repo
cybergraph secrets path/to/repo
cybergraph cloud-code path/to/repo
cybergraph top-risks path/to/repo
cybergraph investigate path/to/repo --output investigation.md
cybergraph export-json path/to/repo --output graph.json
cybergraph review --base main --repo path/to/repo
cybergraph pr-comment --base main --repo path/to/repo --output cybergraph-pr-comment.md
cybergraph visualize path/to/repo
cybergraph sarif --repo path/to/repo --output cybergraph.sarif
```

Typical build output:

```text
Built graph for examples/vulnerable-fastapi
nodes: 18
edges: 24
findings: 3
```

Typical PR comment sections:

```text
Risk: medium
What Changed: CyberGraph detected 2 entrypoints, 1 sensitive sink edge, 1 finding in changed files.
What To Check Next: Confirm changed entrypoints require authentication or authorization when needed.
```

Import scanner results:

```bash
cybergraph import-report semgrep.json --repo path/to/repo
cybergraph import-vulns osv-results.json --repo path/to/repo
cybergraph enrich-vulns advisory-intel.json --repo path/to/repo
cybergraph ask "Which high severity findings involve secrets?" --repo path/to/repo
```

Suppress accepted findings:

```python
def test_fixture():
    # cybergraph: ignore CG-SINK-CALL accepted test-only query
    return db.execute("select 1")
```

Or configure repository-level suppressions:

```toml
[suppressions]
rules = ["CG-SINK-CALL"]
paths = ["legacy/**"]
```

Suppressions hide findings, but the graph still keeps edges such as `REACHES_SINK` so reviewers can inspect the real code path.

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
- `grounded_security_answer_tool` (cited, confidence-scored, local-only)

## Project direction

CyberGraph is intentionally security-first. It is not trying to be a general code graph with security keywords sprinkled on top. The goal is to model controls, attack paths, trust boundaries, scanner findings, and code evidence as one graph.

See:

- [Architecture](docs/architecture.md)
- [Getting started](docs/getting-started.md)
- [Five-minute tutorial](docs/tutorial.md)
- [Security ontology](docs/security-ontology.md)
- [Product plan](docs/product-plan.md)
- [GitHub Action](docs/github-action.md)

## Status

Private bootstrap. The first version is small on purpose: it establishes the package, graph store, Python analyzer, scanner import path, evidence retrieval, and MCP surface.

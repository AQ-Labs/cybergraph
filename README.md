# CyberGraph

Security review for codebases, powered by knowledge graphs.

CyberGraph maps a repository into a cybersecurity knowledge graph so developers can inspect security layers, risky code paths, scanner findings, and evidence-backed answers without reading the whole codebase by hand.

> **🔒 No API keys. Fully offline. Your code never leaves your machine.**
> `pip install cybergraph` and you get the complete toolkit — the interactive HTML report, attack-path graphs, cited findings, and SARIF export — with **zero API keys, zero signup, and zero network calls**. There are no runtime dependencies. An LLM is entirely optional and only rephrases answers the graph has already grounded in evidence; nothing about the analysis requires one.

## See it in action

CyberGraph turns a codebase into an interactive security map. Below it is analyzing [OWASP PyGoat](https://github.com/adeyosemanputra/pygoat), a deliberately vulnerable app — **826 nodes, 25 attack paths, no API key**. Everything renders in one self-contained, offline HTML file.

**Security zones — your app as an attack narrative.** Entrypoints flow left-to-right through guards and application logic into sensitive sinks, secrets, and dependencies:

![CyberGraph security-zones view of OWASP PyGoat](docs/assets/report-zones.png)

**Guided report — posture grade, top risks, and stats at a glance.** Real reachable vulnerabilities (`eval`, `pickle.loads`, `sql_lab_table.objects.raw`, `subprocess.Popen`) rank at the top, each with an evidence-backed score:

![CyberGraph report overview with security posture grade and top risks](docs/assets/report-overview.png)

**Attack-path explorer — trace user input to a dangerous sink.** The report opens on the highest-risk path, glowing from route entrypoint to sink:

![CyberGraph attack-path explorer highlighting a route-to-sink path](docs/assets/report-attack-paths.png)

Generate this for any repo with `cybergraph visualize path/to/repo` (dark theme shown; a light theme and toggle are built in).

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
- **Interactive, offline HTML report** built for first-time readers: a dark-mode-first neon graph explorer (glowing, security-typed nodes with a light/dark toggle), NODE/EDGE/ZONE explainer cards, a guided first view that opens on the top attack path with a plain-language narrative, a security-zones view (Attack Surface → Guards → Logic → Sensitive Sinks), search, layer/severity filters, a details panel with source drill-down, and entrypoint→sink path highlighting (Cytoscape.js, fully inlined).
- **Exec-first report posture**: an A–F security grade with a one-line verdict and severity-distribution bar, a since-last-scan delta strip (new/regressed/fixed), findings grouped into expandable rule cards, an honest findings-cap footer, and a print stylesheet for clean PDF export.
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

Supported Python: 3.10, 3.11, 3.12, 3.13.

## Quick start

```bash
cybergraph quickstart .        # zero-to-report: init, build, analyze, open report
cybergraph init .
cybergraph doctor .
cybergraph analyze .          # build + run every analysis, print top risks
cybergraph history .          # what's new / fixed / regressed since the last scan
cybergraph config show .      # inspect effective config + LLM/graph state
cybergraph build path/to/repo
cybergraph ask "Which functions reach SQL execution?" --repo path/to/repo
cybergraph explain "Which routes reach SQL execution?" --repo path/to/repo
cybergraph paths --repo path/to/repo
cybergraph layers --repo path/to/repo
cybergraph secrets path/to/repo
cybergraph cloud-code path/to/repo
cybergraph top-risks path/to/repo
cybergraph scan path/to/repo               # lightweight built-in analyzers, no graph needed
cybergraph triage path/to/repo             # rank findings; --llm suppresses false positives
cybergraph sca path/to/repo                # prioritize dependency CVEs by reachability
cybergraph infer-specs path/to/repo        # propose custom taint sinks/sources
cybergraph iac-paths path/to/repo          # public exposure -> privileged IaC resource
cybergraph investigate path/to/repo --output investigation.md
cybergraph strix-plan path/to/repo --output strix-plan.md
cybergraph import-strix strix_runs/<run> --repo path/to/repo
cybergraph export-json path/to/repo --output graph.json
cybergraph opengraph path/to/repo --output opengraph.json   # BloodHound OpenGraph interop
cybergraph review --base main --repo path/to/repo
cybergraph pr-comment --base main --repo path/to/repo --output cybergraph-pr-comment.md
cybergraph visualize path/to/repo
cybergraph sarif --repo path/to/repo --output cybergraph.sarif
```

Typical build output:

```text
Built security graph for examples/vulnerable-fastapi
Nodes: 15 | Edges: 28 | Findings: 1
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

Validate reachable risk with an AI pentester ([Strix](https://github.com/usestrix/strix)):

```bash
# 1. Turn CyberGraph's reachable paths into a focused Strix scope brief
cybergraph strix-plan path/to/repo --output strix-plan.md

# 2. Run Strix yourself against that brief (needs Docker + an LLM key):
#      strix -n -t path/to/repo -m quick --instruction-file strix-plan.md
#    ...or let CyberGraph orchestrate it end-to-end (optional, opt-in):
cybergraph strix-run path/to/repo --scan-mode quick

# 3. Import Strix's PoC-validated findings back into the graph
cybergraph import-strix strix_runs/<run-name> --repo path/to/repo
cybergraph top-risks path/to/repo   # validated findings rank at the top
```

CyberGraph tells Strix *where* to attack (reachable routes and sinks), and Strix
tells CyberGraph *what is actually exploitable* (validated with a working PoC).
Strix is never a dependency — the `strix-run` bridge only activates when the
`strix` binary and Docker are both present, so the offline-by-default workflow is
unchanged.

Suppress accepted findings:

```python
def test_fixture(name):
    # cybergraph: ignore CG-SQL-EXEC accepted test-only query
    return db.execute("select * from users where name = '" + name + "'")
```

Or configure repository-level suppressions:

```toml
[suppressions]
rules = ["CG-SQL-EXEC"]
paths = ["legacy/**"]
```

Naming a rule also covers the `-UNVERIFIED` variant CyberGraph reports when it can see a value reach a sink but cannot confirm how the value was built — accepting `CG-SQL-EXEC` accepts `CG-SQL-EXEC-UNVERIFIED` on the same line or in the same repository. The reverse is deliberately not true: naming `CG-SQL-EXEC-UNVERIFIED` accepts only the unconfirmed case, and a confirmed `CG-SQL-EXEC` is still reported.

Suppressions hide findings, but the graph still keeps edges such as `REACHES_SINK` so reviewers can inspect the real code path.

**New:** `paths` now also hides matching entrypoint-to-sink *attack paths* from the ranked, actionable surfaces — `cybergraph attack-paths`, top risks, `analyze`, the PR review, the cloud and Strix scopes. Attack paths were previously never suppressed anywhere, so this is a change in what those commands print. A path is hidden only when **every** file it touches is suppressed, so a route crossing from suppressed code into live code is still reported. The exploration and evidence surfaces still show suppressed paths — the JSON graph export (which records the policy under its `suppression` key), the HTML report, the MCP `explain_attack_path_tool`, grounded answers, and LLM triage slices — and a suppressed path never consumes a slot a real one needs on any of them. Each surface caps how many paths it traverses; suppressed paths are collected separately and fill only what the real ones leave, so accepted fixture noise cannot push the genuine attack paths off the end of the report, the exported graph or the evidence an LLM is grounded on. A PR review scans both sides of the diff under the *current* configuration — `[suppressions] paths`, `[ignore] paths` and `[security] sinks` alike — so changing any of them can never appear as an added or removed attack path. It is reported as a configuration change instead, alongside a count of the reachable risks the suppressions hide (hidden, not fixed) and the changed files `[ignore] paths` kept out of the analysis entirely (not analysed, not fixed). A PR that genuinely removes a vulnerable line is still reported as `removed`, and one that genuinely introduces a sink is still reported as `added`. Scan history holds the same line: a finding that disappears because `[suppressions] rules`, `[suppressions] paths` or `[ignore] paths` now covers it is counted as *hidden by config (hidden, not fixed)* rather than as fixed, on `cybergraph history`, on the `analyze` delta line and in the HTML report's delta strip. Its history row stays open, so dropping the suppression later reads as persisting rather than as a regression. A finding that disappears because the code changed is still fixed.

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

Available tools:

- `build_security_graph_tool`
- `query_security_graph_tool`
- `explain_attack_path_tool`
- `grounded_security_answer_tool` (cited, confidence-scored, local-only)
- `analyze_repo_tool` (build + full analysis in one call)
- `top_risks_tool`
- `secret_exposures_tool`
- `prioritize_dependencies_tool` (reachability-ranked SCA)
- `iac_attack_paths_tool`
- `import_scanner_report_tool`
- `import_vulnerabilities_tool`

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

Beta. CyberGraph analyzes five languages, builds interprocedural attack paths, imports and enriches scanner findings, correlates IaC to code, ships an interactive HTML report, and exposes an MCP surface for AI assistants. The graph store, analyzers, evidence retrieval, and report are stable; the public API and finding rules may still change before 1.0.

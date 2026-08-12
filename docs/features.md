# CyberGraph — Features & Capabilities

A detailed reference to what CyberGraph is, what it does, and how each piece works. For the
short pitch see the [README](../README.md); for architecture internals see
[architecture.md](architecture.md).

---

## 1. What CyberGraph is

CyberGraph is an **offline security verifier and monitor for code changes**, run *independently*
of the model that wrote the code. Its headline job: given a change to a repository, check it
against the security guarantees CyberGraph can verify and return a single verdict — **ACCEPT**
(the supported checks ran and found nothing) or **REVIEW** (something changed, or a relevant
check could not be verified) — with cited evidence and an explicit list of what could not be
checked. ACCEPT is not a certification that the change is secure; it is the narrower, honest
claim that the guarantees CyberGraph understands were preserved.

It does this **deterministically and entirely offline**: no API keys, no signup, no network
calls, no runtime dependencies, and — critically — **no LLM tokens**. A large language model is
optional and only ever rephrases answers the graph has already grounded in evidence; nothing
about the analysis or the verdict requires one.

Underneath, CyberGraph parses a repository into a **cybersecurity knowledge graph** — functions,
routes, guards, sinks, secrets, cloud resources, and the edges between them (calls, user-input
flow, reaches-sink, uses/exposes-secret). That graph is the engine that makes the verdicts
precise. It is not the pitch; the verdict is.

### Zero-token verification, independent of the coding model

AI coding agents now write a large and growing share of code, and each change can introduce a
vulnerability. The common way to guard that — having the same class of model that wrote the code
also review it — is nondeterministic, spends tokens on every turn, and gets slower and costlier
as the codebase and change rate grow. CyberGraph moves that verification **off the token meter**:

- **No per-check LLM or API cost.** The security decision is a deterministic graph-and-rules
  check, so verifying a change consumes no tokens — you can run it on every commit and every
  agent turn without a per-check cost to weigh. (Wall-clock varies with repo size and which
  analyses run — a graph rebuild, SCA, or history pass is not instantaneous — but none of it
  bills against a model.)
- **An independent reviewer.** The verdict does not come from the model under review, so it is
  not vulnerable to the same blind spot that produced the code.
- **It keeps the LLM on the work only an LLM can do.** When a model *is* in the loop (optional
  phrasing/triage), CyberGraph narrows it to grounded evidence, so you are not paying a model to
  re-derive what the graph already knows.

The claim here is a *property* — zero-token, deterministic verification — not a measured savings
figure; any "X% fewer tokens" number would need an end-to-end benchmark, which is future work.

---

## 2. The verdict engine

### ACCEPT / REVIEW, and the honesty gate

`cybergraph check` compares the current state of a repo against a base ref
(`--mode merge-base|worktree|range`) and reports:

- **`accept`** — every capability that was in scope ran and found nothing.
- **`review`** — a check failed, or a relevant capability could not run (a blind spot), or a
  change touched a declared security boundary.
- **`not_evaluated`** — an explicit list of what CyberGraph could *not* check on this change.

It never turns "did not look" into a pass. A capability passes only when there is **positive
evidence** it was analyzed. This is the product's core credibility claim: for a verification
tool, a false ACCEPT is worse than a false positive.

### The five capability states

Every capability reports one of five states — the distinctions between the last three carry the
product's credibility:

| State | Meaning |
|---|---|
| `PASS` | the check ran on this change and found nothing |
| `FAIL` | the check ran and found something |
| `NOT_APPLICABLE` | supported, but nothing in this change is in its scope |
| `UNKNOWN` | supported, but it could not run here (a blind spot) |
| `NOT_SUPPORTED` | the capability does not exist yet for this language/surface |

`NOT_APPLICABLE` and `NOT_SUPPORTED` look alike and are not: a README-only change is
NOT_APPLICABLE everywhere and can honestly ACCEPT, while a change to a language with no analyzer
is NOT_SUPPORTED and forces REVIEW — accepting there would be false assurance. Coverage is
*declared*, never inferred: each capability states the file globs it claims, so the tool cannot
silently imply coverage it does not have.

### The cardinal rule: only literals are SAFE

The injection verdicts (SQL, command, path, code-execution, deserialization) are decided by a
per-language **construction classifier** working with intra-function **taint**:

- A sink argument that is a **provably all-literal / constant** construction reads **SAFE**.
- A construction containing a **variable** reads **UNSAFE** when taint confirms the variable is
  attacker-influenced, and **UNKNOWN** otherwise.
- Native **deserialization** is never provably SAFE from construction alone.
- Anything the classifier cannot read (an unbalanced string, an opaque call, an unmodelled
  construct) is **UNKNOWN**, never SAFE.

**Uncertainty never becomes safety.** When the tool is unsure it emits a `-UNVERIFIED` finding
(which drives REVIEW) rather than a false ACCEPT. The classifier is a positive-literal-proof: it
must *prove* the whole argument is literal to say SAFE; absent that proof, the value is treated
as non-literal.

This precision is why a verdict is trustworthy enough to gate on. It is computed from
construction provenance — `"SELECT ... " + userId` is UNSAFE, `String.format`/interpolation with
a variable hole is UNSAFE, an all-literal `"SELECT 1"` is SAFE — not from a keyword match.

---

## 3. Languages & coverage

CyberGraph analyzes **five languages** through a shared analyzer contract, with graceful
fallback for the rest.

| Language | Frameworks understood | Injection verdicts | Validation |
|---|---|---|---|
| Python | FastAPI, Flask, Django | SQL · command · path · code-exec · deserialization · template | **Labelled precision/recall/abstention benchmark ✓** |
| JavaScript / TypeScript | Express, Next.js | SQL · command · code-exec · path | Beta |
| Go | net/http, Gin, Echo | SQL · command · path (no code-exec sink in Go) | Beta |
| Java | Spring, JDBC | SQL · command · path · deserialization | Beta |
| C# | ASP.NET Core, ADO.NET | SQL · command · path · deserialization · code-execution (incl. string interpolation) | Beta |

Assurance is **not** uniform across the five. Python carries the strongest validated coverage —
it is the only language held to a labelled precision/recall/abstention benchmark
(`benchmark/run_precision.py`) that gates every change. The other four grade sink arguments in
the same shape (below) and are **Beta** until each earns its own labelled benchmark; the docs and
UI say so rather than implying identical assurance.

**Verdict-grade vs inventory-grade.** A verdict-grade class grades the sink argument
SAFE/UNSAFE/UNKNOWN. Any language or sink class not yet upgraded is **inventory-grade**: a
`*-SINK-CALL` row that marks "a sensitive sink is used here" — a map of where sensitive calls
live, not a confirmed verdict. CI's SARIF export filters inventory rules out of code-scanning
uploads (so they don't manufacture alert fatigue); graded verdict rules are never filtered.

**The honesty invariant.** Verdict-grade detection is a structural, line-based classifier — not
a full parse tree. So each non-Python language stays `NOT_SUPPORTED` for the
`source_analysis_support` capability (whole-file "CyberGraph can fully read this language")
even while its injection capabilities are graded. `VERIFIED_GLOBS` (the set that claims full
source analysis) remains Python-only by design. An unreadable or unparseable file always reads
UNKNOWN/FAILED, never PASS.

---

## 4. Automatic verification — hooks

`cybergraph check` verifies a change, but something has to invoke it. Hooks make it fire on its
own at the moment code is accepted:

```bash
cybergraph hook install claude-code    # runs when an AI agent turn ends (Stop hook)
cybergraph hook install pre-commit      # runs before each commit (the staged index)
cybergraph hook status                  # what's installed
cybergraph hook uninstall pre-commit
```

- **Advisory by default:** a REVIEW is *surfaced, not blocking* — the commit proceeds, the agent
  continues, and the verdict is reported.
- **`--strict` opts into blocking:** a REVIEW becomes a non-zero pre-commit exit, or a Claude
  Code stop-block the agent must resolve before finishing.
- Installing over an existing pre-commit hook is refused unless you pass `--force` (which backs
  up the old hook first).

The hook is what closes the loop for AI-generated code: the verdict runs on **every** agent turn
or commit regardless of whether the agent chooses to check itself.

---

## 5. The knowledge graph

CyberGraph builds a local SQLite graph in `.cybergraph/graph.db` typed with security semantics.

- **Nodes:** functions, routes/entrypoints, auth/authz guards, validators, sensitive sinks,
  secrets, cloud resources, dependencies.
- **Edges:** `CALLS` → `CALLS_RESOLVED` (cross-file, confidence-tagged), user-input/data-flow,
  `REACHES_SINK`, `USES_SECRET` → `EXPOSES_SECRET`, and IaC-to-code references.
- **Attack paths:** a BFS from entrypoints to sinks over resolved calls produces
  interprocedural, route → service → repository → sink paths, each with confidence,
  sanitizer-barrier flags, taint/data-reachability, a risk score, and fix guidance. A
  `--shallow` mode reproduces intra-function traversal for comparison.
- **Resolution honesty:** cross-file call resolution degrades to `low` confidence with
  `ambiguous: true` rather than asserting certainty.

This is what lets CyberGraph answer *reachability* — not "a dangerous call exists" but "user
input can reach this dangerous call from this route with no guard in between."

---

## 6. Security policy

CyberGraph verifies against a **declared security policy** — the routes/functions expected to
require authentication, ownership checks, or other guards — kept as a committed
`cybergraph.policy.toml`.

```bash
cybergraph check . --init-policy    # bootstrap the policy from routes that already require login
cybergraph policy --repo .          # show the declared policy and what it protects
cybergraph policy --repo . --baseline
```

Because the policy is a plain committed TOML file, any human or agent working in the repo can
read what CyberGraph expects to be protected without running the tool. A change that silently
drops a guard the policy declares is what turns an ACCEPT into a REVIEW.

---

## 7. Findings, suppressions & honesty

- **`-UNVERIFIED` variants:** when CyberGraph can see a value reach a sink but cannot confirm how
  it was built, it reports the `-UNVERIFIED` variant (e.g. `CG-SQL-EXEC-UNVERIFIED`) — an
  explicit abstention that drives REVIEW, never a confident claim.
- **Inline suppressions:** `# cybergraph: ignore CG-SQL-EXEC <reason>` on the sink line. Naming a
  rule also accepts its `-UNVERIFIED` variant; the reverse is deliberately not true.
- **Repository suppressions:** `[suppressions] rules = [...]` / `paths = [...]` in config.
- **Suppressed ≠ fixed:** suppressions hide findings, but the graph keeps the edges
  (`REACHES_SINK`) so reviewers can still inspect the path. A finding that disappears because a
  suppression now covers it is counted as *hidden by config (hidden, not fixed)* in history, the
  delta strip, and the report — its history row stays open, so dropping the suppression later
  reads as persisting, not as a regression. A finding that disappears because the code changed is
  counted as fixed. Suppressed attack paths never consume a slot a real one needs on any capped
  surface (report, export, LLM evidence).

---

## 8. Interoperability

CyberGraph positions as a hub, not just another scanner:

- **Imports:** OSV Scanner, npm audit, Semgrep JSON, SARIF, Gitleaks — all into the same graph.
- **Exports:** SARIF out (for GitHub code scanning), JSON graph export, BloodHound OpenGraph.
- **Enrichment:** offline EPSS / KEV / CVSS / advisory JSON.
- **AI pentester bridge (Strix):** `cybergraph strix-plan` turns reachable paths into a focused
  scope brief; Strix validates what's actually exploitable with a working PoC;
  `cybergraph import-strix` feeds PoC-validated findings back so they rank at the top. Strix is
  never a dependency — the bridge only activates when the `strix` binary and Docker are both
  present, so the offline-by-default workflow is unchanged.
- **MCP tools:** an interoperability surface for AI assistants (see §12). Not a gate — the hook
  (§4) is the gate.

---

## 9. Dependency reachability (SCA)

`cybergraph sca` prioritizes dependency CVEs by **reachability** — is the vulnerable code
actually reachable from production routes, or merely present in a lockfile? It maps dependency
manifests and lockfiles across npm, Python, Go, Maven/Gradle, and .NET ecosystems, and connects
a CVE to the routes and sinks that can reach it, so the ranking reflects real risk rather than
raw CVE counts.

---

## 10. Cloud & IaC correlation

`cybergraph cloud-code` / `iac-paths` correlate Terraform resources to the application code that
references them, so **public cloud exposure can be connected to reachable routes, sinks, and
dependency risk** — e.g. a public bucket or an over-privileged IAM role reachable from an
internet-facing route. Config posture is checked too: open Firebase security rules, Supabase
tables with row-level security off, and public S3/GCS bucket policies — a change that weakens one
is a REVIEW.

---

## 11. Reporting

`cybergraph visualize` produces a single self-contained, offline HTML file (Cytoscape.js, fully
inlined — no CDN, no network):

- **Dark-mode-first neon graph explorer** with a light/dark toggle and security-typed, glowing
  nodes.
- **Guided first view** that opens on the top attack path with a plain-language narrative.
- **Security-zones view:** Attack Surface → Guards → Logic → Sensitive Sinks.
- **Exec-first posture:** an A–F security grade, a one-line verdict, a severity-distribution bar,
  a since-last-scan delta strip (new / regressed / fixed), findings grouped into expandable rule
  cards, an honest findings-cap footer, and a print stylesheet for clean PDF export.
- Search, layer/severity filters, a details panel with source drill-down, and entrypoint→sink
  path highlighting.

---

## 12. Evidence & answers

- **Grounded answers** (`cybergraph explain`): file/line/rule/path citations, attack-path
  narratives, remediation guidance, and a high/medium/low/insufficient confidence level. It never
  claims a vulnerability without supporting evidence and **abstains** (returns
  `CONFIDENCE_INSUFFICIENT`) rather than fabricate — and works with no LLM at all.
- **Faithfulness-checked triage:** `cybergraph triage --llm` can suppress a finding only on a
  false-positive verdict whose cited evidence appears verbatim in the supplied code slice — a
  faithfulness check, not a trust-the-model check.
- **Optional, local-only LLM phrasing** via configurable providers (Anthropic Claude, OpenAI,
  Kimi), constrained to retrieved evidence.
- **MCP tools** for AI coding assistants: `build_security_graph_tool`,
  `query_security_graph_tool`, `explain_attack_path_tool`, `grounded_security_answer_tool`,
  `analyze_repo_tool`, `top_risks_tool`, `secret_exposures_tool`,
  `prioritize_dependencies_tool`, `iac_attack_paths_tool`, `import_scanner_report_tool`,
  `import_vulnerabilities_tool`, and `check_change_tool` (mirrors `cybergraph check --json`).

---

## 13. Trust & deployment

- **Zero runtime dependencies** (`dependencies = []`) and fully offline — installable in
  regulated environments (finance, defence, health) where network-reaching tooling cannot go.
- **Your code never leaves your machine.**
- **CI is fork-safe and least-privilege:** untrusted PR code runs with `contents: read` only; the
  PR comment is posted by a separate `workflow_run` job from the default branch. The
  `cybergraph check` step runs on every PR as a non-gating notification until the field
  false-positive rate is measured.
- Python 3.10 – 3.13; ruff-linted; a labelled precision/recall/abstention benchmark and a
  mutation harness that proves the verdicts can actually fail (every seeded fail-open is caught).

---

## 14. Command reference (selected)

```text
cybergraph quickstart .        # zero-to-report: init, build, analyze, open report
cybergraph check .             # ACCEPT/REVIEW verdict for a change (the core command)
cybergraph hook install ...    # run check automatically on commit / agent turn
cybergraph policy --repo .     # show the declared security policy
cybergraph analyze .           # build + run every analysis, print top risks
cybergraph history .           # what's new / fixed / regressed / hidden-by-config since last scan
cybergraph visualize .         # interactive offline HTML report
cybergraph explain "..."       # evidence-cited, confidence-scored answer
cybergraph paths / layers / secrets / cloud-code / top-risks
cybergraph scan / triage / sca / iac-paths / infer-specs
cybergraph review --base main  # PR-style diff verdict
cybergraph sarif / export-json / opengraph      # exports
cybergraph import-report / import-vulns / enrich-vulns / import-strix   # imports
```

---

## 15. Status & roadmap

**Beta.** Stable: the graph store, the five-language analyzers, evidence retrieval, and the HTML
report. The verdict layer is verdict-grade for Python, JavaScript/TypeScript, Go, and Java, with
C# landing in the same shape. The public API and finding rules may still change before 1.0.

Known, documented follow-ups (all fail-safe — they under-claim, never issue a false ACCEPT):

- Sinks configured via property assignment rather than call arguments (e.g. a command or query
  string assigned to a property, then executed) are not yet traced across the assignment.
- Some broad bare-name matches over-flag to `-UNVERIFIED` (REVIEW) rather than resolving
  precisely — conservative noise, never a missed vulnerability.
- Verdict coverage continues to widen: more sink classes per language, and receiver-type
  precision for cases currently handled conservatively.

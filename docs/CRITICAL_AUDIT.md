# CyberGraph — Critical Audit

**Date:** 2026-08-08
**Repo:** https://github.com/khan-ARK/cybergraph
**Audited at:** branch `chore/code-scanning-hygiene` @ `36b5a87`
**Method:** full source read (10,869 LOC), full test run (279 passed / 43s), self-scan, and a live stress test against an unrelated real-world 275-file repository.

This document is the reference for the design discussion that follows it. It records findings and evidence only — it deliberately does not choose a direction.

---

## 1. Repository identity

| | |
|---|---|
| Remote | `https://github.com/khan-ARK/cybergraph.git` (fetch + push) |
| Default branch | `main` |
| Current branch | `chore/code-scanning-hygiene` (pushed to origin) |
| Other branches | `Ver-1.0` (local only) |
| Owners | `khan-ARK`, `Hasan-Laraib` (CODEOWNERS) |
| Package | `cybergraph` v0.1.0 — **not yet published to PyPI** |
| Secrets hygiene | `.env` present locally, correctly gitignored, absent from history |

---

## 2. What the system is

A zero-runtime-dependency Python CLI that parses a repository into a SQLite graph
(`.cybergraph/graph.db`) typed with security semantics, then answers questions over it.

### Pipeline

| Stage | Module | Behaviour |
|---|---|---|
| Collect | `analysis/collector.py` | Walk repository files |
| Parse | `analysis/{python,javascript,go,java,csharp}.py` | Per-language → Nodes / Edges / Findings |
| Resolve | `analysis/resolve.py` | `CALLS` (bare name strings) → `CALLS_RESOLVED` (cross-file, confidence-tagged) |
| Traverse | `security/attack_paths.py` | BFS entrypoint → sink over resolved calls |
| Retrieve | `rag/grounded.py` | Score evidence records, assemble cited answer, abstain when unsupported |
| Present | `visualize.py`, `sarif.py`, `pr_comment.py`, `mcp_server.py` | HTML report / SARIF / PR comment / MCP tools |

### Scale

- 10,869 LOC source across 62 modules
- 279 tests, all passing (43.3s)
- 5 languages, 28 CLI subcommands, 11 MCP tools
- Largest file: `visualize.py` at 1,469 LOC (13.5% of the codebase)

---

## 3. Strengths (evidence-backed)

### 3.1 Engineering and supply-chain discipline — top decile for solo OSS

- 279 passing tests, ruff-linted, Python 3.10–3.13 supported.
- CI is SHA-pinned, least-privilege, and **fork-safe**: `cybergraph.yml` runs untrusted PR
  code with `contents: read` only; the PR comment is posted by a separate `ci-report.yml`
  `workflow_run` job that runs from the default branch. Most commercial tools get this wrong.
- Dependabot, CodeQL, OpenSSF Scorecard, PyPI Trusted Publishing with PEP 740 attestations,
  CODEOWNERS, SECURITY.md, CODE_OF_CONDUCT.md, issue/PR templates — all present.

### 3.2 Zero dependencies + fully offline is a real moat

`pyproject.toml`: `dependencies = []`. This is the single most marketable fact about the
project. Regulated buyers (finance, defence, health) cannot install tooling that reaches the
network. CyberGraph can be installed where Snyk, Semgrep Cloud, and Endor cannot.

### 3.3 Honest epistemics — rare in this category

- `rag/grounded.py:277-282` — returns `CONFIDENCE_INSUFFICIENT` and declines to answer rather
  than fabricate.
- `security/triage.py:142-152` — `should_suppress()` drops a finding only on a
  false-positive verdict **whose cited evidence appears verbatim in the supplied slice**.
  That is a faithfulness check, not a trust-the-model check. Better than most funded startups.
- `analysis/resolve.py:57-71` — resolution degrades to `low` confidence with
  `ambiguous: true` rather than asserting certainty.

### 3.4 Strategy document is sharper than the implementation

`docs/COMPETITOR_MAP.md` correctly identifies the wedge (reachability-grounded SAST + LLM
false-positive triage), cites current literature (LLMxCPG USENIX'25, IRIS ICLR'25, LLM4PFA),
and flags its own research gaps. The thesis is right; the code has not caught up to it.

### 3.5 Performance is a non-issue

275-file repository → 22.6s build, 7,820 nodes, 92,474 edges. HTML report: 2.5s, 1.0 MB,
fully self-contained and offline.

### 3.6 Interoperability surface is unusually broad

SARIF in/out, OSV, npm audit, Semgrep, Gitleaks, Strix, BloodHound OpenGraph, MCP. Positioning
as a hub rather than yet another scanner is strategically correct.

### 3.7 Secret-flow modelling is genuinely differentiated

`security/secrets.py` models `USES_SECRET` → `EXPOSES_SECRET` edges — *where a credential
flows*, not merely that a credential-shaped string exists. Gitleaks finds strings; this finds
paths. Currently under-marketed.

---

## 4. Weaknesses

> **Status update — 2026-08-10 (verdict-core / verdict-surfaces, commits `a770280`..`9b03ee2`):**
> Sections below now carry a status of `OPEN`, `MITIGATED`, or `VERIFIED RESOLVED`. Everything
> in the original prose (`Measured impact`, code excerpts, etc.) is left as historical record
> of the state that was true at the original audit date; the status line and the note appended
> to each section describe what has changed since. See §4.9 below for the honest before/after
> table with commit shas.

### 4.1 VERIFIED RESOLVED (Python) — the core detector is a substring grep, and the project already knows it

`security/ontology.py:82-85`:

```python
SINK_KEYWORDS = {"execute","query","raw","shell","subprocess","eval","exec",
                 "open","write","connect","deserialize","pickle","render_template_string"}
```

Matched with `any(kw in call_name.lower())` (`analysis/python.py:122`). Consequences:

- `open` matches `open`, `reopen`, `open_config`, `opendir`, `_open_session`
- `raw` matches `draw`, `rawData`, `drawChart`
- `write` matches every logger and every file writer
- `connect` matches every DB pool, socket, and event listener

**A finding is emitted with no requirement that the sink argument be tainted.** Taint is
computed separately and only influences ranking.

Measured impact:

| Target | Findings | Distinct rules | Severity spread |
|---|---|---|---|
| CyberGraph's own `src/` | **151** | 1 (`CG-SINK-CALL`) | 100% `medium` |
| graphify (275 files, real repo) | **2,739** | 1 (`CG-SINK-CALL`) | 100% `medium` |

**The project's own CI deletes every one of them before upload.**
`.github/workflows/cybergraph.yml:78-84`:

```yaml
- name: Drop informational sink-inventory findings from the self-scan SARIF
  run: |
    jq '.runs[].results |= map(select(.ruleId | test("^CG-.*SINK-CALL$") | not))' \
      cybergraph.sarif > cybergraph.filtered.sarif
```

Committed comment: *"not actionable on CyberGraph's own parameterized sqlite calls. Keep the
code scanning tab signal-only."* (commits `0a95621`, `36b5a87`).

This is the most important fact in the repository. The project has concluded in production
that its only built-in rule produces no actionable signal, and worked around it in YAML rather
than fixing the rule. Every user hits this on first run without the `jq` snippet.

It also directly inverts the stated strategy: `COMPETITOR_MAP.md` names alert fatigue as the
dominant developer pain, and the shipped tool manufactures it.

**Resolution (VERIFIED RESOLVED for Python; non-Python remains inventory-grade):** the
verdict-core plan (Tasks 1–7, merged in `fe07800` "Merge pull request #38 from
AQ-Labs/feat/verdict-core-detector") replaced the `any(kw in call_name.lower())` substring
match for Python with an exact-match sink registry (`a770280` `feat(sinks): exact-match
registry with vulnerability and shell semantics`) plus per-sink unsafe-use predicates
(`beb9686` `feat(predicates): per-sink semantics with real confinement and shell rules`) that
require the sink argument be tainted, or the finding is downgraded to a `-UNVERIFIED`
abstention rather than a confirmed finding. The Task 7 gate
(`benchmark/run_precision.py`) passed for Python: recall ≥ 0.95, safe-abstention ≤ 0.15
(currently: `GATE PASSED`, recall 1.00, safe false-positive 0.00 across all gated classes).
Re-scanning graphify — the same 275-file external repository used for the original
measurement — now produces **0 confirmed Python findings** (down from 2,739). CyberGraph's
own `src/` similarly drops from 151 to **0 confirmed Python findings**.

This is Python-only. The four non-Python analyzers (JavaScript/TypeScript, Go, Java, C#) are
still the regex substring matcher described in §4.5 and still emit `CG-<LANG>-SINK-CALL`
inventory rows — e.g. re-scanning CyberGraph's own `src/` today still reports 3
`CG-JS-SINK-CALL` findings against the vendored `assets/cytoscape.min.js`. Those four rules
remain classified as inventory, not verdicts, until their Phase-2 upgrade (see §4.5).

**The CI SARIF filter (`.github/workflows/cybergraph.yml`, "Drop informational
sink-inventory findings") is therefore kept, not deleted, and its scope has changed with the
fix:** before this work the filter's pattern (`^CG-.*SINK-CALL$`) matched Python's own
substring-grep output, so the tool really was deleting its own only rule's findings, as
originally documented above. After the Task 1–7 rewrite, Python's verdict rules
(`CG-SQL-EXEC`, `CG-CMD-EXEC`, `CG-PATH-TRAVERSAL`, `CG-TEMPLATE-INJECT`, `CG-CODE-EXEC`,
`CG-DESERIALIZE`, and their `-UNVERIFIED` abstention variants) do not match that pattern at
all — they reach code scanning uploaded and unfiltered. The filter now suppresses only the
four non-Python `CG-{GO,JAVA,JS,CSHARP}-SINK-CALL` inventory rules, which remain
substring-based and not actionable until Phase 2 gives those languages the same treatment
Python just received. `tests/test_sarif.py::test_sarif_filter_targets_only_inventory_not_verdicts`
is a direct regression test for this scope.

### 4.2 OPEN (severity: CRITICAL) — the ontology silently assumes "web app with route decorators"

Measured on graphify (a substantial real Python CLI/library):

```
entrypoints: 0
guards: 5
attack paths: 0
```

Entrypoint detection (`python.py:420-443`) requires a decorator ending in
`.route`/`.get`/`.post`/`.put`/`.delete`/`.patch`/`.head`/`.options`, or a Django `urls.py`
`path()`/`re_path()`/`url()` call.

No routes → no entrypoints → **no attack paths → the entire value proposition evaporates**,
and the tool silently degrades to the grep in §4.1 with no warning to the user.

Unmodelled entrypoint classes: CLI commands (`argparse`, `click`, `typer`),
`if __name__ == "__main__"`, message-queue consumers, cron/scheduled jobs, gRPC services,
AWS Lambda / serverless handlers, GitHub Actions workflow inputs, webhook receivers,
deserialization boundaries, MCP tool handlers.

Note: `SOURCE_KEYWORDS` already contains `argv`, but nothing ever constructs an entrypoint
from it — CLI arguments are a textbook CWE-78 source and are entirely unmodelled.

**Status: still OPEN as of 2026-08-10.** Unchanged by verdict-core/verdict-surfaces — those
plans built a decision layer (`cybergraph check`, capability model, policy) on top of the
existing entrypoint detection rather than widening it. This is why `cybergraph check`
reports `UNKNOWN` for `reachable_data_paths` on a repository with no HTTP routes rather than
a false `accept` — the capability model (Task 8, `feat(checks): evaluate every capability;
never pass without evidence`) requires positive evidence before a capability passes, so the
zero-entrypoint gap degrades to an honest abstention instead of a silent pass. Entrypoint
pluralism (CLI/`__main__`/queues/Lambda/MCP tools) remains unimplemented and is tracked as
Phase 2 work in `docs/superpowers/plans/2026-08-08-verdict-core.md`.

### 4.3 VERIFIED RESOLVED — `top-risks` output is incorrect, and suppressions do not reach it

Live output on graphify:

```
[HIGH 78/100] secret: tests/test_hook_guard.py::_cli -> subprocess.run (internal)
```

All ten "top risks" are `subprocess.run` calls **in the test suite**, mislabelled `secret:`.
They are neither secrets nor risks.

On CyberGraph itself, `.cybergraph.toml` suppresses `tests/*`, `benchmark/*`, `examples/*`,
yet `cybergraph analyze .` still reports:

```
[CRITICAL 95/100] attack-path: benchmark/cases/go_http_cmdi/main.go::route:/ping:14 -> exec.Command
[CRITICAL 94/100] attack-path: tests/fixtures/demo_app/app.py::users -> run_query
```

**Suppressions filter `findings` but not attack paths or risk ranking.** The user set a config
and the ranked output ignored it. This is a defect, not a design decision.

**Resolution:** fixed in `a8f8c26` `fix(paths): suppress before applying the traversal
limit`, with a direct regression test added in the same commit
(`tests/test_attack_path_suppressions.py`, Task 6 of verdict-core). Suppression is now
applied before the traversal/ranking limit is enforced, and follow-up commits (`5772bb8`
`fix(paths): keep suppressed paths on exploration and evidence surfaces`, `4d60f67`
`fix(attack-paths): suppressed paths must not starve the exploration surfaces`, `b0d4b12`
`fix(export): record the graph document's two suppression policies`) ensure a suppressed
attack path is hidden from ranked/actionable surfaces (`top-risks`, `analyze`, PR review)
without starving those surfaces of slots, while still appearing on exploration/evidence
surfaces (HTML report, `explain`, JSON export) for reviewer inspection. Regression pinned
further in `6bad214` `test(attack-paths): pin traversal invariants and the ranked
suppression surfaces`.

### 4.4 OPEN (severity: HIGH) — call resolution is name-only

`analysis/resolve.py:89-92`:

```python
def _simple_name(call_name: str) -> str:
    return call_name.rsplit(".", 1)[-1].strip()
```

`db.execute(...)` resolves to *any* function named `execute` in the repository; `self.process()`
links to every `process`. No receiver typing, no import resolution, no scope analysis.

Produces both phantom paths (linking unrelated same-named functions) and missed paths (sinks
behind interfaces). On graphify the graph holds **14,563 raw `CALLS` edges against 700 Function
nodes** — the call graph is overwhelmingly unresolved dangling strings.

The `low`/`ambiguous` confidence tag is honest but does not recover the lost precision.

**Status: still OPEN as of 2026-08-10.** Unchanged by verdict-core/verdict-surfaces — the
`14,563 raw CALLS edges against 700 Function nodes` shape on graphify has not been
re-measured against a fix because no fix landed; name-only resolution remains. The verdict
layer works around it rather than fixing it: `cybergraph check`'s capability model treats
call resolution confidence as an input to whether a capability is evaluated at all, so an
ambiguous resolution degrades toward `UNKNOWN`/`REVIEW` rather than a false `accept`, per the
governing invariant in `docs/superpowers/plans/2026-08-08-verdict-core.md` ("uncertainty
never becomes safety"). Receiver-typed/import-resolved call graphs remain Phase 2 work.

### 4.5 OPEN (severity: HIGH) — four of five languages have no parse tree

Only Python uses a real AST (stdlib `ast`). The JavaScript/TypeScript, Go, Java, and C#
analyzers are regex-based — each begins `import re` and each docstring self-describes as a
"Lightweight ... analyzer":

| Analyzer | Parsing strategy | Regex call sites |
|---|---|---|
| `analysis/python.py` | stdlib `ast` | 0 |
| `analysis/javascript.py` | regex | 8 |
| `analysis/csharp.py` | regex | 7 |
| `analysis/go.py` | regex | 6 |
| `analysis/java.py` | regex | 6 |

This compounds §4.1 and §4.4. Requiring a *tainted argument* before emitting a finding, or
resolving a call by receiver type, needs structure that regex does not provide. Any precision
target therefore has to be stated per-language, or the project has to take on a parsing
dependency (e.g. tree-sitter), which trades directly against the zero-dependency moat in §3.2.

**Status: still OPEN as of 2026-08-10, and this is the direct reason §4.1's CI SARIF filter
is kept rather than deleted.** The Task 1–7 exact-match-registry-plus-predicate rewrite that
resolved §4.1 for Python depends on an AST (taint through real expression structure); it was
applied to `analysis/python.py` only. JavaScript/TypeScript, Go, Java, and C# still run the
pre-rewrite regex substring matcher and still emit their `CG-{JS,GO,JAVA,CSHARP}-SINK-CALL`
rule as inventory, not a verdict — there is no tainted-argument requirement to apply without
a parse tree. Those four rules therefore stay classified as inventory-grade and stay behind
the CI SARIF filter until each language gets its own Phase-2 sink registry/predicate pass (or
the project takes on a parsing dependency, which is the tradeoff already recorded above
against §3.2's zero-dependency moat).

**Note (2026-08-11): resolved for JS (core four) and Go (SQL/command/path); Java/C# and
other classes remain inventory-grade.** Without a JS or Go parser, a structural,
statement-local classifier per language (`analysis/js_provenance.py`,
`analysis/go_provenance.py`) now grades sink arguments as SAFE (all-literal/constant
construction only), UNSAFE (a construction containing a variable that line-based
intra-function taint confirms), or UNKNOWN (a variable it cannot resolve — never SAFE)
rather than emitting the flat `CG-{JS,GO}-SINK-CALL` inventory row. JS covers four sink
classes (SQL, command, code-exec, path); Go covers three (SQL, command, path — Go has no
registered code-exec sink). Java and C# are unchanged, and other JS/TS sink classes (beyond
SQL/command/code/path) still fall back to the pre-rewrite inventory rule. §4.5 stays OPEN.

### 4.6 MEDIUM — benchmark claims drift from the committed artifact

| | `benchmark/README.md` | `benchmark/results.json` |
|---|---|---|
| Cases | 11 | 10 |
| Precision | 0.9 | 0.889 |
| F1 | 0.947 | 0.941 |

`benchmark/cases/py_fastapi_tainted_sqli/` exists on disk but is absent from results.
`benchmark/results.json` is gitignored (`.gitignore:30`) while `README.md` quotes numbers from
it — the published claim can never be verified against a committed artifact.

For a tool whose pitch is evidence over assertion, this is the wrong place to be loose.
Separately, 11 hand-seeded cases with zero real CVEs constitute a regression guard, not a
benchmark — the README says so honestly, but the figure gets cited as one.

### 4.7 Lower-severity issues

| Issue | Location | Note |
|---|---|---|
| `visualize.py` is 1,469 LOC | `visualize.py` | HTML + CSS + JS + model + theming fused; hardest file in the repo to change or accept contributions to |
| Stale LLM defaults | `llm/client.py:36-40` | `claude-opus-4-8` is valid but one generation behind `claude-opus-5`; `gpt-4o-mini` is also dated |
| Architecture doc stale | `docs/architecture.md:22-28` | Lists JS analyzers, dependency ingestion, HTML viz, MCP as "near-term roadmap" — all shipped |
| Product plan is a stub | `docs/product-plan.md` | 26 lines, effectively a launch checklist |
| Hand-rolled TOML parser | `config.py`, warned about in `.cybergraph.toml:9-10` | Cannot parse multi-line arrays; the limitation leaks into user-facing config docs. `tomllib` is stdlib from 3.11 and would cost zero dependencies |
| `repo_pos` positional alias | `cli.py`, ~10 subcommands | Both `--repo X` and a trailing positional are accepted, inconsistent with `build`/`scan`/`analyze` which take `repo` directly |
| No severity gradation | all analyzers | Everything is `medium`; triage is therefore impossible |
| Line-based suppressions | `suppressions.py` | No content fingerprint, so any suppression breaks on a line move |
| Full rebuild every run | `build.py` | No incremental analysis; fine at 275 files, not at 5,000 |

---

## 4.8 Status transitions — before/after, with commit shas

Recorded 2026-08-10, at the end of the verdict-core / verdict-surfaces plans (20 tasks).

| Section | Status | Before | After | Key commit(s) |
|---|---|---|---|---|
| §4.1 substring detector | **VERIFIED RESOLVED** (Python only) | CyberGraph `src/`: 151 findings, 1 rule (`CG-SINK-CALL`), 100% medium. graphify (275 files): 2,739 findings, 1 rule, 100% medium. | Python: 0 confirmed findings on both CyberGraph `src/` and graphify — Task 7 gate `GATE PASSED` (recall 1.00 ≥ 0.95, safe false-positive 0.00 ≤ 0.05, safe-abstention 0.00 ≤ 0.15, all classes). Non-Python: CyberGraph `src/` still reports 3 `CG-JS-SINK-CALL` inventory findings (vendored `assets/cytoscape.min.js`) — unchanged, inventory-grade, filtered from code scanning by design (see §4.5). | `a770280` (exact-match sink registry), `beb9686` (per-sink predicates), `fe07800` (Task 1–7 merged, PR #38) |
| §4.2 entrypoints | **OPEN** | `entrypoints: 0`, `attack paths: 0` on graphify; silent degradation to grep, no warning. | Unchanged measurement; the verdict layer now reports `UNKNOWN` instead of a false accept when no entrypoints exist (Task 8, capability model). | `638a331` `feat(checks): evaluate every capability; never pass without evidence` |
| §4.3 suppressions ignored in ranking | **VERIFIED RESOLVED** | `.cybergraph.toml` suppressed `tests/*`/`benchmark/*`/`examples/*`; `analyze` still ranked `benchmark/cases/go_http_cmdi/...` and `tests/fixtures/demo_app/...` at CRITICAL. | Suppression applied before the traversal/ranking limit; direct regression test asserts a suppressed path cannot occupy a ranked slot while still surfacing on exploration/evidence views. | `a8f8c26` (fix + `tests/test_attack_path_suppressions.py`), `5772bb8`, `4d60f67`, `b0d4b12`, `6bad214` |
| §4.4 call resolution name-only | **OPEN** | graphify: 14,563 raw `CALLS` edges against 700 Function nodes; `_simple_name()` resolves by trailing identifier only. | Unchanged measurement; no receiver typing or import resolution added. The verdict layer treats low/ambiguous resolution confidence as grounds to abstain (`UNKNOWN`/`REVIEW`) rather than accept. | none (tracked as Phase 2 in `docs/superpowers/plans/2026-08-08-verdict-core.md`) |
| §4.5 four languages without parse trees | **OPEN** | JS/TS, Go, Java, C# analyzers are regex-based (`import re`, 6–8 call sites each); no structure to require a tainted argument. | Unchanged; this is why the four `CG-{JS,GO,JAVA,CSHARP}-SINK-CALL` rules remain inventory-grade and why the CI SARIF filter (§4.1) still suppresses them from code scanning. | none (tracked as Phase 2) |

Live re-measurement commands used above: `cybergraph scan src` (CyberGraph self-scan), `cybergraph sarif --repo src --output ...` (rule-id breakdown), `python benchmark/run_precision.py` (gate).

---

## 5. Features that should be cut or demoted

Ordered by confidence.

1. **`CG-SINK-CALL` as a *finding*.** Keep the `REACHES_SINK` edge; stop emitting a finding.
   It is inventory, not a vulnerability — the project's own CI says so. Highest-value single
   change available.
2. **`cybergraph strix-run`** (`security/strix_runner.py`, 139 LOC). Requires Docker *and* an
   LLM key — the exact inverse of the "no keys, fully offline" headline that is the product's
   differentiator. `strix-plan` and `import-strix` are cheap and fine; the orchestrator is
   scope creep.
3. **`ask` vs `explain`.** Two commands answering questions, one strictly better. Alias `ask`
   to `explain`, delete the old path.
4. **`scan` vs `build` vs `analyze`.** Three entry commands whose differences are not legible
   to a new user. `analyze` should be the only documented one.
5. **`opengraph` export** (124 LOC). BloodHound interop with no cloud/identity data to emit —
   a schema adapter with no payload. Park until Phase 3 exists.
6. **`infer-specs`.** Speculative sink suggestions layered on a detector that already
   over-reports. Wrong ordering — fix precision before widening the net.
7. **`--shallow` ablation flag** on `paths`. A research affordance in a product CLI; belongs in
   the benchmark harness.

The CLI exposes **28 subcommands**. A first-time user cannot form a mental model of that.

---

## 6. Usability gaps

| Today | Should be |
|---|---|
| 28 subcommands in `--help` | ~6 visible; the rest behind an advanced group |
| `build` → `ask` → `paths` → `visualize` | `cybergraph` with no args = analyze cwd + open report |
| `--repo X` on some commands, positional on others, plus `repo_pos` aliases | one convention everywhere |
| 2,739 `medium` findings | ≤20 by default, `--all` for the rest, explicit "N suppressed as inventory" line |
| Silent zero-entrypoint degradation | explicit warning: "No HTTP routes found. If this is a CLI/library, run `--entrypoints cli`" |
| Suppression by rule/path only | plus content-hash fingerprints, plus a `cybergraph baseline` command |
| `.cybergraph.toml` requires single-line arrays | use `tomllib` on 3.11+, fall back only on 3.10 |

---

## 7. Fit against current market pain

| Pain | CyberGraph today | Verdict |
|---|---|---|
| Alert fatigue / SAST false positives | *Causes* it (2,739 mediums). Has the right cure designed (`triage.py`) but it is opt-in, default-off, and needs an API key | **Inverted** |
| "Is this CVE reachable?" | `sca.py` is the right idea; blocked by name-only resolution and zero entrypoints on non-web code | Partial |
| AI-generated code outpacing review | The dominant 2026 pain. Not addressed at all | **Missed — and it is the open wedge** |
| Secrets sprawl | `secrets.py` models exposure *paths*, genuinely differentiated | **Strength**, under-marketed |
| Attack-path context | Best-in-class design; works on fixtures, produces nothing on real non-web repos | Demo↔real gap |
| Compliance / audit evidence | Report + SARIF + history delta is ~80% of an audit artifact | Underexploited |

**Summary:** CyberGraph is a well-built *graph substrate* wearing the marketing of a *scanner*.
The substrate is the asset; the scanner on top of it is currently a liability.

---

## 8. Distribution options (recorded, not chosen)

1. **Security layer for AI coding agents.** `mcp_server.py` already exists. Every Claude
   Code / Cursor / Copilot user generates code faster than they can review it. An offline,
   no-key check inside the agent loop is a category with no incumbent — Snyk, Semgrep and
   Endor are all built for the human-PR era.
2. **Make the HTML report the shareable artifact.** 1.0 MB, self-contained, offline,
   dark-mode graph. People screenshot reports; nobody screenshots SARIF. Add a grade badge
   and make no-arg invocation produce it.
3. **Publish to PyPI.** `pipx install cybergraph` does not work today. Cheapest high-impact
   action available; nothing spreads until it lands.
4. **Scan 20 well-known OSS repos and publish results honestly, including the misses.** Most
   credible content a security tool can publish, and it doubles as a real benchmark corpus
   replacing the 11 seeded fixtures.
5. **Ship a GitHub App, not just a workflow.** The `pr-comment` machinery exists; this is a
   packaging problem.

**Risk note:** launching before §4.1 and §4.2 are fixed exposes every new user to a
2,739-finding first run. That is a one-shot reputation loss.

---

## 9. Candidate work items (recorded, not sequenced)

Ordered by impact ÷ effort.

| # | Item | Rationale |
|---|---|---|
| 1 | Precision rewrite of sink detection — exact-match registry per language/framework, tainted argument required, severity by CWE | Everything else is downstream of this |
| 2 | Entrypoint pluralism — CLI, `__main__`, queue consumers, Lambda handlers, MCP tools, GH Actions inputs | Unlocks the product on non-web repositories |
| 3 | Local FP triage with no API key — deterministic graph-slice heuristics (sanitizer on path, constant argument, test-file context, parameterized query detected) | Cuts noise without breaking the no-keys promise |
| 4 | `cybergraph baseline` — accept everything present, report only what is new | Makes adoption on an existing codebase possible on day one |
| 5 | AI-diff mode — `review --agent` returning structured JSON, plus an MCP `security_review_diff` tool | The wedge in §8.1 |
| 6 | Severity + CWE + OWASP on every finding | Required by any enterprise buyer; everything is `medium` today |
| 7 | Fingerprinted suppressions (content hash, not line number) | Suppressions currently break on every refactor |
| 8 | Framework packs — declarative per-framework sources/sinks/sanitizers/routes/guards, community-extensible without touching Python | Turns 5 hardcoded languages into an ecosystem; how Semgrep won |
| 9 | Incremental builds | 22s at 275 files is fine; 5,000 files is not |
| 10 | Split `visualize.py` into `report/{model,html,theme,assets}.py` | Prerequisite for outside contribution to the report |
| 11 | Apply suppressions to attack paths and risk ranking | Fixes §4.3 |
| 12 | Reconcile `benchmark/README.md` with `results.json`; commit the results file | Fixes §4.5 |

Items 1–4 determine whether the project succeeds. Item 5 determines how fast.

---

## 10. One-paragraph summary

CyberGraph is a legitimately good graph engine with an honest evidence layer and best-in-class
OSS and CI hygiene, with a keyword grep bolted onto the front of it. The grep produces 2,739
undifferentiated findings on real code; the project's own CI carries a `jq` filter to delete
its output; and on any repository without HTTP route decorators the attack-path engine — the
actual product — returns zero. `docs/COMPETITOR_MAP.md` correctly diagnoses alert fatigue as
the dominant pain, and the shipped tool currently *is* alert fatigue. Fix detection precision
and entrypoint coverage and there is a defensible product here. Ship as-is and the first
hundred users bounce.

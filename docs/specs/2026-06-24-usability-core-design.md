# Design Spec — Usability Core (Theme A, Spec 1)

**Status:** approved design, pre-implementation
**Author:** Laraib
**Date:** 2026-06-24
**Scope:** first workstream of the CyberGraph improvement roadmap (Theme A — Usability & Navigation)

---

## Context

CyberGraph has a strong engine (29 CLI commands; a security-typed graph with taint/dataflow
edges; reachability attack paths; SCA with EPSS/KEV; Strix pentest bridge; IaC→cloud paths; a
deterministic risk model; an interactive HTML graph explorer; an MCP server). The gap is
**usability**: the power is hard to reach.

Confirmed friction (from a code audit of the current tree):
- **No single orchestrating command** — users chain order-dependent commands (e.g.
  `build → import-vulns → sca`); some commands silently rebuild, others assume a built graph.
- **Inconsistent CLI** — `repo` is positional on some commands, a `--repo` flag on others; all
  output is plain uncoloured text with **no `--json`/machine-readable stdout**.
- **No `.env` loader** — LLM features need manual `CYBERGRAPH_LLM_*` env exports.
- **Silent truncation** — the graph/report caps at 600 nodes with no visible banner.
- **No `config show`** — the effective configuration can't be inspected.
- **MCP exposes only 4 of 29 capabilities** — an IDE/agent can't drive the full workflow.

**Primary users (both, equally):** a security engineer (CLI + HTML report) and a developer
(IDE/CI via MCP). The design therefore builds **one shared core** surfaced through *both* the CLI
and MCP.

**Outcome:** one `analyze` command and one shared result object that the CLI (text + `--json` +
colour), the HTML report, and the MCP server all consume — plus the small friction-killers.

## Non-goals (this spec)

- HTML report redesign (dark mode, unified search, source drill-down) and the first-run
  interactive wizard → **Spec 2 (Report & onboarding polish)**.
- New detection capabilities, temporal analysis, threat-intel/standards, KG analytics → later
  themes (B–E) in the roadmap. This spec is usability only.
- No CLI-framework migration (stay on `argparse`); no new hard runtime dependencies.

## Principles / constraints

- **Additive & non-breaking:** every existing command keeps working unchanged.
- **No new hard dependencies:** colour/tables via a tiny internal helper (respect `NO_COLOR` +
  TTY); the `.env` loader is a minimal hand-rolled parser.
- **Deterministic default path:** LLM stays opt-in; nothing here requires a key.
- **One source of truth:** all surfaces render from the same `AnalysisResult`.
- Commits authored as the user only (no co-author trailer), on a feature branch.

## Architecture — one build, one result, four surfaces

```
build graph ONCE
      │
      ▼
orchestrator.run_full_analysis(repo)  ──►  AnalysisResult (typed)
      │                                          │
      │                    ┌─────────────┬────────┴────────┬──────────────┐
      ▼                    ▼             ▼                 ▼              ▼
 (reuses existing     CLI text       CLI --json        HTML report    MCP tools
  analysis fns,       (coloured/                        (renders       (return
  no re-build)        tabular)                          from result)   to_json())
```

### New modules

**`src/cybergraph/report_model.py`**
- `@dataclass(frozen=True) AnalysisResult` with: `repo: str`, `counts: dict` (nodes/edges/findings),
  `top_risks: list[TopRisk]`, `attack_paths: list`, `secret_exposures: list`, `sca: list`,
  `iac_paths: list`, `cloud_code_paths: list`, `layers: list`, `truncated: bool`,
  `timings: dict[str, float]`, `llm_configured: bool`, `errors: dict[str, str]` (per-stage).
- `to_json(result) -> dict` — a **stable, documented** JSON schema (versioned with a
  `"schema": "cybergraph.analysis/1"` field) reused by `--json`, the report, and MCP.

**`src/cybergraph/orchestrator.py`**
- `run_full_analysis(repo_root, *, limit: int = 10) -> AnalysisResult`.
- Calls `build_graph(repo)` **once**, then fans in the existing functions — `collect_top_risks`,
  `find_attack_paths`, `find_secret_exposures`, `prioritize_vulnerabilities`,
  `find_iac_attack_paths`, `find_cloud_code_paths`, `summarize_layers` — which already read the
  store without rebuilding.
- Each stage wrapped in try/except; a failing stage records into `errors[stage]` and yields an
  empty list rather than aborting. Records `timings[stage]`.
- Reuses `collect_top_risks` for the ranked fan-in (no logic duplication).

**`src/cybergraph/output.py`**
- `render_text(result, *, color: bool) -> str` and small helpers `_table(rows, headers)`,
  `_colorize(text, level)`.
- Colour only when `color and stdout.isatty() and not NO_COLOR`. Pure-ASCII fallback otherwise.
- Unifies the currently-divergent risk formats into one presentation (`[HIGH 82/100] category:
  title`).

### CLI changes (`src/cybergraph/cli.py`)

- **New command** `analyze [repo] [--json] [--limit N] [--no-color] [--no-report]`:
  runs the orchestrator; prints top risks + a summary (coloured/tabular) or JSON; writes the HTML
  report unless `--no-report`. This is the "just run it" entry point.
- **Global output options:** `--json` / `--format {text,json}` and `--no-color` on the main parser
  (honoured by `analyze` first; extended to other formatted commands opportunistically).
- **Consistent `repo`:** add an optional positional `repo` to every command that lacks one, keep
  `--repo` as a working alias; a shared `_resolve_repo(args)` prefers the positional then `--repo`
  then `"."`. Back-compatible.
- **New command** `config show [repo]`: prints the effective `CyberGraphConfig`, whether an LLM is
  configured, and whether the graph is built.
- **Truncation banner:** when `AnalysisResult.truncated` (or an export cap) fires, print
  `⚠ graph truncated to N of M nodes (raise with --max-nodes)`.
- **"Graph not built" guidance:** read commands (`ask`/`explain`/`paths`/`layers`/`sca`) detect an
  empty/missing DB and print `Run 'cybergraph build <repo>' first.` instead of empty output.

### `.env` loader (`src/cybergraph/env.py` + hook in `llm` config)

- `load_dotenv(repo_root)` — minimal parser: read `.env` from repo root and cwd; parse `KEY=VALUE`
  lines (ignore blanks/`#` comments, strip surrounding quotes); **set only keys absent from
  `os.environ`** (never override the real environment). Non-fatal on parse errors.
- Called at CLI startup and before `load_llm_config_from_env()`, so `CYBERGRAPH_LLM_*` in a repo
  `.env` "just works".

### MCP parity (`src/cybergraph/mcp_server.py`)

- Add tools that call the same orchestrator/component functions and return `to_json()`:
  `analyze_repo`, `top_risks`, `secret_exposures`, `prioritize_dependencies`, `iac_attack_paths`,
  `import_scanner_report`, `import_vulnerabilities`.
- Existing 4 tools stay. Result: an IDE/agent can drive the full workflow (the developer persona).

## Data flow

`analyze` (or MCP `analyze_repo`) → `run_full_analysis` builds once and fans in → `AnalysisResult`
→ rendered by `render_text` (human) / `to_json` (`--json`, MCP) / the HTML report. No surface
re-runs analysis or rebuilds the graph.

## Error handling

- Orchestrator: per-stage isolation (one analysis failing never aborts the run; recorded in
  `errors`).
- `.env`/config parse issues: warn, continue.
- `--json` output is always valid JSON, even when stages error (errors surface in the `errors`
  field).

## Testing (add ~12–15; keep the current 164 green)

- Orchestrator populates a non-empty `AnalysisResult` on `examples/vulnerable-fastapi` (or a tiny
  built repo); a deliberately-broken stage lands in `errors` without aborting.
- `to_json` schema stability (keys + `schema` version present; round-trips).
- `.env` loader: loads values, does **not** override existing env, ignores comments/quotes,
  no-ops when absent.
- `config show` output includes config + llm-configured + graph-built.
- Truncation banner appears when capped; absent otherwise.
- `_resolve_repo`: positional wins over `--repo`; `--repo` still works; default `.`.
- MCP: new tools are registered (importable; `mcp` object exposes them).
- `analyze --json` emits valid JSON; `analyze` (text) prints top risks.

## Verification (end-to-end)

1. `python -m ... analyze examples/vulnerable-fastapi` prints coloured top risks + summary and
   writes `.cybergraph/report.html`.
2. `analyze examples/vulnerable-fastapi --json | python -m json.tool` is valid and matches the
   schema.
3. A repo `.env` with `CYBERGRAPH_LLM_*` makes `explain --llm` work with no manual `export`.
4. `config show` reflects `.cybergraph.toml`.
5. MCP server lists the new tools; `analyze_repo` returns the same JSON as `--json`.
6. Full `pytest` green.

## Roadmap context (for sequencing — not this spec)

Full inventory, to be tackled in order after this: **A2** report & onboarding polish (Spec 2) →
**D** temporal analysis (persist scans, first/last seen, trends/MTTR) → **C** threat-intel &
standards (live EPSS/KEV, SBOM+VEX, MITRE ATT&CK, compliance) → **B** detection depth (precise
dataflow linking, real secret scanning, tree-sitter, more IaC) → **E** KG-native intelligence
(centrality/chokepoints, embeddings/NL query, agentic remediation).

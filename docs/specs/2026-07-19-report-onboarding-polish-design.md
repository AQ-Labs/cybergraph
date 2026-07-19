# Design Spec — Report & Onboarding Polish (Theme A, Spec 2)

**Status:** approved design, pre-implementation
**Author:** Laraib
**Date:** 2026-07-19
**Depends on:** Spec 1 "Usability Core" (`run_full_analysis`, `AnalysisResult`, the real `truncated`
signal) — this work branches off `feat/usability-core`.
**Scope:** second workstream of Theme A — make the HTML report and first-run experience delightful
for both a security engineer (report) and a developer (quick onboarding).

---

## Context

The HTML report (`src/cybergraph/visualize.py`, ~800 lines) is a single self-contained, offline
file: a Cytoscape graph explorer (4 modes) above static tables, with search/filters and a details
panel. Confirmed limitations:
- **Light-mode only** — CSS is hardcoded `:root { color-scheme: light }`; no dark theme.
- **Two separate search boxes** — the graph (`#cg-search`) and the findings table each have their
  own text search.
- **No visible truncation banner** — the graph/report caps at 600 nodes; the `truncated` flag
  exists (now real, from Spec 1) but the report never tells the user.
- **No source drill-down** — nodes carry `file`/`line` but the details panel shows no code.

Onboarding is `init` + `doctor` + README; first run is a multi-command sequence with no single
guided path.

**Outcome:** a theme-aware report with one search, a truncation banner, opt-in in-report source
snippets, and a one-command `quickstart` that takes a new user from zero to an open report.

## Principles / constraints

- **Self-contained & offline:** no CDN, no network, no external fonts/assets. Everything inlined.
- **No new hard dependencies.** Theming/search/snippets are hand-rolled HTML/CSS/JS + stdlib Python.
- **Additive & non-breaking:** the 4 explorer modes, filters, details panel, and existing tables
  keep working unchanged.
- **Security first (this is a security tool):** the report is a shareable artifact — source
  embedding is **opt-in and secret-redacted** (see D).
- Commits authored as the user only (no co-author trailer), on `feat/report-onboarding-polish`.

## Non-goals (this spec)

- Refactoring `visualize.py` into a templating framework (targeted in-place edits only).
- An interactive TUI (the guided path is a non-interactive-friendly command).
- Temporal/threat-intel/detection features (later themes).

---

## A. Theme-aware report

- Convert the hardcoded light CSS to **CSS custom properties** on `:root` (e.g. `--bg`, `--fg`,
  `--panel`, `--border`, `--muted`, `--accent`), with a **dark palette** under both
  `@media (prefers-color-scheme: dark)` and `:root[data-theme="dark"]`, and explicit
  `:root[data-theme="light"]` overrides so the toggle wins in both directions.
- **Toggle button** in the header; the choice persists to `localStorage` (`cybergraph-theme`).
- **No flash of wrong theme:** an inline `<script>` in `<head>` reads `localStorage`/`prefers-color-scheme`
  and stamps `data-theme` on `<html>` before first paint.
- **Cytoscape must recolor on toggle** (its styles are set in JS from values, not CSS): read the
  canvas background, node-label, and edge colors from CSS variables at init, and on theme change
  re-apply via `cy.style()`/`cy.container` background + `cy.style().update()`. **Node group
  semantic colors (the 12 `NODE_GROUPS`) stay fixed** across themes (they carry meaning); ensure
  legibility on dark by adding a subtle node border/halo.
- Files: `src/cybergraph/visualize.py` (CSS block, header toggle, ~15 lines of JS).

## B. Unified text search

- Replace the two separate text inputs with **one** `#cg-search`; a single handler filters **both**
  the graph (dim/hide non-matching nodes, as today) **and** the findings-table rows (hide
  non-matching), matching on name/file/group/message.
- **Leave the two severity `<select>` filters as-is** — graph min-severity and findings
  min-severity are intentionally different scopes; document this in a code comment. (Unifying them
  is out of scope.)
- Files: `src/cybergraph/visualize.py` (remove the second search input; extend the handler).

## C. Truncation banner

- When `build_graph_data(...)['truncated']` is true, render a visible banner above the graph:
  `Showing N of M nodes — raise --max-nodes to see the full graph.` (N = shown nodes, M = total).
  Hidden entirely when not truncated.
- Files: `src/cybergraph/visualize.py` (the JSON already carries the counts; add the banner element
  + one conditional).

## D. Opt-in, secret-redacted source drill-down

- **New module `src/cybergraph/report_source.py`:**
  `attach_source_snippets(repo_root, graph_data, *, context=3, max_nodes=200, redact_secrets=True)
  -> None` (mutates `graph_data` in place).
  - Selects nodes that have a finding **or** lie on an attack path AND have `file` + `line > 0`;
    caps at `max_nodes` (security/perf bound).
  - Reads the file with `encoding="utf-8", errors="ignore"`; slices `[line-context, line+context]`
    with correct **start-of-file / end-of-file clamping** (no negative indices, no overrun).
  - **HTML-escapes every line** (`html.escape`) — snippets are rendered as text, never markup.
  - Attaches `node["snippet"] = {"file": rel, "start": s, "lines": [{"n": int, "text": str,
    "highlight": bool}]}` where `highlight` marks the finding/target line.
  - **Secret redaction:** for any node whose finding `rule_id`/category indicates a secret
    (`"SECRET"` in rule_id, or secret-category), the highlighted line's value is masked
    (`text` replaced with the key/prefix + `= "***redacted***"`), so a shared report never leaks a
    credential. Governed by `redact_secrets` (default True).
  - Best-effort: unreadable/binary/missing files → node simply gets no snippet (never raises).
- **`visualize.py`:** call `attach_source_snippets` only when source embedding is enabled (see the
  `--with-source` flag); the details-panel JS renders the snippet (line numbers, monospace,
  highlighted line) when present, and shows nothing extra when absent.
- **`generate_html_report(repo_root, output=None, *, with_source=False)`** gains a keyword; default
  **off** (no source embedded → smallest, safest report).
- Files: new `src/cybergraph/report_source.py`; `src/cybergraph/visualize.py` (details panel + call).

## E. Guided `quickstart` command

- **New `src/cybergraph/quickstart.py`:** `run_quickstart(repo_root, *, open_report, with_source)
  -> QuickstartResult` — runs, in order, `init_project` (only if no `.cybergraph.toml`), then
  `build_graph`, then `run_full_analysis` (reused from Spec 1), then `generate_html_report`. Returns
  a small result (steps run, counts, top risk, report path). Each step logged as
  `[k/4] <step> ... <one-line outcome>`; a step failure is reported and, where safe, the flow
  continues.
- **CLI `quickstart [repo] [--yes] [--no-open] [--with-source]`** (in `cli.py`): prints the step
  log + the single highest risk + the report path. **Browser open** only when `open_report` and the
  session is interactive — i.e. **not** when `--no-open`, not when `stdout` isn't a TTY, and not
  when a `CI` env var is set (guarded `webbrowser.open`, never blocks). `--yes` makes it fully
  non-interactive; `--with-source` forwards to the report.
- Files: new `src/cybergraph/quickstart.py`; `src/cybergraph/cli.py` (parser + dispatch).

---

## Data flow

`build_graph_data` (+ real `truncated`) → *(optional)* `attach_source_snippets` → JSON injected
into the themed HTML (one search, banner, drill-down). `quickstart`: `init?` → `build` →
`run_full_analysis` → `generate_html_report` → guarded browser open.

## Error handling

- Snippet reader: best-effort per node; any read/parse error → skip that node's snippet, never
  crash the report.
- Theme: if `localStorage` is unavailable, fall back to `prefers-color-scheme`.
- `quickstart`: per-step failures are reported with a clear message; `webbrowser.open` is wrapped so
  a missing browser never aborts or hangs.

## Testing (add ~14–18; keep the current 203 green)

- **Theme:** generated HTML contains the CSS variables, both `prefers-color-scheme: dark` and
  `:root[data-theme="dark"]`, the head anti-FOUC script, and a theme-toggle control.
- **Search:** the HTML contains exactly **one** text-search input (`#cg-search`) — assert the second
  one is gone — and the handler references both the graph and the findings table.
- **Banner:** present with "of" + node counts when the graph is truncated (build a &gt;600-node
  fixture or monkeypatch the cap); absent when not truncated.
- **`attach_source_snippets`:** correct lines + `highlight` on the finding line; start-of-file
  (line 1) and end-of-file clamping; HTML-escaping of `<`/`&`; **secret redaction** masks the value
  for a `*-SECRET` finding; missing file → no snippet, no raise; `max_nodes` cap respected.
- **`with_source` default off:** `generate_html_report` embeds no source unless `with_source=True`.
- **`quickstart`:** end-to-end on a tiny repo — builds, analyzes, writes the report, exit 0; `--yes`
  is non-interactive; `--no-open`/CI never opens a browser (assert `webbrowser.open` not called via
  monkeypatch).

## Verification (end-to-end)

1. `quickstart examples/vulnerable-fastapi --no-open` prints a 4-step log + top risk + report path.
2. Open the report; toggle theme (both look correct; graph recolors); one search box filters graph +
   findings; truncation banner shows only on a large repo.
3. `visualize examples/vulnerable-fastapi --with-source` embeds highlighted snippets; a secret
   finding's value is redacted in the HTML. Default (no flag) embeds no source.
4. Full `pytest` green (≥ ~217 passed).

## Out of scope / follow-ups

- Unifying the two severity filters; a source *viewer* (whole file) vs. snippet; opening source in
  an editor/GitHub deep-link (could pair with `--with-source` later); templating-framework refactor
  of `visualize.py`.

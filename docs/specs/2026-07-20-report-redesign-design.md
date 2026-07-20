# HTML Report Redesign — Design Spec

**Date:** 2026-07-20
**Status:** Approved for planning
**Scope:** The self-contained HTML security report only (`cybergraph visualize` / the report written by `analyze` and `quickstart`). CLI text output and the MCP server are out of scope except that their call into `generate_html_report` must keep working unchanged.

## Goal

Turn the HTML report from a functional-but-plain page into a professional, exec-first security report with a coherent visual design system and a maintainable code layout — while keeping it a single, offline, self-contained HTML file.

## Constraints (Global)

- **Self-contained, offline.** Output is one HTML file with all CSS/JS inlined at generation time. No CDN, no network fetches, no remote fonts. Only Cytoscape.js stays vendored (as today), plus any CSS/JS assets we ship inside the package and inline.
- **Public API unchanged.** `generate_html_report(repo_root: Path, output: Path | None = None, *, with_source: bool = False) -> Path` keeps its exact signature and behavior contract. `analyze`, `quickstart`, `visualize`, and the MCP server must need zero changes.
- **No new runtime dependencies.** All new visuals (severity bar, grade badge) are hand-rolled SVG/CSS. No chart library.
- **HTML escaping preserved.** All interpolated data stays escaped exactly as the current code does (`html.escape`, `_embed_json`'s `</` → `<\/`).
- **Windows-safe.** Any new user-facing CLI strings (none expected) must be cp1252-encodable. Report content is UTF-8 (`encoding="utf-8"`), unchanged.

## Architecture

`visualize.py` becomes a thin composer. The template and its styles/scripts move to package data files, loaded via `importlib.resources` — the same mechanism already used for `assets/cytoscape.min.js` — and inlined into the final HTML.

### File layout

```
src/cybergraph/
  visualize.py            # public API: gather data + compose + write (thin)
  report_sections.py      # one pure function per section → HTML string (new)
  assets/report/
    template.html         # page skeleton with __TOKEN__ placeholders (new)
    report.css            # design tokens + all styles: light/dark/print (new)
    report.js             # explorer + interactions, reorganized from today (new)
```

### Data flow

1. `generate_html_report` opens the `GraphStore`, runs the existing queries (counts, findings `LIMIT 100` severity-ordered, vulnerable dependencies), and gathers `summarize_layers`, `find_attack_paths`, `build_graph_data`, optional `attach_source_snippets`. **Unchanged.**
2. New: it also calls `history.scan_delta(repo_root)` and `history.list_scans(repo_root, limit=2)` to build the delta strip. Both are wrapped so any failure (e.g. no history tables) yields "no delta" rather than raising.
3. It passes each gathered dataset to the matching pure renderer in `report_sections.py`.
4. Each renderer call is wrapped by a `_safe_section(fn, *args)` helper: on exception it returns a small "section unavailable" card and records nothing else (mirrors `AnalysisResult.errors` tolerance). One bad section never aborts the file.
5. `template.html` is loaded, `__TOKEN__`s replaced (existing `_render_html` pattern), CSS/JS inlined, file written UTF-8.

### Asset inlining

`report.css` is inlined inside a `<style>` tag; `report.js` inside a `<script>` tag; Cytoscape source inlined as today. `_embed_json` unchanged for the graph payload. A helper `_read_asset("report/report.css")` wraps `files("cybergraph") / "assets" / ...`.

## Page structure (exec-first UX)

A sticky top navigation bar (report title, section anchor links, theme toggle, "generated <ISO time>") sits above five sections. Each section is a `.card` with a `scroll-margin-top` so anchor links land cleanly under the sticky bar.

### 1. Security Posture (new; opens the page)

- **Grade badge (A–F)** derived from top-risk scores (0–100, confirmed range):
  - **A** — no risk ≥ 40 (or no risks at all → "No significant risks detected.")
  - **B** — highest risk in 40–54
  - **C** — 55–69
  - **D** — 70–84
  - **E** — 85–89
  - **F** — any risk ≥ 90
  - Boundaries are inclusive on the lower bound. The badge shows the letter + a one-sentence plain-language verdict.
- **Severity-distribution bar** (SVG/CSS): horizontal segmented bar over the stored findings by severity (critical→info), each segment width proportional to its count, colored with the severity palette, with a small count label. Zero findings → a single muted "No findings" track.
- **Stat chips:** the existing four (nodes / edges / findings / attack paths), restyled small.
- **Top 3 risks** as prose cards: title, score chip (severity-colored), one-line detail, and a "jump to path →" anchor to the explorer. Uses `graph_data["top_risks"]` (already available), first three.
- **Delta strip** (only when history exists and not first scan): e.g. "Since scan on <prev ts>: +2 new · 1 regressed · 1 fixed · 3 persisting." Counts from `scan_delta`; date from `list_scans(...)[1]["ts"]`. Hidden entirely when `is_first` or no history.

### 2. Attack Paths & Graph Explorer

The current Cytoscape explorer, restyled with design tokens. Behavior (modes, filters, path highlight, details panel, source snippet in details) is preserved. The risk-card strip stays. Toolbar controls get consistent token styling and keep their aria-labels.

### 3. Findings Triage

- Per-row **severity-colored left border** + colored **severity pill**, using the shared palette.
- The existing search box (shared `#cg-search`) + severity `<select>` filter behavior preserved.
- **Client-side sortable columns** (severity, rule, file) via a small vanilla comparator; severity sorts by rank, not alphabetically.
- **Expandable row**: when `with_source=True` and a snippet is attached for the finding's location, a row expands to show the redacted source snippet (reuse the `.cg-snippet` styling). When `with_source=False`, rows are not expandable — no snippet UI, no empty affordance.
- **Honest footer:** "Showing the top 100 findings by severity (N total) — run `cybergraph sarif` or `cybergraph export-json` for the complete set." N is `counts['findings']`. `sarif` confirmed uncapped; `export-json` exists. If total ≤ 100, the footer reads "Showing all N findings."

### 4. Dependencies & Layers

The current vulnerable-dependencies and security-layers tables, restyled. The vuln-dep evidence column pretty-prints its JSON (`json.loads` then indent-2) instead of dumping a raw string; on parse failure it falls back to the escaped raw string.

### 5. About this scan (footer)

Repo path, CyberGraph version (`importlib.metadata.version("cybergraph")`, fallback "unknown"), scan timestamp, and the truncation note when `graph_data["truncated"]` (replacing today's standalone banner, whose logic moves here and into the posture area). No external links.

## Visual design system

Single token block at the top of `report.css`:

- **Type:** system font stack (as today); sizes 12/13/15/18/24/32; weights 400/600/700; body line-height 1.5.
- **Spacing:** `--space-1..7` = 4/8/12/16/24/32/48.
- **Radius:** 8/12/16. One elevation/shadow token.
- **Severity palette (single color language):** critical `#dc2626`, high `#ea580c`, medium `#d97706`, low `#2563eb`, info/none `#64748b`; each with a muted tint variant for pills and row tints. Used identically across posture bar, finding pills, row borders, and Cytoscape severity node borders (JS reads the same hex values).
- **Surfaces:** extend existing `--bg/--panel/--border/--fg/--muted/--th` + `--cy-bg`.
- **Components:** `.card`, `.pill--{critical|high|medium|low|info}`, `.chip`, `.badge-grade`, `.sevbar`/`.sevbar-seg`, `.section`.

## Dark mode + print

- **Dark mode:** tokens defined under `:root` (light) and overridden under both `@media (prefers-color-scheme: dark)` and `:root[data-theme="dark"]`; the light override under `:root[data-theme="light"]`. The existing pre-body inline theme-bootstrap script and the toggle + `localStorage('cybergraph-theme')` are kept verbatim. Everything currently hard-coded light (severity tints, posture visuals, risk cards, `.path` boxes, vuln-dep code blocks) moves to tokens so dark mode is fully covered.
- **Print (`@media print`):** hide sticky nav, theme toggle, and graph toolbar; force light tokens; expand collapsed finding rows; `break-inside: avoid` inside cards. Target: `Ctrl-P → PDF` yields a clean audit handout. **Deferrable:** if the implementation plan runs long, print becomes its own final task — never silently dropped.

## Error handling & degradation

- `_safe_section(fn, *args, **kwargs)` wraps every renderer; on exception returns a "section unavailable" card string.
- History gathering wrapped: missing tables / git → delta strip hidden, no raise.
- Empty states for every section (no findings / no paths / no deps / no risks / first scan) render muted messages, never blank.
- Grade with zero risks → **A**, verdict "No significant risks detected."
- `with_source=False` → non-expandable rows.
- Version lookup failure → "unknown".

## Testing strategy

Extends `tests/test_report_*.py`.

- **Unit (pure renderers):** grade thresholds incl. A/B/C/D/E/F boundary values and empty-risk→A; severity-bar segment counts and zero-findings track; delta-strip text, first-scan hidden, no-history hidden; findings footer wording + true total (≤100 vs >100 branches); every empty state.
- **Composition:** generate from a fixture repo; assert all five section anchors present; assert `cybergraph sarif` string present in findings footer; assert no unresolved `__TOKEN__` remains; assert self-contained (no `http://`/`https://` in asset positions; the report may contain such strings only inside escaped finding data, so the check targets `<link>`/`<script src>`/`url(` — there must be none).
- **Regression (kept):** secret redaction still holds with `--with-source`; dark-mode toggle + theme persistence markup present; graph explorer JSON payload present and parseable.
- **Cross-surface:** `test_cli_analyze.py` (analyze/visualize/quickstart produce a report, signature unchanged) stays green.

## Out of scope (explicit)

- CSV export of findings, raising the 100-finding SQL cap, a client-side SPA/router, virtualized tables, and any CLI-text redesign. These are potential follow-ups, not part of this spec.

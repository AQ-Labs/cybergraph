# Report Reconcile — Design Spec

**Date:** 2026-07-20
**Status:** Awaiting review
**Base:** `origin/main` @ `8cd02b1` (after `feat/report-visual-identity` merged)
**Branch:** `feat/report-reconcile`

## Background

Two report redesigns were developed in parallel. The owner's `feat/report-visual-identity`
("Spec 3": neon theme, findings grouped into rule cards, clickable risk-card strip,
security-zones view, guided first-view, explainer cards) merged to `main` first. My
`feat/report-redesign` (PR #13: exec-first posture grade, since-last-scan delta, sortable
findings, honest cap footer, print export, asset-file extraction) now conflicts.

Reconnaissance of `main` confirmed that **none** of my user-facing features exist there — they
are genuinely additive, not duplicative. This spec ports the additive subset onto `main`'s
architecture and explicitly drops the parts that either don't fit or would fight the merged work.

## Goal

Add four exec-first / usability features to the existing `main` HTML report, fitting the owner's
inline architecture and theme-token system, with zero regression to their `test_report_visual_identity`
suite and the rest of the report tests.

## Scope

### Port (additive)
1. **Security Posture section** — an A–F letter grade + one-line verdict derived from top-risk
   scores, plus a severity-distribution bar. Rendered as a new section near the top.
2. **Since-last-scan delta strip** — "+N new · N regressed · N fixed · N persisting since scan on
   <ts>", from `history.scan_delta` + `history.list_scans`. Hidden on first scan / no history.
3. **Honest findings cap footer** — under the existing grouped findings cards: "Showing the top
   100 findings by severity (N total) — run `cybergraph sarif` or `cybergraph export-json` for the
   complete set." When total ≤ 100: "Showing all N findings."
4. **Print stylesheet** — `@media print` producing a clean PDF (hide nav/toggle/toolbar/graph,
   force light tokens overriding the persisted dark theme, expand collapsed finding groups,
   avoid page breaks inside cards).

### Drop (with rationale)
- **Sortable findings columns** — `main` renders findings as grouped `<details>` cards by rule
  (severity-ordered), not a flat table. Column sort has no home in that structure and the
  by-rule + severity grouping already supersedes it.
- **Asset extraction / `report_sections.py` split** — `main` keeps one inline `_HTML_TEMPLATE`;
  re-extracting would rewrite their merged redesign wholesale for no user-facing benefit and would
  fight `test_report_visual_identity`. New renderers are added as module functions in their
  `visualize.py`, matching their existing `_findings_table`/`_top_risks_table` convention.

## Constraints (Global)

- **Do not regress `main`.** All existing report tests, especially the 14-test
  `test_report_visual_identity` suite, must stay green. Preserve these contracts:
  the 16 CSS token names; the `finding-group`/`data-finding-row`/`data-finding-group` DOM;
  the `risk-card`/`data-risk-jump` strip with no flat risks table; the `_HTML_TEMPLATE`
  placeholder-token list; the `LIMIT 100` vs true `counts()` split; the unified `#cg-search`.
- **Reuse their theme tokens.** All new CSS uses `--panel`/`--border`/`--fg`/`--muted`/`--th`
  etc. — NO new hardcoded light backgrounds (their tests assert this). Severity colors reuse the
  palette already hardcoded in their stylesheet (critical `#dc2626`, high `#d97706`); medium/low/info
  may use `#d97706`/`#2563eb`/`#64748b` for the distribution bar only, as saturated accents (not
  light backgrounds), consistent with how their severity pills/accents already work.
- **`generate_html_report(repo_root, output=None, *, with_source=False) -> Path`** signature unchanged.
- Report stays a single self-contained offline HTML file. All interpolated data HTML-escaped.
  Secret redaction in `--with-source` drill-down must remain intact.
- New renderers added as module functions in `src/cybergraph/visualize.py` (their file), tested via
  `from cybergraph.visualize import ...`.
- Grade scale (inclusive lower bound, highest score drives it): A = no risk ≥40 (or none →
  "No significant risks detected."); B = 40–54; C = 55–69; D = 70–84; E = 85–89; F = ≥90.
- Commits authored as the user only — NO `Co-Authored-By: Claude` trailer. Merge with a merge
  commit or rebase (never squash).

## Design

### New module functions in `visualize.py`
- `_grade(top_risks: list[dict]) -> tuple[str, str]` → `(letter, verdict)`.
- `_severity_bar(counts_by_sev: dict[str, int]) -> str` → segmented bar HTML; zero → "No findings" track.
- `_delta_strip(delta, prev_ts: str | None) -> str` → "" when `delta is None` or `delta.is_first`;
  else the counts strip reading "Since scan on <ts>:" (or "Since last scan:" without a date). No doubled words.
- `_posture_section(counts, top_risks, counts_by_sev, delta_html) -> str` → the section: grade badge
  (letter + verdict), severity bar, and the injected delta strip. Top-3 risk detail already lives in
  their risk-card strip, so posture links to it rather than duplicating cards.
- `_findings_footer(shown: int, total: int) -> str` → the honest cap message.
- `_gather_delta_html(repo_root) -> str` → wraps `history.scan_delta`/`list_scans`; returns "" on any error.

### Composer wiring (`generate_html_report` / `_render_html`)
- Compute a severity distribution over ALL findings: `SELECT severity, COUNT(*) AS n FROM findings
  GROUP BY severity` (inside the open-store block).
- Add template tokens `__POSTURE__` and `__FINDINGS_FOOTER__`; place `__POSTURE__` immediately after
  the stat grid, `__FINDINGS_FOOTER__` immediately after `__FINDINGS_TABLE__`.
- Thread `sev_counts` and `delta_html` through `_render_html`.

### CSS additions (inside the existing inline `<style>`)
- `.badge-grade`, `.sevbar`/`.sevbar-seg`, `.delta-strip`, `.posture` — all using theme tokens.
- `@media print { … }` — the override block MUST target `:root, :root[data-theme="dark"],
  :root[data-theme="light"]` so it beats the persisted dark theme on specificity.

## Error handling & degradation
- History gather wrapped: missing tables / git → delta hidden, never raises.
- Empty risks → grade A + "No significant risks detected."; zero findings → severity bar "No findings".
- `_posture_section`/`_findings_footer` are pure and total; a raising history call cannot abort the report.

## Testing
- New `tests/test_report_reconcile.py`: grade boundaries (A–F + empty→A); severity-bar segments +
  empty; delta-strip hidden cases + counts + date + `"Since since" not in out`; findings footer
  both branches + true total; posture section present with `id="posture"`.
- New print test: `@media print` present and overrides `[data-theme="dark"]`.
- Regression: run the FULL suite incl. `test_report_visual_identity`, `test_report_drilldown*`,
  `test_report_search`, `test_report_theme` — all must stay green. `ruff check --select F src tests` clean.
- Composition: report still self-contained; secret-redaction smoke on the example repo returns nothing.

## Out of scope
Sortable findings, asset extraction, CSV export, raising the 100-cap, any change to the owner's
visual-identity work (neon theme, zones, guided view, risk cards, explainer cards).

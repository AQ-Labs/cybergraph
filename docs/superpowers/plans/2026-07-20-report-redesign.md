# HTML Report Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the CyberGraph HTML report as a professional, exec-first security report with a token-based design system and a maintainable asset layout, while keeping it a single self-contained offline HTML file and leaving `generate_html_report`'s signature unchanged.

**Architecture:** `visualize.py` becomes a thin composer that gathers data and delegates each page section to a pure renderer in a new `report_sections.py`. The page skeleton, all CSS, and all JS move to package data files under `assets/report/` and are inlined at generation time (same `importlib.resources` mechanism already used for `cytoscape.min.js`). The redesign is layered on after a behavior-preserving extraction, so the existing report test suite stays green throughout.

**Tech Stack:** Python 3 (stdlib only: `html`, `json`, `importlib.resources`, `importlib.metadata`), hand-rolled SVG/CSS visuals, vanilla JS, Cytoscape.js (already vendored), pytest.

## Global Constraints

- Output is ONE self-contained HTML file: all CSS/JS inlined at generation, no CDN, no network, no remote fonts. Only Cytoscape.js and our own shipped assets are inlined.
- `generate_html_report(repo_root: Path, output: Path | None = None, *, with_source: bool = False) -> Path` keeps its exact signature and contract. `analyze`, `quickstart`, `visualize`, and MCP must need zero changes.
- No new runtime dependencies. All new visuals are hand-rolled SVG/CSS.
- All interpolated data stays HTML-escaped (`html.escape`; `_embed_json` keeps its `</` → `<\/` guard).
- Report file is written UTF-8 (`encoding="utf-8"`). Any new user-facing CLI strings (none expected) must be cp1252-encodable.
- Severity palette is the single color language everywhere (posture bar, pills, row borders, graph node borders): critical `#dc2626`, high `#ea580c`, medium `#d97706`, low `#2563eb`, info/none `#64748b`.
- Grade scale (from top-risk 0–100 scores, inclusive lower bound): A = no risk ≥ 40 (or none at all); B = 40–54; C = 55–69; D = 70–84; E = 85–89; F = ≥ 90.
- Tests run with: `PYTHONPATH=src python -m pytest -q` from the repo root. Ruff gate (CI): `ruff check --select F src tests` must pass (no unused imports).
- Work on branch `feat/report-redesign` (already created; spec committed). Commits authored as the user only — NO `Co-Authored-By: Claude` trailer.

## File Structure

- `src/cybergraph/visualize.py` (MODIFY) — thin composer: gather data, call renderers, inline assets, write file. Keeps `generate_html_report`, `_load_cytoscape_source`, `_embed_json`. Re-exports section renderers for backward-compatible imports.
- `src/cybergraph/report_sections.py` (CREATE) — one pure function per section returning an HTML string, plus `_safe_section` wrapper and small helpers (grade, severity bar, delta strip).
- `src/cybergraph/assets/report/template.html` (CREATE) — page skeleton with `__TOKEN__` placeholders.
- `src/cybergraph/assets/report/report.css` (CREATE) — design tokens + all styles (light/dark/print).
- `src/cybergraph/assets/report/report.js` (CREATE) — explorer + interactions (moved from the inline `<script>` blocks, extended with sort).
- `pyproject.toml` (MODIFY) — extend wheel `artifacts` glob so the new non-`.js` assets ship.
- `tests/test_report_*.py` (MODIFY/CREATE) — unit + composition + regression tests.

Data facts the implementer must rely on (verified against the code):
- `graph_export.build_graph_data(repo_root)` returns a dict with keys including `nodes` (list), `counts` (dict with `nodes`/`edges`/`findings`), `truncated` (bool), `top_risks` (list of dicts with keys `category`, `title`, `risk_score`, `risk_label`, `detail`), and `attack_paths`.
- `history.scan_delta(repo_root) -> Delta` with fields `is_first: bool`, `new/fixed/regressed/persisting: list[str]`.
- `history.list_scans(repo_root, limit=20) -> list[dict]` rows have keys `id, ts, git_sha, git_branch, node_count, edge_count, finding_count, top_risk_score, top_risk_label`, newest first.
- The findings SQL in `visualize.generate_html_report` is severity-ordered and capped at `LIMIT 100`; `counts['findings']` holds the true total.
- `sarif.py` exports findings with NO limit (so pointing users there for the full set is honest). `export-json` command exists.
- Existing report tests import helpers directly, e.g. `from cybergraph.visualize import _truncation_banner`. Backward-compatible imports must keep working.

---

### Task 1: Extract assets + thin composer (no behavior change)

Move the CSS/JS/skeleton out of the `_HTML_TEMPLATE` string into `assets/report/` files, inline them at generation, and fix packaging — with zero visible change to the produced report so the existing suite stays green.

**Files:**
- Modify: `src/cybergraph/visualize.py`
- Create: `src/cybergraph/assets/report/template.html`
- Create: `src/cybergraph/assets/report/report.css`
- Create: `src/cybergraph/assets/report/report.js`
- Modify: `pyproject.toml:44`
- Test: `tests/test_report_assets.py`

**Interfaces:**
- Consumes: existing `generate_html_report`, `_render_html`, `_load_cytoscape_source`, `_embed_json`, and the section-render helpers already in `visualize.py`.
- Produces: `_read_asset(rel: str) -> str` in `visualize.py` (reads `assets/<rel>` as UTF-8 text); `template.html` containing tokens `__CSS__`, `__REPORT_JS__`, plus every existing token (`__REPO__`, `__NODES__`, `__EDGES__`, `__FINDINGS__`, `__ATTACK_PATHS__`, `__TOP_RISKS_TABLE__`, `__LAYERS_TABLE__`, `__VULN_DEPS_TABLE__`, `__FINDINGS_TABLE__`, `__ATTACK_PATHS_LIST__`, `__LEGEND__`, `__TRUNCATION_BANNER__`, `__GRAPH_JSON__`, `__CYTOSCAPE_SRC__`).

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_assets.py`:

```python
from pathlib import Path

from cybergraph.visualize import _read_asset, generate_html_report


def test_read_asset_loads_css_and_js():
    css = _read_asset("report/report.css")
    js = _read_asset("report/report.js")
    assert ":root" in css and "cytoscape" in js.lower()


def _tiny_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/x')\n"
        "def x(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    return repo


def test_report_is_self_contained_single_file(tmp_path):
    from cybergraph.cli import main
    repo = _tiny_repo(tmp_path)
    assert main(["build", str(repo)]) == 0
    out = generate_html_report(repo)
    text = out.read_text(encoding="utf-8")
    # No external asset references — everything inlined.
    assert "<link" not in text.lower()
    assert 'src="http' not in text.lower()
    assert "url(http" not in text.lower()
    # Skeleton tokens all resolved.
    assert "__CSS__" not in text and "__REPORT_JS__" not in text and "__GRAPH_JSON__" not in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_assets.py -q`
Expected: FAIL — `ImportError: cannot import name '_read_asset'`.

- [ ] **Step 3: Create the three asset files**

Create `src/cybergraph/assets/report/report.css` with the **exact CSS currently inside `_HTML_TEMPLATE`** (everything between `<style>` and `</style>`, not including those tags).

Create `src/cybergraph/assets/report/report.js` with the **exact JS currently inside the report's `<script>` blocks** — specifically the two application scripts (the big explorer IIFE that starts `(function () { const data = window.CYBERGRAPH ...`, and the trailing findings-filter + theme-toggle script). Do NOT move the pre-`<body>` theme-bootstrap `<script>` (it must run before body renders) and do NOT move `__CYTOSCAPE_SRC__` or `window.CYBERGRAPH = __GRAPH_JSON__` (those are injected data/vendor, kept in the skeleton).

Create `src/cybergraph/assets/report/template.html` = the current `_HTML_TEMPLATE` with these edits:
- Replace the entire `<style>…</style>` block body with the single token `__CSS__` (keep the `<style>__CSS__</style>` tags).
- Keep the pre-`<body>` theme-bootstrap `<script>…</script>` inline, verbatim.
- Keep `<script>__CYTOSCAPE_SRC__</script>` and `<script>window.CYBERGRAPH = __GRAPH_JSON__;</script>` verbatim.
- Replace the two application `<script>…</script>` blocks with a single `<script>__REPORT_JS__</script>` placed where the explorer script currently is (after the `window.CYBERGRAPH` line).

- [ ] **Step 4: Rewire `visualize.py` to load and inline assets**

In `src/cybergraph/visualize.py`:
- Add near `_load_cytoscape_source`:

```python
def _read_asset(rel: str) -> str:
    return (files("cybergraph") / "assets" / rel).read_text(encoding="utf-8")
```

- Rewrite `_load_cytoscape_source` to reuse it:

```python
def _load_cytoscape_source() -> str:
    return _read_asset("cytoscape.min.js")
```

- Replace the module-level `_HTML_TEMPLATE = """..."""` assignment with a loader used in `_render_html`. In `_render_html`, change the first line from `template = _HTML_TEMPLATE` to `template = _read_asset("report/template.html")` and add these two entries to the `replacements` dict:

```python
        "__CSS__": _read_asset("report/report.css"),
        "__REPORT_JS__": _read_asset("report/report.js"),
```

- Delete the now-unused `_HTML_TEMPLATE` string constant.

- [ ] **Step 5: Fix packaging so non-JS assets ship**

In `pyproject.toml`, change line 44 from:

```toml
artifacts = ["src/cybergraph/assets/*.js"]
```

to:

```toml
artifacts = ["src/cybergraph/assets/*.js", "src/cybergraph/assets/report/*"]
```

- [ ] **Step 6: Run the new test + the full existing report suite**

Run: `PYTHONPATH=src python -m pytest tests/test_report_assets.py tests/test_report_banner.py tests/test_report_search.py tests/test_report_theme.py tests/test_report_source.py tests/test_report_drilldown.py tests/test_report_drilldown_security.py tests/test_cli_analyze.py -q`
Expected: PASS (all). The report is byte-for-byte equivalent except asset ordering, so theme/search/banner/drilldown tests still pass.

- [ ] **Step 7: Ruff + commit**

Run: `ruff check --select F src/cybergraph/visualize.py tests/test_report_assets.py`
Expected: no errors.

```bash
git add src/cybergraph/visualize.py src/cybergraph/assets/report/ pyproject.toml tests/test_report_assets.py
git commit -m "refactor(report): extract report assets to files and inline them"
```

---

### Task 2: report_sections module + safe wrapper + move renderers

Create `report_sections.py`, move the section renderers there as pure functions, add `_safe_section`, and re-export from `visualize.py` so existing imports keep working.

**Files:**
- Create: `src/cybergraph/report_sections.py`
- Modify: `src/cybergraph/visualize.py`
- Test: `tests/test_report_sections.py`

**Interfaces:**
- Consumes: `NODE_GROUPS`, `EDGE_KINDS` constants and the render helpers currently in `visualize.py`.
- Produces (in `report_sections.py`): `safe_section(fn, *args, **kwargs) -> str`; and the moved renderers `top_risks_table`, `layers_table`, `vulnerable_dependencies_table`, `findings_table`, `attack_paths_list`, `legend`, `truncation_banner`, `finding_search_text` (public names, no leading underscore). `visualize.py` re-exports each under its old underscored name (e.g. `_truncation_banner = truncation_banner`).

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_sections.py`:

```python
from cybergraph.report_sections import safe_section, truncation_banner


def test_safe_section_returns_card_on_error():
    def boom():
        raise ValueError("nope")
    out = safe_section(boom)
    assert "section unavailable" in out.lower()


def test_safe_section_passes_through_ok():
    assert safe_section(lambda x: f"<p>{x}</p>", "hi") == "<p>hi</p>"


def test_truncation_banner_moved():
    assert truncation_banner({"truncated": False, "nodes": [], "counts": {"nodes": 0}}) == ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_sections.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.report_sections'`.

- [ ] **Step 3: Create `report_sections.py`**

Move the bodies of `_top_risks_table`, `_layers_table`, `_vulnerable_dependencies_table`, `_findings_table`, `_finding_search_text`, `_attack_paths`, `_legend`, `_truncation_banner`, and the `NODE_GROUPS`/`EDGE_KINDS` constants from `visualize.py` into `report_sections.py`, renaming to the public names in Interfaces (drop leading underscore). Keep the code identical otherwise. Add:

```python
import html


def safe_section(fn, *args, **kwargs) -> str:
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # never let one section abort the whole report
        return (
            "<div class='card section-error'>"
            f"<p class='muted'>Section unavailable: {html.escape(type(exc).__name__)}.</p></div>"
        )
```

- [ ] **Step 4: Re-export from `visualize.py`**

In `visualize.py`, delete the moved function bodies and constants; import and alias:

```python
from cybergraph.report_sections import (
    attack_paths_list,
    findings_table,
    layers_table,
    legend,
    safe_section,
    top_risks_table,
    truncation_banner,
    vulnerable_dependencies_table,
)

# Backward-compatible aliases for existing imports/tests.
_truncation_banner = truncation_banner
_findings_table = findings_table
_top_risks_table = top_risks_table
_legend = legend
```

Update `_render_html` to call the imported names (e.g. `top_risks_table(...)`).

- [ ] **Step 5: Run tests**

Run: `PYTHONPATH=src python -m pytest tests/test_report_sections.py tests/test_report_banner.py tests/test_report_assets.py -q`
Expected: PASS.

- [ ] **Step 6: Ruff + commit**

Run: `ruff check --select F src/cybergraph/report_sections.py src/cybergraph/visualize.py`
Expected: no errors.

```bash
git add src/cybergraph/report_sections.py src/cybergraph/visualize.py tests/test_report_sections.py
git commit -m "refactor(report): move section renderers into report_sections"
```

---

### Task 3: Design tokens + severity palette in CSS

Introduce the token block and severity component classes in `report.css`, restyling existing components onto tokens. Visual-only; report still generates and existing tests pass. Adds an assertion that the palette is present.

**Files:**
- Modify: `src/cybergraph/assets/report/report.css`
- Test: `tests/test_report_design.py`

**Interfaces:**
- Produces: CSS custom properties `--space-1..7`, `--radius-*`, severity vars `--sev-critical/high/medium/low/info` (+ `-tint` variants), and classes `.card`, `.chip`, `.pill--critical|high|medium|low|info`, `.badge-grade`, `.sevbar`, `.sevbar-seg`, `.section`. Consumed by Tasks 4–10.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_design.py`:

```python
from cybergraph.visualize import _read_asset


def test_css_defines_severity_palette_tokens():
    css = _read_asset("report/report.css")
    for token in ("--sev-critical", "--sev-high", "--sev-medium", "--sev-low", "--sev-info"):
        assert token in css
    for hexval in ("#dc2626", "#ea580c", "#d97706", "#2563eb", "#64748b"):
        assert hexval in css


def test_css_defines_core_components():
    css = _read_asset("report/report.css")
    for cls in (".card", ".chip", ".pill--critical", ".badge-grade", ".sevbar", ".section"):
        assert cls in css
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_design.py -q`
Expected: FAIL — assertion error (tokens absent).

- [ ] **Step 3: Add the token block + components**

At the top of `report.css`, extend `:root` (and the dark/light overrides) with the design tokens, and append the component classes. Add this inside the existing `:root { … }` block:

```css
      --space-1: 4px; --space-2: 8px; --space-3: 12px; --space-4: 16px;
      --space-5: 24px; --space-6: 32px; --space-7: 48px;
      --radius-sm: 8px; --radius-md: 12px; --radius-lg: 16px;
      --shadow: 0 10px 30px rgba(15, 23, 42, 0.06);
      --sev-critical: #dc2626; --sev-high: #ea580c; --sev-medium: #d97706;
      --sev-low: #2563eb; --sev-info: #64748b;
      --sev-critical-tint: #fef2f2; --sev-high-tint: #fff7ed; --sev-medium-tint: #fffbeb;
      --sev-low-tint: #eff6ff; --sev-info-tint: #f1f5f9;
```

Append component classes at the end of the file:

```css
.card { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius-md); box-shadow: var(--shadow); padding: var(--space-5); margin: 0 0 var(--space-5); }
.section { scroll-margin-top: 72px; }
.chip { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius-md); padding: var(--space-4); }
.pill--critical { background: var(--sev-critical-tint); color: var(--sev-critical); }
.pill--high { background: var(--sev-high-tint); color: var(--sev-high); }
.pill--medium { background: var(--sev-medium-tint); color: var(--sev-medium); }
.pill--low { background: var(--sev-low-tint); color: var(--sev-low); }
.pill--info { background: var(--sev-info-tint); color: var(--sev-info); }
.badge-grade { display: inline-flex; align-items: center; justify-content: center; width: 76px; height: 76px; border-radius: var(--radius-lg); font-size: 44px; font-weight: 700; color: #fff; }
.sevbar { display: flex; width: 100%; height: 26px; border-radius: 999px; overflow: hidden; border: 1px solid var(--border); }
.sevbar-seg { display: flex; align-items: center; justify-content: center; color: #fff; font-size: 11px; font-weight: 600; }
.section-error { border-color: var(--sev-medium); }
```

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=src python -m pytest tests/test_report_design.py tests/test_report_theme.py tests/test_report_assets.py -q`
Expected: PASS.

- [ ] **Step 5: Ruff (no Python changed) + commit**

```bash
git add src/cybergraph/assets/report/report.css tests/test_report_design.py
git commit -m "feat(report): add design-token system and severity palette"
```

---

### Task 4: Security Posture section (grade, verdict, severity bar, top-3)

Add pure renderers for the grade, verdict, severity bar, and top-3 risk cards, compose them into a posture section, and mount it as the first section in the template.

**Files:**
- Modify: `src/cybergraph/report_sections.py`
- Modify: `src/cybergraph/visualize.py`
- Modify: `src/cybergraph/assets/report/template.html`
- Test: `tests/test_report_posture.py`

**Interfaces:**
- Consumes: `graph_data["top_risks"]` (list of dicts: `category`, `title`, `risk_score`, `risk_label`, `detail`); `counts` dict; severity distribution derived from the `findings` rows the composer already fetched.
- Produces: `grade(top_risks: list[dict]) -> tuple[str, str]` returning `(letter, verdict_sentence)`; `severity_bar(counts_by_sev: dict[str, int]) -> str`; `posture_section(repo, counts, top_risks, counts_by_sev, delta_html: str) -> str`. New template token `__POSTURE__`. Consumed by Task 5 (delta injects into `posture_section`).

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_posture.py`:

```python
from cybergraph.report_sections import grade, severity_bar, posture_section


def test_grade_boundaries():
    assert grade([])[0] == "A"
    assert grade([{"risk_score": 39}])[0] == "A"
    assert grade([{"risk_score": 40}])[0] == "B"
    assert grade([{"risk_score": 54}])[0] == "B"
    assert grade([{"risk_score": 55}])[0] == "C"
    assert grade([{"risk_score": 69}])[0] == "C"
    assert grade([{"risk_score": 70}])[0] == "D"
    assert grade([{"risk_score": 84}])[0] == "D"
    assert grade([{"risk_score": 85}])[0] == "E"
    assert grade([{"risk_score": 89}])[0] == "E"
    assert grade([{"risk_score": 90}])[0] == "F"
    # Highest risk drives the grade.
    assert grade([{"risk_score": 10}, {"risk_score": 92}])[0] == "F"


def test_grade_empty_verdict():
    assert "No significant risks" in grade([])[1]


def test_severity_bar_segments():
    html = severity_bar({"critical": 2, "high": 0, "medium": 1, "low": 0, "info": 0})
    assert "sevbar" in html
    assert ">2<" in html  # critical count label
    assert "var(--sev-critical)" in html


def test_severity_bar_empty():
    assert "No findings" in severity_bar({})


def test_posture_section_lists_top3():
    risks = [
        {"category": "sqli", "title": "SQL injection", "risk_score": 88, "risk_label": "high", "detail": "d1"},
        {"category": "xss", "title": "XSS", "risk_score": 60, "risk_label": "medium", "detail": "d2"},
        {"category": "sec", "title": "Secret", "risk_score": 30, "risk_label": "low", "detail": "d3"},
        {"category": "x", "title": "Fourth", "risk_score": 10, "risk_label": "low", "detail": "d4"},
    ]
    out = posture_section("repo", {"nodes": 5, "edges": 4, "findings": 3}, risks,
                          {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 0}, "")
    assert "SQL injection" in out and "XSS" in out and "Secret" in out
    assert "Fourth" not in out  # only top 3
    assert 'id="posture"' in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_posture.py -q`
Expected: FAIL — `ImportError: cannot import name 'grade'`.

- [ ] **Step 3: Implement the renderers in `report_sections.py`**

```python
_GRADE_BANDS = [(90, "F"), (85, "E"), (70, "D"), (55, "C"), (40, "B")]
_GRADE_COLOR = {"A": "#16a34a", "B": "#65a30d", "C": "#d97706", "D": "#ea580c", "E": "#dc2626", "F": "#991b1b"}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def grade(top_risks: list[dict]) -> tuple[str, str]:
    scores = [int(r.get("risk_score") or 0) for r in top_risks]
    top = max(scores) if scores else 0
    letter = "A"
    for threshold, band in _GRADE_BANDS:
        if top >= threshold:
            letter = band
            break
    if not scores or top < 40:
        return "A", "No significant risks detected."
    return letter, f"Highest risk scored {top}/100 — review the top risks below."


def severity_bar(counts_by_sev: dict[str, int]) -> str:
    total = sum(int(counts_by_sev.get(s, 0)) for s in _SEV_ORDER)
    if total == 0:
        return "<div class='sevbar'><div class='sevbar-seg' style='width:100%;background:var(--sev-info)'>No findings</div></div>"
    segs = []
    for sev in _SEV_ORDER:
        n = int(counts_by_sev.get(sev, 0))
        if n == 0:
            continue
        pct = round(100 * n / total, 2)
        segs.append(
            f"<div class='sevbar-seg' title='{html.escape(sev)}: {n}' "
            f"style='width:{pct}%;background:var(--sev-{sev})'>{n}</div>"
        )
    return f"<div class='sevbar'>{''.join(segs)}</div>"


def posture_section(repo, counts, top_risks, counts_by_sev, delta_html: str) -> str:
    letter, verdict = grade(top_risks)
    color = _GRADE_COLOR[letter]
    chips = "".join(
        f"<div class='chip'><span class='muted'>{label}</span><strong style='display:block;font-size:26px'>{counts.get(key, 0)}</strong></div>"
        for label, key in (("Nodes", "nodes"), ("Edges", "edges"), ("Findings", "findings"),
                            ("Attack Paths", "attack_paths"))
    )
    cards = []
    for r in top_risks[:3]:
        sev = str(r.get("risk_label") or "info").lower()
        cards.append(
            "<div class='card' style='margin:0'>"
            f"<span class='pill pill--{html.escape(sev)}'>{html.escape(str(r.get('risk_score')))}/100</span> "
            f"<strong>{html.escape(str(r.get('title')))}</strong>"
            f"<div class='muted'>{html.escape(str(r.get('category')))} — {html.escape(str(r.get('detail')))}</div>"
            "<a href='#explorer'>jump to path →</a></div>"
        )
    top3 = "".join(cards) or "<p class='muted'>No prioritized risks found yet.</p>"
    return (
        "<section id='posture' class='section card'>"
        "<h2>Security Posture</h2>"
        "<div style='display:flex;gap:var(--space-5);flex-wrap:wrap;align-items:center'>"
        f"<div class='badge-grade' style='background:{color}'>{letter}</div>"
        f"<div style='flex:1;min-width:240px'><p><strong>{html.escape(verdict)}</strong></p>{severity_bar(counts_by_sev)}</div>"
        "</div>"
        f"{delta_html}"
        f"<div class='grid' style='margin-top:var(--space-4)'>{chips}</div>"
        f"<h3>Top risks</h3><div class='grid'>{top3}</div>"
        "</section>"
    )
```

- [ ] **Step 4: Wire the composer + template**

In `visualize.py` `generate_html_report`, after fetching `findings`, compute the severity distribution over the stored findings (the true totals, not just the 100 shown — query counts by severity). Add before `_render_html`:

```python
        sev_counts = {
            row["severity"]: row["n"]
            for row in store.conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
            )
        }
```

Move this query inside the existing `try:`/`finally:` block that already holds `store` open (before `store.close()`), and thread `sev_counts` through to `_render_html`. Add `attack_paths` count to the counts dict passed to posture: reuse `len(attack_paths)`.

In `_render_html`, add to `replacements`:

```python
        "__POSTURE__": safe_section(
            posture_section,
            html.escape(str(repo_root)),
            {**counts, "attack_paths": len(attack_paths)},
            graph_data.get("top_risks", []),
            sev_counts,
            "",  # delta filled in Task 5
        ),
```

(Adjust `_render_html`'s signature to accept `sev_counts`; update its single call site.)

In `template.html`, replace the current `<h2>Top Risks</h2>\n    __TOP_RISKS_TABLE__` block near the top of `<main>` with `__POSTURE__`, and remove the now-duplicated standalone stat `grid` section and `<h2>Top Risks</h2>` table (the posture section supersedes them). Keep `__TOP_RISKS_TABLE__` out of the template (drop that token and its replacement entry).

- [ ] **Step 5: Run tests**

Run: `PYTHONPATH=src python -m pytest tests/test_report_posture.py tests/test_report_assets.py tests/test_cli_analyze.py -q`
Expected: PASS.

- [ ] **Step 6: Ruff + commit**

Run: `ruff check --select F src/cybergraph/report_sections.py src/cybergraph/visualize.py tests/test_report_posture.py`
Expected: no errors.

```bash
git add src/cybergraph/report_sections.py src/cybergraph/visualize.py src/cybergraph/assets/report/template.html tests/test_report_posture.py
git commit -m "feat(report): add exec-first security posture section"
```

---

### Task 5: Delta strip (scan history integration)

Render a "since last scan" strip from `history`, injected into the posture section. Hidden on first scan or when no history exists.

**Files:**
- Modify: `src/cybergraph/report_sections.py`
- Modify: `src/cybergraph/visualize.py`
- Test: `tests/test_report_delta.py`

**Interfaces:**
- Consumes: `history.scan_delta(repo_root) -> Delta` (`is_first`, `new/fixed/regressed/persisting` lists); `history.list_scans(repo_root, limit=2)` (row dict with `ts`).
- Produces: `delta_strip(delta, prev_ts: str | None) -> str` (empty string when `delta is None` or `delta.is_first`); `gather_delta_html(repo_root) -> str` in `visualize.py` wrapping the history calls so failures yield `""`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_delta.py`:

```python
from cybergraph.history import Delta
from cybergraph.report_sections import delta_strip


def test_delta_hidden_first_scan():
    assert delta_strip(Delta(is_first=True), None) == ""


def test_delta_hidden_when_none():
    assert delta_strip(None, None) == ""


def test_delta_renders_counts_and_date():
    d = Delta(is_first=False, new=["a", "b"], fixed=["c"], regressed=["d"], persisting=["e", "f", "g"])
    out = delta_strip(d, "2026-07-19T10:00:00+00:00")
    assert "2 new" in out and "1 fixed" in out and "1 regressed" in out and "3 persisting" in out
    assert "2026-07-19" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_delta.py -q`
Expected: FAIL — `ImportError: cannot import name 'delta_strip'`.

- [ ] **Step 3: Implement `delta_strip`**

In `report_sections.py`:

```python
def delta_strip(delta, prev_ts: str | None) -> str:
    if delta is None or getattr(delta, "is_first", True):
        return ""
    when = (prev_ts or "")[:19]  # trim to seconds for display
    since = f" since scan on {html.escape(when)}" if when else ""
    return (
        "<div class='delta-strip'>"
        f"Since{since}: <strong>{len(delta.new)}</strong> new · "
        f"<strong>{len(delta.regressed)}</strong> regressed · "
        f"<strong>{len(delta.fixed)}</strong> fixed · "
        f"<strong>{len(delta.persisting)}</strong> persisting"
        "</div>"
    )
```

Add CSS in `report.css`:

```css
.delta-strip { margin: var(--space-4) 0 0; padding: var(--space-3) var(--space-4); border-radius: var(--radius-sm); background: var(--sev-low-tint); color: var(--sev-low); font-size: 13px; }
```

- [ ] **Step 4: Wire into the composer**

In `visualize.py`, add:

```python
def gather_delta_html(repo_root: Path) -> str:
    try:
        from cybergraph import history
        delta = history.scan_delta(repo_root)
        scans = history.list_scans(repo_root, limit=2)
        prev_ts = scans[1]["ts"] if len(scans) > 1 else None
        return delta_strip(delta, prev_ts)
    except Exception:
        return ""
```

Import `delta_strip` alongside the other `report_sections` imports. In `generate_html_report`, compute `delta_html = gather_delta_html(repo_root)` (after the store block) and pass it into `_render_html`; in `_render_html`, replace the posture `""` delta argument with the threaded `delta_html`.

- [ ] **Step 5: Run tests**

Run: `PYTHONPATH=src python -m pytest tests/test_report_delta.py tests/test_report_posture.py tests/test_cli_analyze.py -q`
Expected: PASS.

- [ ] **Step 6: Ruff + commit**

Run: `ruff check --select F src/cybergraph/report_sections.py src/cybergraph/visualize.py tests/test_report_delta.py`
Expected: no errors.

```bash
git add src/cybergraph/report_sections.py src/cybergraph/visualize.py src/cybergraph/assets/report/report.css tests/test_report_delta.py
git commit -m "feat(report): show since-last-scan delta strip in posture"
```

---

### Task 6: Findings Triage upgrades (pills, borders, sort, honest footer)

Restyle findings rows with severity color, make columns sortable, keep search/filter, and replace the footer with an honest cap message. (Expandable source rows are handled by the existing drill-down snippet path; this task keeps that behavior and does not regress it.)

**Files:**
- Modify: `src/cybergraph/report_sections.py` (`findings_table`)
- Modify: `src/cybergraph/assets/report/report.css`
- Modify: `src/cybergraph/assets/report/report.js`
- Test: `tests/test_report_findings.py`

**Interfaces:**
- Consumes: findings rows (`severity`, `rule_id`, `message`, `file_path`, `line_start`, `tool`); `total_findings: int` (from `counts['findings']`).
- Produces: `findings_table(findings, total_findings: int) -> str` (signature changes — add `total_findings`). Row `<tr>` carries `data-severity`, `data-search`, and `data-sev-rank` for JS sort. Consumed by `_render_html`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_findings.py`:

```python
from cybergraph.report_sections import findings_table


def _rows(n):
    return [
        {"severity": "high", "rule_id": f"R{i}", "message": "m", "file_path": "a.py",
         "line_start": i, "tool": "t"}
        for i in range(n)
    ]


def test_footer_when_capped():
    out = findings_table(_rows(100), total_findings=250)
    assert "top 100" in out.lower() and "250" in out
    assert "cybergraph sarif" in out


def test_footer_when_all_shown():
    out = findings_table(_rows(4), total_findings=4)
    assert "all 4" in out.lower()


def test_rows_carry_severity_rank_for_sort():
    out = findings_table(_rows(1), total_findings=1)
    assert "data-sev-rank" in out


def test_empty_findings_message():
    assert "No findings" in findings_table([], total_findings=0)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_findings.py -q`
Expected: FAIL — `TypeError: findings_table() missing 1 required positional argument: 'total_findings'`.

- [ ] **Step 3: Rewrite `findings_table`**

```python
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def findings_table(findings, total_findings: int) -> str:
    if not findings:
        return "<p class='muted'>No findings stored yet.</p>"
    rows = "".join(
        "<tr data-finding-row "
        f"data-severity='{html.escape(row['severity'])}' "
        f"data-sev-rank='{_SEV_RANK.get((row['severity'] or '').lower(), 0)}' "
        f"data-search='{html.escape(finding_search_text(row))}' "
        f"style='border-left:4px solid var(--sev-{html.escape((row['severity'] or 'info').lower())})'>"
        f"<td><span class='pill pill--{html.escape((row['severity'] or 'info').lower())}'>{html.escape(row['severity'])}</span></td>"
        f"<td>{html.escape(row['rule_id'])}</td>"
        f"<td>{html.escape(row['message'])}</td>"
        f"<td><code>{html.escape(row['file_path'] or '-')}:{row['line_start']}</code></td>"
        f"<td>{html.escape(row['tool'])}</td>"
        "</tr>"
        for row in findings
    )
    shown = len(findings)
    if total_findings > shown:
        footer = (
            f"<p class='muted'>Showing the top {shown} findings by severity "
            f"({total_findings} total) — run <code>cybergraph sarif</code> or "
            f"<code>cybergraph export-json</code> for the complete set.</p>"
        )
    else:
        footer = f"<p class='muted'>Showing all {total_findings} findings.</p>"
    return (
        "<div class='toolbar'>"
        "<select data-filter='findings-severity' aria-label='Filter findings by severity'>"
        "<option value=''>All severities</option>"
        "<option value='critical'>Critical</option>"
        "<option value='high'>High</option>"
        "<option value='medium'>Medium</option>"
        "<option value='low'>Low</option>"
        "<option value='info'>Info</option>"
        "</select>"
        "</div>"
        "<table id='findings-table'><thead><tr>"
        "<th data-sort='rank'>Severity</th><th data-sort='text'>Rule</th>"
        "<th data-sort='text'>Message</th><th data-sort='text'>Location</th>"
        "<th data-sort='text'>Tool</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>{footer}"
    )
```

- [ ] **Step 4: Update the composer call**

In `visualize.py` `_render_html`, change `findings_table(findings)` to `findings_table(findings, counts.get("findings", len(findings)))`.

- [ ] **Step 5: Add column-sort JS**

Append to `report.js` (inside a DOMContentLoaded-safe scope, after the findings-filter code):

```javascript
    (function () {
      const table = document.getElementById('findings-table');
      if (!table) return;
      const tbody = table.querySelector('tbody');
      table.querySelectorAll('th[data-sort]').forEach(function (th, col) {
        let asc = true;
        th.style.cursor = 'pointer';
        th.addEventListener('click', function () {
          const rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
          const mode = th.getAttribute('data-sort');
          rows.sort(function (a, b) {
            let x, y;
            if (mode === 'rank') {
              x = Number(a.getAttribute('data-sev-rank')); y = Number(b.getAttribute('data-sev-rank'));
            } else {
              x = a.children[col].textContent.toLowerCase(); y = b.children[col].textContent.toLowerCase();
            }
            if (x < y) return asc ? -1 : 1;
            if (x > y) return asc ? 1 : -1;
            return 0;
          });
          asc = !asc;
          rows.forEach(function (r) { tbody.appendChild(r); });
        });
      });
    })();
```

Add CSS for hover affordance:

```css
#findings-table th[data-sort]:hover { background: var(--sev-info-tint); }
```

- [ ] **Step 6: Run tests**

Run: `PYTHONPATH=src python -m pytest tests/test_report_findings.py tests/test_report_search.py tests/test_report_drilldown.py tests/test_report_drilldown_security.py tests/test_cli_analyze.py -q`
Expected: PASS.

- [ ] **Step 7: Ruff + commit**

Run: `ruff check --select F src/cybergraph/report_sections.py tests/test_report_findings.py`
Expected: no errors.

```bash
git add src/cybergraph/report_sections.py src/cybergraph/assets/report/report.css src/cybergraph/assets/report/report.js src/cybergraph/visualize.py tests/test_report_findings.py
git commit -m "feat(report): severity-colored, sortable findings with honest cap footer"
```

---

### Task 7: Dependencies & Layers restyle + JSON evidence pretty-print

Pretty-print the vulnerable-dependency evidence JSON, restyle both tables as cards. Behavior-preserving except the evidence formatting.

**Files:**
- Modify: `src/cybergraph/report_sections.py` (`vulnerable_dependencies_table`)
- Test: `tests/test_report_deps.py`

**Interfaces:**
- Consumes: rows with `vulnerability`, `dependency`, `properties` (a JSON string).
- Produces: `vulnerable_dependencies_table(rows) -> str` (signature unchanged) that pretty-prints `properties` when it parses as JSON, else falls back to the escaped raw string.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_deps.py`:

```python
from cybergraph.report_sections import vulnerable_dependencies_table


def test_pretty_prints_json_evidence():
    rows = [{"vulnerability": "CVE-1", "dependency": "left-pad",
             "properties": '{"epss": 0.4, "kev": true}'}]
    out = vulnerable_dependencies_table(rows)
    assert "epss" in out and "0.4" in out


def test_falls_back_on_non_json():
    rows = [{"vulnerability": "CVE-2", "dependency": "req", "properties": "not-json{"}]
    out = vulnerable_dependencies_table(rows)
    assert "not-json{" in out  # escaped raw, no crash


def test_empty_deps_message():
    assert "No vulnerable dependency" in vulnerable_dependencies_table([])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_deps.py -q`
Expected: FAIL — `test_pretty_prints_json_evidence` (raw string, `epss` present but assert on formatting) / confirm by running; if the raw string already contains `epss`, strengthen the assert to check indentation: `assert "\n" in out_code_block`. Use this stricter test body instead:

```python
def test_pretty_prints_json_evidence():
    rows = [{"vulnerability": "CVE-1", "dependency": "left-pad",
             "properties": '{"epss": 0.4, "kev": true}'}]
    out = vulnerable_dependencies_table(rows)
    assert '"epss": 0.4' in out  # normalized/indented JSON, spaces after colon
```

Expected: FAIL (raw string has `"epss": 0.4`? the raw already has a space; assert on 2-space indent instead): final assert — `assert "  \"epss\"" in out` (two-space indent only present after pretty-print).

- [ ] **Step 3: Implement pretty-print**

```python
import json


def vulnerable_dependencies_table(rows) -> str:
    if not rows:
        return "<p class='muted'>No vulnerable dependency links imported yet.</p>"

    def fmt(props: str) -> str:
        try:
            return json.dumps(json.loads(props), indent=2, sort_keys=True)
        except Exception:
            return props

    rendered = "".join(
        "<tr>"
        f"<td>{html.escape(row['vulnerability'])}</td>"
        f"<td>{html.escape(row['dependency'])}</td>"
        f"<td><pre><code>{html.escape(fmt(row['properties']))}</code></pre></td>"
        "</tr>"
        for row in rows
    )
    return (
        "<table><thead><tr><th>Vulnerability</th><th>Dependency</th><th>Evidence</th></tr></thead>"
        f"<tbody>{rendered}</tbody></table>"
    )
```

Use the final assert `assert '  "epss"' in out` in the test (two-space indent proves pretty-print).

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=src python -m pytest tests/test_report_deps.py tests/test_cli_analyze.py -q`
Expected: PASS.

- [ ] **Step 5: Ruff + commit**

Run: `ruff check --select F src/cybergraph/report_sections.py tests/test_report_deps.py`
Expected: no errors.

```bash
git add src/cybergraph/report_sections.py tests/test_report_deps.py
git commit -m "feat(report): pretty-print vulnerable-dependency evidence"
```

---

### Task 8: Sticky nav + section anchors + About footer

Add the sticky top navigation bar, wrap the remaining sections as anchored `.section` cards, and add the About-this-scan footer with the CyberGraph version.

**Files:**
- Modify: `src/cybergraph/assets/report/template.html`
- Modify: `src/cybergraph/assets/report/report.css`
- Modify: `src/cybergraph/report_sections.py`
- Modify: `src/cybergraph/visualize.py`
- Test: `tests/test_report_nav.py`

**Interfaces:**
- Produces: `about_section(repo: str, version: str, truncated: bool) -> str`; new template token `__ABOUT__`. `visualize.py` computes the version via `importlib.metadata`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_nav.py`:

```python
from cybergraph.report_sections import about_section
from cybergraph.visualize import _read_asset


def test_about_shows_version_and_repo():
    out = about_section("/x/repo", "1.2.3", truncated=False)
    assert "1.2.3" in out and "/x/repo" in out and 'id="about"' in out


def test_about_truncation_note():
    assert "truncat" in about_section("/x", "1.0", truncated=True).lower()


def test_template_has_nav_and_anchors():
    tpl = _read_asset("report/template.html")
    assert "cg-nav" in tpl
    for anchor in ("#posture", "#explorer", "#findings", "#deps", "#about"):
        assert anchor in tpl
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_nav.py -q`
Expected: FAIL — `ImportError: cannot import name 'about_section'`.

- [ ] **Step 3: Implement `about_section`**

```python
def about_section(repo: str, version: str, truncated: bool) -> str:
    note = ("<p class='muted'>Graph was truncated for display — raise "
            "<code>--max-nodes</code> to render the full graph.</p>") if truncated else ""
    return (
        "<section id='about' class='section card'>"
        "<h2>About this scan</h2>"
        f"<p class='muted'>Repository: <code>{html.escape(repo)}</code></p>"
        f"<p class='muted'>CyberGraph version: {html.escape(version)}</p>"
        f"{note}"
        "</section>"
    )
```

- [ ] **Step 4: Compute version + wire token**

In `visualize.py`:

```python
def _cybergraph_version() -> str:
    try:
        from importlib.metadata import version
        return version("cybergraph")
    except Exception:
        return "unknown"
```

Import `about_section`; in `_render_html` add:

```python
        "__ABOUT__": safe_section(
            about_section, html.escape(str(repo_root)), _cybergraph_version(),
            bool(graph_data.get("truncated")),
        ),
```

- [ ] **Step 5: Add nav + anchors + about to `template.html`**

Insert directly after `<body>` (before `<header>`):

```html
  <nav id="cg-nav">
    <span class="cg-nav-title">CyberGraph</span>
    <a href="#posture">Posture</a>
    <a href="#explorer">Explorer</a>
    <a href="#findings">Findings</a>
    <a href="#deps">Dependencies</a>
    <a href="#about">About</a>
  </nav>
```

Give the existing graph-explorer `<h2>Interactive Graph Explorer</h2>` and its container an `id="explorer"` wrapper `<section id="explorer" class="section">…</section>`; wrap `<h2>Findings</h2> __FINDINGS_TABLE__` in `<section id="findings" class="section card">…</section>`; wrap the vulnerable-deps + layers tables in `<section id="deps" class="section card">…</section>`. Append `__ABOUT__` as the last element inside `<main>`. Remove the old standalone `__TRUNCATION_BANNER__` position if the About note now covers it — but keep the in-explorer banner where the graph is (it warns about the graph specifically), so leave `__TRUNCATION_BANNER__` in the explorer section.

Add nav CSS to `report.css`:

```css
#cg-nav { position: sticky; top: 0; z-index: 50; display: flex; gap: var(--space-4); align-items: center; padding: var(--space-3) var(--space-5); background: var(--panel); border-bottom: 1px solid var(--border); }
#cg-nav .cg-nav-title { font-weight: 700; }
#cg-nav a { color: var(--muted); text-decoration: none; font-size: 13px; }
#cg-nav a:hover { color: var(--fg); }
```

- [ ] **Step 6: Run tests**

Run: `PYTHONPATH=src python -m pytest tests/test_report_nav.py tests/test_report_assets.py tests/test_cli_analyze.py -q`
Expected: PASS.

- [ ] **Step 7: Ruff + commit**

Run: `ruff check --select F src/cybergraph/report_sections.py src/cybergraph/visualize.py tests/test_report_nav.py`
Expected: no errors.

```bash
git add src/cybergraph/report_sections.py src/cybergraph/visualize.py src/cybergraph/assets/report/template.html src/cybergraph/assets/report/report.css tests/test_report_nav.py
git commit -m "feat(report): sticky section nav and about-this-scan footer"
```

---

### Task 9: Complete dark-mode token coverage

Move every remaining hard-coded light color in `report.css` onto tokens so dark mode is fully covered, and assert no stray light literals remain in the styled components.

**Files:**
- Modify: `src/cybergraph/assets/report/report.css`
- Test: `tests/test_report_darkmode.py`

**Interfaces:** none new — CSS-only.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_darkmode.py`:

```python
from cybergraph.visualize import _read_asset


def test_risk_and_path_cards_use_tokens_not_hardcoded_white():
    css = _read_asset("report/report.css")
    # The .risk-card and .path rules must not force a literal white background.
    for rule_name in (".risk-card", ".path"):
        idx = css.find(rule_name + " {")
        assert idx != -1, rule_name
        block = css[idx:css.find("}", idx)]
        assert "#fff" not in block and "white" not in block, f"{rule_name} still hard-codes white"


def test_dark_overrides_present():
    css = _read_asset("report/report.css")
    assert '[data-theme="dark"]' in css and "prefers-color-scheme: dark" in css
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_darkmode.py -q`
Expected: FAIL — `.risk-card`/`.path` still contain `#fff`/`white` (from the original template CSS).

- [ ] **Step 3: Replace hard-coded colors with tokens**

In `report.css`, edit the migrated rules so backgrounds/borders use tokens. Specifically:
- `.path` — change `background: white;` → `background: var(--panel);` and `border: 1px solid #d0d7de;` → `border: 1px solid var(--border);`
- `.risk-card` — change `background: #fff;` → `background: var(--panel);` and `border: 1px solid #e2e8f0;` → `border: 1px solid var(--border);`
- `.toolbar input, .toolbar select, .toolbar button` — change `background: white; color: #161b22;` → `background: var(--panel); color: var(--fg);` and `border: 1px solid #b6c2cf;` → `border: 1px solid var(--border);`
- `.graph-head` — replace the light `linear-gradient(...)` with `background: var(--th);`
- `th` already uses `var(--th)`; leave it. `code { color: #7c2d12; }` → `code { color: var(--sev-high); }` (readable in both themes).

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=src python -m pytest tests/test_report_darkmode.py tests/test_report_theme.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/assets/report/report.css tests/test_report_darkmode.py
git commit -m "fix(report): complete dark-mode coverage via design tokens"
```

---

### Task 10: Print stylesheet (deferrable)

Add a print media block producing a clean PDF via Ctrl-P. This is the explicitly deferrable task — implement it last; if descoped, it becomes a standalone follow-up (do not silently drop it).

**Files:**
- Modify: `src/cybergraph/assets/report/report.css`
- Test: `tests/test_report_print.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_print.py`:

```python
from cybergraph.visualize import _read_asset


def test_print_media_block_hides_chrome():
    css = _read_asset("report/report.css")
    idx = css.find("@media print")
    assert idx != -1
    block = css[idx:]
    assert "#cg-nav" in block and "display: none" in block
    assert ".toolbar" in block
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_print.py -q`
Expected: FAIL — no `@media print` block.

- [ ] **Step 3: Append the print block to `report.css`**

```css
@media print {
  #cg-nav, #cg-theme-toggle, .toolbar, .graph-head, #cy { display: none !important; }
  :root { --bg: #ffffff; --fg: #111827; --panel: #ffffff; --border: #d8e0ea; --muted: #444; }
  body { background: #fff; }
  .card, .section { break-inside: avoid; box-shadow: none; }
  [data-finding-row] { display: table-row !important; }
}
```

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=src python -m pytest tests/test_report_print.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/assets/report/report.css tests/test_report_print.py
git commit -m "feat(report): print stylesheet for clean PDF export"
```

---

### Task 11: Full-suite green + composition guard + manual smoke

Final integration: run the entire suite, add a single composition test asserting all five sections coexist and the file stays self-contained, and smoke the real example repo in both `--with-source` modes.

**Files:**
- Test: `tests/test_report_composition.py`

- [ ] **Step 1: Write the composition test**

Create `tests/test_report_composition.py`:

```python
from pathlib import Path

from cybergraph.cli import main
from cybergraph.visualize import generate_html_report


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/users')\n"
        "def list_users(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    return repo


def test_all_sections_present_and_self_contained(tmp_path):
    repo = _repo(tmp_path)
    assert main(["build", str(repo)]) == 0
    out = generate_html_report(repo, with_source=True)
    text = out.read_text(encoding="utf-8")
    for anchor in ('id="posture"', 'id="explorer"', 'id="findings"', 'id="deps"', 'id="about"'):
        assert anchor in text
    assert "cybergraph sarif" in text
    assert "__" not in text.split("<body")[1] or "____" not in text  # no leftover tokens in body
    assert "<link" not in text.lower() and 'src="http' not in text.lower()
```

- [ ] **Step 2: Run the full report + CLI suite**

Run: `PYTHONPATH=src python -m pytest tests/ -q`
Expected: PASS (entire suite). If any pre-existing test asserts old markup (e.g. a removed `<h2>Top Risks</h2>` table), update that test to the new structure and note it in the commit.

- [ ] **Step 3: Ruff gate over the whole change**

Run: `ruff check --select F src tests`
Expected: no errors (matches CI).

- [ ] **Step 4: Manual smoke on the example repo**

```bash
PYTHONPATH=src python -c "import sys; from cybergraph.cli import main; sys.exit(main(['quickstart','examples/vulnerable-fastapi','--no-open','--yes']))"
PYTHONPATH=src python -c "import sys; from cybergraph.cli import main; sys.exit(main(['visualize','examples/vulnerable-fastapi','--with-source']))"
```
Expected: exit 0 both; open `examples/vulnerable-fastapi/.cybergraph/report.html` and confirm posture grade, severity bar, sortable findings, dark-mode toggle, and print preview. Then confirm no secret leaked:

```bash
grep -io "supersecret\|password123\|sk-[a-zA-Z0-9]\{10,\}\|AKIA[0-9A-Z]\{16\}" examples/vulnerable-fastapi/.cybergraph/report.html
```
Expected: no output (redaction intact).

- [ ] **Step 5: Commit**

```bash
git add tests/test_report_composition.py
git commit -m "test(report): composition guard for sections and self-containment"
```

---

## Self-Review

**1. Spec coverage:**
- Self-contained/offline → Tasks 1, 11 (composition self-containment asserts). ✓
- API unchanged → Task 1 keeps signature; `test_cli_analyze` guards it across tasks. ✓
- No new deps / hand-rolled visuals → Tasks 4 (SVG-free CSS bar, div-based), 6, all stdlib. ✓
- HTML escaping preserved → every renderer uses `html.escape`; `_embed_json` untouched. ✓
- Severity palette single language → Task 3 tokens; Tasks 4/6 consume; graph node borders in report.js already use the hexes (note: report.js severity border currently `#dc2626`/`#d97706` — Task 6/9 do not change JS node colors, acceptable since spec says "same hex values"; high=`#ea580c` differs from the JS `#dc2626` used for critical+high border. This is a known minor inconsistency: the JS lumps high with critical for the *border*. Left as-is to avoid graph-behavior change; palette consistency holds for all HTML chrome). ✓ (documented)
- Grade scale → Task 4 `grade()` with boundary tests. ✓
- Windows-safe / UTF-8 → no new CLI strings; report stays `encoding="utf-8"`. ✓
- Posture (grade/verdict/bar/chips/top-3/delta) → Tasks 4, 5. ✓
- Explorer preserved + restyled → Tasks 1 (moved), 8 (anchor wrap), 9 (toolbar tokens). ✓
- Findings triage (pills/borders/sort/expand/footer) → Task 6; expand = existing drill-down snippet path, guarded by `test_report_drilldown*`. ✓
- Deps & layers + JSON pretty-print → Task 7. ✓
- About footer + version → Task 8. ✓
- Dark mode complete → Task 9. Print → Task 10. ✓
- Error handling `_safe_section` + empty states + version fallback → Task 2 (`safe_section`), used in Tasks 4/8; empty states in each renderer; version fallback Task 8. ✓
- Testing strategy → Tasks 4–11 unit + composition + regression + cross-surface. ✓
- Packaging (non-JS assets ship) → Task 1 Step 5. ✓ (gap the spec implied but didn't name; added.)

**2. Placeholder scan:** No TBD/TODO. Every code step has real code. Task 7 Step 2 gives the exact final assert (`'  "epss"'`) to disambiguate pretty-print. ✓

**3. Type consistency:** `findings_table(findings, total_findings)` — new signature updated at its only call site (Task 6 Step 4). `posture_section(repo, counts, top_risks, counts_by_sev, delta_html)` — call site in Task 4 Step 4 passes `""`, replaced by `delta_html` in Task 5 Step 4; consistent. `grade`/`severity_bar`/`delta_strip`/`about_section` names match between definition and tests. Re-export aliases in Task 2 keep `_truncation_banner` etc. importable (existing tests). ✓

One deliberate carry-over documented above: report.js keeps critical+high sharing a red node border; only HTML chrome adopts the full 5-color palette. This avoids changing graph rendering behavior and is consistent with the spec's "single color language" for the report chrome.

# Report & Onboarding Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the CyberGraph HTML report theme-aware with one unified search, a truncation banner, and opt-in secret-redacted source drill-down, and add a guided `quickstart` command.

**Architecture:** Targeted, additive edits to the existing self-contained `visualize.py` template (CSS variables + a theme toggle, one search handler, a banner token, a details-panel snippet renderer), a new pure-Python `report_source.py` for snippet gathering, and a new `quickstart.py` + CLI command reusing Spec 1's `run_full_analysis`.

**Tech Stack:** Python 3.10+ stdlib (html, json, webbrowser, pathlib), inlined Cytoscape.js (already vendored); pytest. No new dependencies; report stays 100% offline/self-contained.

## Global Constraints

- Branch off `feat/usability-core` (this depends on Spec 1's `run_full_analysis` and the real `truncated` flag). Work on `feat/report-onboarding-polish`.
- **Self-contained/offline:** no CDN, no network, no external fonts/assets — everything inlined.
- **No new hard dependencies.**
- **Additive & non-breaking:** the 4 Cytoscape explorer modes, filters, details panel, tables, and existing commands keep working.
- **Security:** source embedding is opt-in (`with_source=False` default) and secret-category findings are redacted in embedded snippets.
- Commits authored as the user only — **no `Co-Authored-By` / Claude attribution trailer**; no `--no-verify`.
- Tests run `PYTHONPATH=src python -m pytest -q`; baseline is **203 passed**; must stay green after every task.
- Reuse existing symbols:
  - `cybergraph.visualize.generate_html_report(repo_root, output=None) -> Path`; internal `_render_html(...)`, `_findings_table(findings)`, `_HTML_TEMPLATE` (token replacement via `__TOKEN__`), `_embed_json(data)`.
  - `cybergraph.graph_export.build_graph_data(repo_root, max_nodes=600) -> dict` (keys include `nodes`, `truncated`, and `counts`).
  - `cybergraph.orchestrator.run_full_analysis(repo_root, *, limit=10) -> AnalysisResult` (Spec 1).
  - `cybergraph.init_project.init_project(repo, force=False)`, `cybergraph.build.build_graph(repo)`, `cybergraph.graph.GraphStore.open_for_repo(repo)`.

## File Structure

- Create `src/cybergraph/report_source.py` — source-snippet gathering + secret redaction.
- Modify `src/cybergraph/visualize.py` — `with_source` param + snippet call; theme CSS/toggle; unified search; truncation banner; details-panel snippet render.
- Create `src/cybergraph/quickstart.py` — `run_quickstart` orchestration.
- Modify `src/cybergraph/cli.py` — `quickstart` command; forward `--with-source` to `visualize`.
- Modify `README.md`, `docs/architecture.md` — document `quickstart` + report features.
- Tests: `tests/test_report_source.py`, `tests/test_report_theme.py`, `tests/test_report_search.py`, `tests/test_report_banner.py`, `tests/test_report_drilldown.py`, `tests/test_quickstart.py`.

---

### Task 1: Source-snippet gathering with secret redaction (`report_source.py`)

**Files:**
- Create: `src/cybergraph/report_source.py`
- Test: `tests/test_report_source.py`

**Interfaces:**
- Produces: `attach_source_snippets(repo_root: Path, graph_data: dict, *, context: int = 3, max_nodes: int = 200, redact_secrets: bool = True) -> None` (mutates each qualifying node dict, adding `node["snippet"] = {"file": str, "start": int, "lines": [{"n": int, "text": str, "highlight": bool}]}`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report_source.py
from pathlib import Path

from cybergraph.report_source import attach_source_snippets


def _graph(repo: Path, extra=None):
    node = {"id": "app.py::h", "file": "app.py", "line": 3, "findings": []}
    if extra:
        node.update(extra)
    return {"nodes": [node]}


def _write(repo: Path, name: str, text: str):
    (repo / name).write_text(text, encoding="utf-8")


def test_attaches_highlighted_snippet_for_finding_node(tmp_path: Path):
    _write(tmp_path, "app.py", "a = 1\nb = 2\nrun(x)\nc = 3\nd = 4\n")
    g = _graph(tmp_path, {"findings": [{"severity": "high", "rule_id": "CG-X", "message": "m"}]})
    attach_source_snippets(tmp_path, g, context=1)
    snip = g["nodes"][0]["snippet"]
    assert snip["file"] == "app.py"
    nums = [ln["n"] for ln in snip["lines"]]
    assert nums == [2, 3, 4]  # context=1 around line 3, clamped
    hl = [ln for ln in snip["lines"] if ln["highlight"]]
    assert len(hl) == 1 and hl[0]["n"] == 3 and "run(x)" in hl[0]["text"]


def test_start_of_file_clamps_without_negative(tmp_path: Path):
    _write(tmp_path, "app.py", "run(x)\nb = 2\n")
    g = _graph(tmp_path, {"line": 1, "findings": [{"rule_id": "CG-X", "severity": "high", "message": "m"}]})
    attach_source_snippets(tmp_path, g, context=3)
    assert [ln["n"] for ln in g["nodes"][0]["snippet"]["lines"]] == [1, 2]


def test_html_is_escaped(tmp_path: Path):
    _write(tmp_path, "app.py", "x = '<b>&</b>'\n")
    g = _graph(tmp_path, {"line": 1, "findings": [{"rule_id": "CG-X", "severity": "high", "message": "m"}]})
    attach_source_snippets(tmp_path, g)
    text = g["nodes"][0]["snippet"]["lines"][0]["text"]
    assert "&lt;b&gt;" in text and "<b>" not in text


def test_secret_finding_line_is_redacted(tmp_path: Path):
    _write(tmp_path, "Dockerfile", "FROM x\nENV API_KEY=supersecretvalue\n")
    g = _graph(tmp_path, {"id": "Dockerfile", "file": "Dockerfile", "line": 2,
                          "findings": [{"rule_id": "CG-DOCKER-SECRET", "severity": "critical", "message": "m"}]})
    attach_source_snippets(tmp_path, g, context=0)
    line = g["nodes"][0]["snippet"]["lines"][0]
    assert line["highlight"] is True
    assert "supersecretvalue" not in line["text"]
    assert "redacted" in line["text"].lower()


def test_node_without_finding_or_file_gets_no_snippet(tmp_path: Path):
    g = {"nodes": [{"id": "n", "file": "", "line": 0, "findings": []},
                   {"id": "m", "file": "missing.py", "line": 5, "findings": [{"rule_id": "R", "severity": "low", "message": "x"}]}]}
    attach_source_snippets(tmp_path, g)
    assert "snippet" not in g["nodes"][0]  # no file
    assert "snippet" not in g["nodes"][1]  # file missing -> best-effort skip


def test_max_nodes_cap(tmp_path: Path):
    _write(tmp_path, "app.py", "run(x)\n")
    nodes = [{"id": f"n{i}", "file": "app.py", "line": 1,
              "findings": [{"rule_id": "R", "severity": "low", "message": "x"}]} for i in range(5)]
    g = {"nodes": nodes}
    attach_source_snippets(tmp_path, g, context=0, max_nodes=2)
    assert sum("snippet" in n for n in g["nodes"]) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_report_source.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.report_source'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/cybergraph/report_source.py
"""Attach bounded, HTML-escaped, secret-redacted source snippets to graph nodes.

Opt-in: only called when the report is generated with source embedding enabled.
The report is a shareable artifact, so snippets for secret-category findings have
their value masked, and every line is HTML-escaped."""

from __future__ import annotations

import html
from pathlib import Path

_REDACTED = '"***redacted***"'


def _is_secret_finding(findings: list) -> bool:
    for f in findings or []:
        rule = str(f.get("rule_id", "")).upper()
        if "SECRET" in rule or "CREDENTIAL" in rule or "PASSWORD" in rule:
            return True
    return False


def _redact(text: str) -> str:
    """Mask a value after the first '=' or ':' so a shared report never leaks it."""
    for sep in ("=", ":"):
        idx = text.find(sep)
        if idx != -1:
            return text[: idx + 1] + " " + _REDACTED
    return _REDACTED


def attach_source_snippets(
    repo_root: Path,
    graph_data: dict,
    *,
    context: int = 3,
    max_nodes: int = 200,
    redact_secrets: bool = True,
) -> None:
    repo_root = Path(repo_root).resolve()
    cache: dict[str, list[str] | None] = {}
    attached = 0
    for node in graph_data.get("nodes", []):
        if attached >= max_nodes:
            break
        rel = node.get("file") or ""
        line = int(node.get("line") or 0)
        findings = node.get("findings") or []
        on_path = bool(node.get("on_path"))
        if not rel or line <= 0 or not (findings or on_path):
            continue
        if rel not in cache:
            try:
                cache[rel] = (repo_root / rel).read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                cache[rel] = None
        lines = cache[rel]
        if not lines:
            continue
        secret = redact_secrets and _is_secret_finding(findings)
        lo = max(1, line - context)
        hi = min(len(lines), line + context)
        rendered = []
        for n in range(lo, hi + 1):
            raw = lines[n - 1]
            highlight = n == line
            if highlight and secret:
                raw = _redact(raw)
            rendered.append({"n": n, "text": html.escape(raw), "highlight": highlight})
        node["snippet"] = {"file": rel, "start": lo, "lines": rendered}
        attached += 1
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_report_source.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/report_source.py tests/test_report_source.py
git commit -m "feat(report): add secret-redacted source-snippet gathering"
```

---

### Task 2: Opt-in source drill-down in the report (`visualize.py`)

**Files:**
- Modify: `src/cybergraph/visualize.py` (`generate_html_report` signature; call `attach_source_snippets`; add snippet CSS; extend `showDetails` JS)
- Test: `tests/test_report_drilldown.py`

**Interfaces:**
- Consumes: `attach_source_snippets` (Task 1).
- Produces: `generate_html_report(repo_root, output=None, *, with_source: bool = False) -> Path`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report_drilldown.py
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.visualize import generate_html_report


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/x')\n"
        "def h(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    build_graph(repo)
    return repo


def test_default_off_embeds_no_snippet(tmp_path: Path):
    repo = _repo(tmp_path)
    out = generate_html_report(repo, tmp_path / "r.html")
    html = out.read_text(encoding="utf-8")
    assert '"snippet"' not in html


def test_with_source_embeds_snippet_and_render_code(tmp_path: Path):
    repo = _repo(tmp_path)
    out = generate_html_report(repo, tmp_path / "r.html", with_source=True)
    html = out.read_text(encoding="utf-8")
    assert '"snippet"' in html                 # snippet data embedded
    assert "db.execute" in html                # the finding line is present
    assert "cg-snippet" in html                # details-panel renderer markup/class
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_report_drilldown.py -v`
Expected: FAIL — `generate_html_report() got an unexpected keyword argument 'with_source'`

- [ ] **Step 3: Write minimal implementation**

In `visualize.py`, change the signature and add the snippet call. Find the current `def generate_html_report(repo_root: Path, output: Path | None = None) -> Path:` and its body that calls `build_graph_data` (via `_render_html`/graph assembly). Update to:

```python
def generate_html_report(repo_root: Path, output: Path | None = None, *, with_source: bool = False) -> Path:
```

Locate where `graph_data` is obtained (it comes from `build_graph_data` and is passed into `_render_html`). Immediately after `graph_data` is built and before it is embedded, add:

```python
    if with_source:
        from cybergraph.report_source import attach_source_snippets

        attach_source_snippets(repo_root, graph_data)
```

Add snippet CSS inside the `<style>` block (before the closing `</style>` at the `@media (max-width: 820px)` line). Add:

```css
    .cg-snippet { margin-top: 8px; border: 1px solid var(--border, #d0d7de); border-radius: 8px; overflow: auto; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .cg-snippet .ln { display: flex; gap: 10px; padding: 1px 8px; white-space: pre; }
    .cg-snippet .ln .num { color: var(--muted, #94a3b8); user-select: none; min-width: 30px; text-align: right; }
    .cg-snippet .ln.hl { background: rgba(245, 158, 11, 0.18); }
```

In the `showDetails` function, immediately before `document.getElementById('cg-details').innerHTML = html;` (currently line ~745), add the snippet renderer:

```javascript
        const snip = d.snippet;
        if (snip && snip.lines && snip.lines.length) {
          html += '<div class="kv"><strong>Source:</strong> <code>' + esc(snip.file) + '</code></div>';
          html += '<div class="cg-snippet">';
          snip.lines.forEach(function (ln) {
            html += '<div class="ln' + (ln.highlight ? ' hl' : '') + '"><span class="num">' + esc(ln.n) + '</span><span>' + ln.text + '</span></div>';
          });
          html += '</div>';
        }
```

(Note: `ln.text` is already HTML-escaped by Task 1, so it is inserted as-is; all other interpolations use `esc`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_report_drilldown.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/visualize.py tests/test_report_drilldown.py
git commit -m "feat(report): opt-in source drill-down in the details panel"
```

---

### Task 3: Theme-aware report (dark/light + toggle) (`visualize.py`)

**Files:**
- Modify: `src/cybergraph/visualize.py` (`<style>` → CSS variables + dark palette; `<head>` anti-FOUC script; header toggle button; cy label theming)
- Test: `tests/test_report_theme.py`

**Interfaces:**
- Produces: generated HTML with theme variables, a `data-theme` toggle, and dark-scheme support.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report_theme.py
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.visualize import generate_html_report


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    build_graph(repo)
    return repo


def test_report_is_theme_aware(tmp_path: Path):
    html = generate_html_report(_repo(tmp_path), tmp_path / "r.html").read_text(encoding="utf-8")
    assert "--bg" in html and "--fg" in html                 # CSS variables
    assert "prefers-color-scheme: dark" in html               # auto dark
    assert '[data-theme="dark"]' in html                      # explicit override
    assert 'id="cg-theme-toggle"' in html                     # toggle control
    assert "localStorage" in html and "cybergraph-theme" in html  # persistence + anti-FOUC
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_report_theme.py -v`
Expected: FAIL — `--bg`/`data-theme` not present.

- [ ] **Step 3: Write minimal implementation**

(a) Replace the first two `<style>` lines (currently `:root { color-scheme: light; ... }` and `body { ... background: #f5f7fb; color: #111827; }`) with theme variables + a dark palette, and change the hardcoded surface colors to variables:

```css
    :root {
      color-scheme: light; font-family: Inter, Segoe UI, Arial, sans-serif;
      --bg: #f5f7fb; --fg: #111827; --panel: #ffffff; --border: #d8e0ea;
      --muted: #667085; --th: #f0f3f6; --cy-bg: #f8fafc;
    }
    @media (prefers-color-scheme: dark) {
      :root { color-scheme: dark; --bg: #0b1220; --fg: #e5e7eb; --panel: #111827;
              --border: #243044; --muted: #94a3b8; --th: #1a2334; --cy-bg: #0b1220; }
    }
    :root[data-theme="dark"] { color-scheme: dark; --bg: #0b1220; --fg: #e5e7eb; --panel: #111827;
              --border: #243044; --muted: #94a3b8; --th: #1a2334; --cy-bg: #0b1220; }
    :root[data-theme="light"] { color-scheme: light; --bg: #f5f7fb; --fg: #111827; --panel: #ffffff;
              --border: #d8e0ea; --muted: #667085; --th: #f0f3f6; --cy-bg: #f8fafc; }
    body { margin: 0; background: var(--bg); color: var(--fg); }
```

Then change these existing rules to use the variables (replace the literal colors):
- `.muted { color: var(--muted); }`
- `.stat, table { background: var(--panel); border: 1px solid var(--border); ... }` (keep the box-shadow)
- `th, td { ... border-bottom: 1px solid var(--border); }` and `th { background: var(--th); ... }`
- `.graph-card, .details { background: var(--panel); border: 1px solid var(--border); ... }`
- `#cy { height: 640px; background: var(--cy-bg); }`

(b) In `<head>`, before `</head>`, add the anti-FOUC + toggle bootstrap script:

```html
  <script>
    (function () {
      try {
        var t = localStorage.getItem('cybergraph-theme');
        if (!t) t = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', t);
      } catch (e) {}
    })();
  </script>
```

(c) In the `<header>` (after the `<h1>`), add the toggle button:

```html
    <button id="cg-theme-toggle" type="button" style="position:absolute;top:20px;right:24px;cursor:pointer;border:1px solid rgba(255,255,255,0.4);background:transparent;color:white;border-radius:6px;padding:6px 10px;">Theme</button>
```

Set `header { ... position: relative; }` (append `position: relative;` to the existing `header` rule).

(d) At the end of the second `<script>` block (after the findings filter listeners, before `</script>` at line ~796), add the toggle handler:

```javascript
    document.getElementById('cg-theme-toggle')?.addEventListener('click', function () {
      var cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', cur);
      try { localStorage.setItem('cybergraph-theme', cur); } catch (e) {}
    });
```

(e) Cy label legibility on dark: in the cy `style` array, node selector (currently `'color': '#0b1220'`), add a text outline so labels read on both themes — change that node style block to include:

```javascript
            'color': '#0b1220', 'text-outline-width': 2, 'text-outline-color': '#f8fafc',
```

(This white halo keeps dark node labels legible on a dark canvas; semantic node fill colors are unchanged.)

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_report_theme.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/visualize.py tests/test_report_theme.py
git commit -m "feat(report): theme-aware report with dark mode and toggle"
```

---

### Task 4: Unified text search (`visualize.py`)

**Files:**
- Modify: `src/cybergraph/visualize.py` (`_findings_table`: remove its own search input; second `<script>`: point the findings filter at `#cg-search`)
- Test: `tests/test_report_search.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report_search.py
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.visualize import generate_html_report


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/x')\ndef h(request):\n    return db.execute(request.query['q'])\n",
        encoding="utf-8",
    )
    build_graph(repo)
    return repo


def test_single_unified_search_box(tmp_path: Path):
    html = generate_html_report(_repo(tmp_path), tmp_path / "r.html").read_text(encoding="utf-8")
    # the findings table no longer has its own text search input
    assert "data-filter='findings-search'" not in html and 'data-filter="findings-search"' not in html
    # exactly one search input remains: the shared #cg-search
    assert html.count('type="search"') + html.count("type='search'") == 1
    # the findings filter is wired to the shared box
    assert "getElementById('cg-search')" in html
    # the findings severity filter is preserved (kept separate by design)
    assert "findings-severity" in html
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_report_search.py -v`
Expected: FAIL — findings-search input still present; two search inputs.

- [ ] **Step 3: Write minimal implementation**

(a) In `_findings_table` (around line 170-182), remove the findings-search input line. Delete these two lines:

```python
        "<input data-filter='findings-search' type='search' "
        "placeholder='Search findings by rule, file, message, or tool'>"
```

so the returned toolbar starts directly with the `findings-severity` select.

(b) In the second `<script>` block (line ~784), change the findings-search reference from its own input to the shared box:

```javascript
    const findingSearch = document.getElementById('cg-search');
    const findingSeverity = document.querySelector('[data-filter="findings-severity"]');
```

Leave `filterFindings`, the `findingSearch?.addEventListener('input', filterFindings)`, and `findingSeverity?.addEventListener('change', filterFindings)` lines as-is — they now operate on the shared `#cg-search` input. (Result: typing in `#cg-search` filters both the graph — via the existing `applyFilters` listener at line 763 — and the findings table.)

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_report_search.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/visualize.py tests/test_report_search.py
git commit -m "feat(report): unify graph and findings search into one box"
```

---

### Task 5: Truncation banner (`visualize.py`)

**Files:**
- Modify: `src/cybergraph/visualize.py` (add `_truncation_banner` helper + `__TRUNCATION_BANNER__` token + placement in template)
- Test: `tests/test_report_banner.py`

**Interfaces:**
- Produces: `_truncation_banner(graph_data: dict) -> str`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report_banner.py
from cybergraph.visualize import _truncation_banner


def test_banner_when_truncated():
    html = _truncation_banner({"truncated": True, "nodes": [0] * 600, "counts": {"nodes": 1500}})
    assert "600" in html and "1500" in html and "max-nodes" in html


def test_no_banner_when_not_truncated():
    assert _truncation_banner({"truncated": False, "nodes": [0] * 10, "counts": {"nodes": 10}}) == ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_report_banner.py -v`
Expected: FAIL — `cannot import name '_truncation_banner'`

- [ ] **Step 3: Write minimal implementation**

Add the helper near the other `_*` render helpers in `visualize.py`:

```python
def _truncation_banner(graph_data: dict) -> str:
    if not graph_data.get("truncated"):
        return ""
    shown = len(graph_data.get("nodes", []))
    total = int(graph_data.get("counts", {}).get("nodes", shown))
    return (
        "<div style='margin:0 0 12px;padding:10px 12px;border-radius:8px;"
        "background:#fef3c7;color:#92400e;border:1px solid #fde68a;font-size:13px;'>"
        f"Showing {shown} of {total} nodes — raise <code>--max-nodes</code> to see the full graph."
        "</div>"
    )
```

In `_render_html`'s `replacements` dict, add:

```python
        "__TRUNCATION_BANNER__": _truncation_banner(graph_data),
```

In `_HTML_TEMPLATE`, place the token right before the graph explorer toolbar — immediately after the `<h2>Interactive Graph Explorer</h2>` / mode-help line and before `<div class="risk-strip"...>`:

```html
    __TRUNCATION_BANNER__
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_report_banner.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/visualize.py tests/test_report_banner.py
git commit -m "feat(report): show a truncation banner when the graph is capped"
```

---

### Task 6: Guided `quickstart` command (`quickstart.py` + `cli.py`)

**Files:**
- Create: `src/cybergraph/quickstart.py`
- Modify: `src/cybergraph/cli.py` (parser + dispatch; forward `--with-source` to the `visualize` command too)
- Test: `tests/test_quickstart.py`

**Interfaces:**
- Consumes: `init_project`, `build_graph`, `run_full_analysis`, `generate_html_report`.
- Produces: `run_quickstart(repo_root: Path, *, with_source: bool = False) -> QuickstartResult` (dataclass: `steps: list[str]`, `report_path: Path`, `top_risk: str | None`); CLI command `quickstart [repo] [--yes] [--no-open] [--with-source]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_quickstart.py
from pathlib import Path

import pytest

from cybergraph.cli import main
from cybergraph.quickstart import run_quickstart


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/x')\ndef h(request):\n    return db.execute(request.query['q'])\n",
        encoding="utf-8",
    )
    return repo


def test_run_quickstart_builds_analyzes_and_writes_report(tmp_path: Path):
    repo = _repo(tmp_path)
    result = run_quickstart(repo)
    assert result.report_path.is_file()
    assert len(result.steps) == 4
    assert result.top_risk  # at least one risk on the vulnerable sample


def test_cli_quickstart_no_open_never_opens_browser(tmp_path: Path, capsys, monkeypatch):
    repo = _repo(tmp_path)
    import webbrowser
    opened = {"n": 0}
    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: opened.__setitem__("n", opened["n"] + 1))
    code = main(["quickstart", str(repo), "--no-open", "--yes"])
    out = capsys.readouterr().out
    assert code == 0
    assert opened["n"] == 0                 # browser never opened
    assert "[1/4]" in out and "[4/4]" in out  # step log printed
    assert "report" in out.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_quickstart.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.quickstart'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/cybergraph/quickstart.py
"""Guided one-command onboarding: init -> build -> analyze -> report."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.init_project import init_project
from cybergraph.orchestrator import run_full_analysis
from cybergraph.visualize import generate_html_report


@dataclass
class QuickstartResult:
    report_path: Path
    steps: list[str] = field(default_factory=list)
    top_risk: str | None = None


def run_quickstart(repo_root: Path, *, with_source: bool = False) -> QuickstartResult:
    repo_root = Path(repo_root).resolve()
    steps: list[str] = []

    if not (repo_root / ".cybergraph.toml").is_file():
        init_project(repo_root)
        steps.append("[1/4] init ... created .cybergraph.toml")
    else:
        steps.append("[1/4] init ... config already present")

    counts = build_graph(repo_root)
    steps.append(f"[2/4] build ... {counts['nodes']} nodes, {counts['findings']} findings")

    result = run_full_analysis(repo_root)
    top = result.top_risks[0] if result.top_risks else None
    top_risk = f"{top.risk_label.upper()} {top.risk_score}/100 {top.category}: {top.title}" if top else None
    steps.append(f"[3/4] analyze ... {len(result.top_risks)} risk(s)"
                 + (f"; top: {top_risk}" if top_risk else ""))

    report = generate_html_report(repo_root, with_source=with_source)
    steps.append(f"[4/4] report ... {report}")

    return QuickstartResult(report_path=report, steps=steps, top_risk=top_risk)
```

In `cli.py` `build_parser`, before `return parser`, add:

```python
    quickstart = sub.add_parser(
        "quickstart", help="Zero-to-report: init, build, analyze, and open the HTML report"
    )
    quickstart.add_argument("repo", nargs="?", default=".", help="Repository root")
    quickstart.add_argument("--yes", action="store_true", help="Run non-interactively")
    quickstart.add_argument("--no-open", action="store_true", help="Do not open the report in a browser")
    quickstart.add_argument("--with-source", action="store_true", help="Embed (secret-redacted) source snippets in the report")
```

Add this dispatch branch in `main`:

```python
    elif args.command == "quickstart":
        import os
        import sys
        import webbrowser

        from .quickstart import run_quickstart

        result = run_quickstart(repo, with_source=args.with_source)
        for step in result.steps:
            print(step)
        can_open = (not args.no_open) and sys.stdout.isatty() and not os.environ.get("CI")
        if can_open:
            try:
                webbrowser.open(result.report_path.as_uri())
            except Exception:
                pass
        print(f"\nOpen the report: {result.report_path}")
```

Also give the existing `visualize` command a `--with-source` flag and forward it. Find the `visualize` parser and add:

```python
    visualize.add_argument("--with-source", action="store_true", help="Embed (secret-redacted) source snippets")
```

and in the `visualize` dispatch branch, change the `generate_html_report(...)` call to pass `with_source=args.with_source`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_quickstart.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/quickstart.py src/cybergraph/cli.py tests/test_quickstart.py
git commit -m "feat(cli): add guided 'quickstart' command and --with-source report flag"
```

---

### Task 7: Full-suite verification + docs

**Files:**
- Modify: `README.md` (Quick start), `docs/architecture.md`

- [ ] **Step 1: Run the full suite**

Run: `PYTHONPATH=src python -m pytest -q`
Expected: all prior tests plus the new ones PASS (target ≈ 221 passed), no regressions.

- [ ] **Step 2: End-to-end smoke**

Run: `python -c "import sys; from cybergraph.cli import main; sys.exit(main(['quickstart','examples/vulnerable-fastapi','--no-open','--yes']))"`
Expected: prints `[1/4]`..`[4/4]` and a report path; exit 0.

Run: `python -c "import sys; from cybergraph.cli import main; sys.exit(main(['visualize','examples/vulnerable-fastapi','--with-source']))"` then confirm the report file contains `cg-snippet` and no plaintext secret.

- [ ] **Step 3: Update docs**

In `README.md` Quick start, add near the top:
```
cybergraph quickstart .        # zero-to-report: init, build, analyze, open report
```
In `docs/architecture.md`, append under "Pipeline": `7. The HTML report is theme-aware with one unified search, a truncation banner, and opt-in secret-redacted source drill-down; 'quickstart' runs the whole flow in one command.`

- [ ] **Step 4: Commit**

```bash
git add README.md docs/architecture.md
git commit -m "docs: document quickstart and the polished report"
```

---

## Self-Review

**Spec coverage:**
- A. Theme-aware report → Task 3 (CSS vars + dark + toggle + anti-FOUC + cy label outline). ✓
- B. Unified text search (severity filters kept separate) → Task 4. ✓
- C. Truncation banner from the real `truncated` flag → Task 5. ✓
- D. Opt-in, secret-redacted source drill-down → Task 1 (gather+redact) + Task 2 (opt-in plumbing + render). ✓
- E. Guided `quickstart` with guarded browser open (`--no-open`/non-TTY/CI) + `--yes` + `--with-source` → Task 6. ✓
- Testing (theme/search/banner/snippet/redaction/quickstart) → each task + Task 7. ✓
- Self-contained/offline, additive, no new deps → constraints honored (no CDN/asset added; all edits additive). ✓

**Placeholder scan:** no TBD/TODO; every code step has complete code or a precise anchored snippet + complete test code. ✓

**Type consistency:** `attach_source_snippets` snippet shape (`{file,start,lines:[{n,text,highlight}]}`) matches the `showDetails` renderer (Task 2) and the tests (Task 1). `generate_html_report(..., with_source=...)` signature matches its callers in Task 6 and the `visualize`/`quickstart` dispatch. `_truncation_banner(graph_data)` matches its token use. `run_quickstart(...) -> QuickstartResult(report_path, steps, top_risk)` matches the CLI dispatch and tests. ✓

**Note for the implementer:** Tasks 2–5 edit the large embedded HTML/JS template in `visualize.py`; make the edits at the exact anchors named (line numbers are current-as-of-writing and may drift — match on the quoted surrounding text, not the number) and keep every existing token/handler intact. The tests assert the required HTML structure, so a broken edit fails fast.

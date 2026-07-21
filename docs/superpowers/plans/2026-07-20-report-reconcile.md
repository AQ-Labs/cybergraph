# Report Reconcile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port four additive exec-first/usability features (posture A–F grade + severity bar, since-last-scan delta strip, honest findings cap footer, print stylesheet) onto the owner's already-merged inline HTML report on `main`, with zero regression to their report tests.

**Architecture:** The report on `main` is one inline `_HTML_TEMPLATE` string in `src/cybergraph/visualize.py`, filled by `_render_html` via `str.replace`. New renderers are added as module functions in that same file (matching the existing `_findings_table`/`_top_risks_table`/`_top_risks_table` convention). New CSS goes into the existing inline `<style>` block, reusing their theme tokens. No asset extraction, no new modules.

**Tech Stack:** Python 3 stdlib (`html`, `json`, `importlib`), the existing `cybergraph.history` module, vanilla inline CSS/JS, pytest.

## Global Constraints

- Base branch/commit: `feat/report-reconcile` off `origin/main` @ `8cd02b1` (spec already committed).
- Do NOT regress existing report tests — especially the 14-test `tests/test_report_visual_identity.py`. Preserve: the 16 CSS token names; the `finding-group`/`data-finding-row`/`data-finding-group` DOM; the `risk-card`/`data-risk-jump` strip with NO flat risks table; the `_HTML_TEMPLATE` placeholder-token set; the `LIMIT 100` display vs true `counts()` total; the unified `#cg-search`.
- `generate_html_report(repo_root, output=None, *, with_source=False) -> Path` signature unchanged.
- ONE self-contained offline HTML file; all interpolated data HTML-escaped; secret redaction in `--with-source` intact.
- New CSS chrome (posture card, delta strip) uses THEIR theme tokens (`--panel`, `--border`, `--fg`, `--muted`, `--th`) — never a hardcoded light background. Severity-bar segment colors are saturated accents applied as INLINE `style="background:#..."` on the segments (not CSS rules), so a CSS-scanning "no hardcoded light background" test cannot trip on them.
- Grade scale (inclusive lower bound, highest score drives it): A = no risk ≥40 (or none → "No significant risks detected."); B = 40–54; C = 55–69; D = 70–84; E = 85–89; F = ≥90.
- Tests: `PYTHONPATH=src python -m pytest -q` from repo root. Ruff gate: `ruff check --select F src tests` (no unused imports).
- Commits authored as the user only — NO `Co-Authored-By: Claude` trailer.

Anchor points in `main`'s `src/cybergraph/visualize.py` (verified):
- `generate_html_report` body lines 23–72; store block ends at `store.close()` (line ~57); `_render_html(...)` call at lines 66–69.
- `_render_html(repo_root, counts, layers, findings, vulnerable_dependencies, attack_paths, graph_data)` at line 83; `replacements` dict lines 87–110; replace-loop 111–112.
- `counts["findings"]` is the true total (independent `SELECT COUNT(*)`); findings display query capped `LIMIT 100`.
- Template: `<section class="grid">` stat grid at line 516 (closes ~523); `<h2>Top Risks</h2>` at 525 + `__TOP_RISKS_TABLE__` at 526; `<h2>Findings</h2>` at 599 + `__FINDINGS_TABLE__` at 600; `__ATTACK_PATHS_LIST__` at 602.
- CSS: `:root` at 351; `@media (prefers-color-scheme: dark)` at 361; `:root[data-theme="dark"]` at 370; `:root[data-theme="light"]` at 377. No `@media print` exists.
- `history.scan_delta(repo_root) -> Delta(is_first, new/fixed/regressed/persisting)` and `history.list_scans(repo_root, limit) -> list[dict]` (rows have `ts`), in `src/cybergraph/history.py`.

## File Structure

- `src/cybergraph/visualize.py` (MODIFY) — add module functions `_grade`, `_severity_bar`, `_posture_section`, `_delta_strip`, `_gather_delta_html`, `_findings_footer`; add `sev_counts`/`delta_html` to `_render_html` + the composer; add `__POSTURE__`/`__FINDINGS_FOOTER__` tokens + CSS to the inline template.
- `tests/test_report_reconcile.py` (CREATE) — unit tests for the new renderers.
- `tests/test_report_print.py` (CREATE) — print-stylesheet test.

---

### Task 1: Security Posture section (grade, verdict, severity bar)

**Files:**
- Modify: `src/cybergraph/visualize.py`
- Test: `tests/test_report_reconcile.py`

**Interfaces:**
- Consumes: `graph_data["top_risks"]` (dicts with `risk_score` int, `risk_label`, `title`, `category`, `detail`); a `counts_by_sev` dict; `counts` dict.
- Produces: `_grade(top_risks: list[dict]) -> tuple[str, str]`; `_severity_bar(counts_by_sev: dict[str, int]) -> str`; `_posture_section(counts, top_risks, counts_by_sev, delta_html: str) -> str`. New template token `__POSTURE__`. `_render_html` gains a `sev_counts` parameter.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_reconcile.py`:

```python
from cybergraph.visualize import _grade, _severity_bar, _posture_section


def test_grade_boundaries():
    assert _grade([])[0] == "A"
    assert _grade([{"risk_score": 39}])[0] == "A"
    assert _grade([{"risk_score": 40}])[0] == "B"
    assert _grade([{"risk_score": 54}])[0] == "B"
    assert _grade([{"risk_score": 55}])[0] == "C"
    assert _grade([{"risk_score": 69}])[0] == "C"
    assert _grade([{"risk_score": 70}])[0] == "D"
    assert _grade([{"risk_score": 84}])[0] == "D"
    assert _grade([{"risk_score": 85}])[0] == "E"
    assert _grade([{"risk_score": 89}])[0] == "E"
    assert _grade([{"risk_score": 90}])[0] == "F"
    assert _grade([{"risk_score": 10}, {"risk_score": 92}])[0] == "F"


def test_grade_empty_verdict():
    assert "No significant risks" in _grade([])[1]


def test_severity_bar_segments():
    out = _severity_bar({"critical": 2, "high": 0, "medium": 1, "low": 0, "info": 0})
    assert "sevbar" in out
    assert ">2<" in out
    assert "#dc2626" in out  # critical color, inline


def test_severity_bar_empty():
    assert "No findings" in _severity_bar({})


def test_posture_section_present():
    out = _posture_section(
        {"nodes": 5, "edges": 4, "findings": 3, "attack_paths": 1},
        [{"category": "sqli", "title": "SQL injection", "risk_score": 88,
          "risk_label": "high", "detail": "d"}],
        {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        "",
    )
    assert 'id="posture"' in out
    assert "SQL injection" not in out  # posture links to the risk strip, doesn't duplicate cards
    assert ">B<" in out or "badge-grade" in out  # grade badge present
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_reconcile.py -q`
Expected: FAIL — `ImportError: cannot import name '_grade'`.

- [ ] **Step 3: Implement the renderers in `visualize.py`**

Add near the other `_*table` helpers (module scope):

```python
_GRADE_BANDS = [(90, "F"), (85, "E"), (70, "D"), (55, "C"), (40, "B")]
_GRADE_COLOR = {"A": "#16a34a", "B": "#65a30d", "C": "#d97706",
                "D": "#ea580c", "E": "#dc2626", "F": "#991b1b"}
_SEV_BAR_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_BAR_COLOR = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
                  "low": "#2563eb", "info": "#64748b"}


def _grade(top_risks: list[dict]) -> tuple[str, str]:
    scores = [int(r.get("risk_score") or 0) for r in top_risks]
    top = max(scores) if scores else 0
    letter = "A"
    for threshold, band in _GRADE_BANDS:
        if top >= threshold:
            letter = band
            break
    if not scores or top < 40:
        return "A", "No significant risks detected."
    return letter, f"Highest risk scored {top}/100 — see the top risks below."


def _severity_bar(counts_by_sev: dict) -> str:
    total = sum(int(counts_by_sev.get(s, 0)) for s in _SEV_BAR_ORDER)
    if total == 0:
        return ("<div class='sevbar'><div class='sevbar-seg' "
                "style='width:100%;background:#64748b'>No findings</div></div>")
    segs = []
    for sev in _SEV_BAR_ORDER:
        n = int(counts_by_sev.get(sev, 0))
        if n == 0:
            continue
        pct = round(100 * n / total, 2)
        segs.append(
            f"<div class='sevbar-seg' title='{html.escape(sev)}: {n}' "
            f"style='width:{pct}%;background:{_SEV_BAR_COLOR[sev]}'>{n}</div>"
        )
    return f"<div class='sevbar'>{''.join(segs)}</div>"


def _posture_section(counts, top_risks, counts_by_sev, delta_html: str) -> str:
    letter, verdict = _grade(top_risks)
    color = _GRADE_COLOR[letter]
    return (
        "<section id='posture' class='posture'>"
        "<h2>Security Posture</h2>"
        "<div class='posture-row'>"
        f"<div class='badge-grade' style='background:{color}'>{letter}</div>"
        f"<div class='posture-main'><p><strong>{html.escape(verdict)}</strong></p>"
        f"{_severity_bar(counts_by_sev)}</div>"
        "</div>"
        f"{delta_html}"
        "</section>"
    )
```

- [ ] **Step 4: Wire the composer + template**

In `generate_html_report`, inside the `try:` block before `store.close()`, add the distribution query:

```python
        sev_counts = {
            row["severity"]: row["n"]
            for row in store.conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
            )
        }
```

Change the `_render_html(...)` call to pass `sev_counts`:

```python
        _render_html(
            repo_root, counts, layers, findings, vulnerable_dependencies,
            attack_paths, graph_data, sev_counts,
        ),
```

Update `_render_html`'s signature to end with `..., graph_data, sev_counts` and add to `replacements`:

```python
        "__POSTURE__": _posture_section(
            {**counts, "attack_paths": len(attack_paths)},
            graph_data.get("top_risks", []),
            sev_counts,
            "",  # delta filled in Task 2
        ),
```

In the `_HTML_TEMPLATE`, insert `__POSTURE__` on its own line immediately AFTER the stat-grid `</section>` (the one containing `__NODES__`, closing around line 523) and BEFORE `<h2>Top Risks</h2>`.

Add CSS inside the inline `<style>` (near the other component rules), using their tokens for chrome:

```css
    .posture { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 18px; margin: 18px 0; }
    .posture-row { display: flex; gap: 18px; align-items: center; flex-wrap: wrap; }
    .posture-main { flex: 1; min-width: 240px; }
    .badge-grade { display: inline-flex; align-items: center; justify-content: center; width: 72px; height: 72px; border-radius: 16px; font-size: 42px; font-weight: 700; color: #fff; }
    .sevbar { display: flex; width: 100%; height: 24px; border-radius: 999px; overflow: hidden; border: 1px solid var(--border); }
    .sevbar-seg { display: flex; align-items: center; justify-content: center; color: #fff; font-size: 11px; font-weight: 600; }
```

- [ ] **Step 5: Run tests (unit + full regression)**

Run: `PYTHONPATH=src python -m pytest tests/test_report_reconcile.py tests/test_report_visual_identity.py tests/test_cli_analyze.py -q`
Expected: PASS. If `test_report_visual_identity` flags a hardcoded light background from the new CSS, confirm the offending value is a token (it should be — only `#fff` text on the saturated badge and `#fff` seg text are literal, which are foreground colors on saturated backgrounds, not panel backgrounds). If a real conflict arises, move the flagged color to a token; do not weaken their test.

- [ ] **Step 6: Ruff + commit**

Run: `ruff check --select F src/cybergraph/visualize.py tests/test_report_reconcile.py`
Expected: no errors.

```bash
git add src/cybergraph/visualize.py tests/test_report_reconcile.py
git commit -m "feat(report): add exec-first security posture section"
```

---

### Task 2: Since-last-scan delta strip

**Files:**
- Modify: `src/cybergraph/visualize.py`
- Test: `tests/test_report_reconcile.py`

**Interfaces:**
- Consumes: `history.scan_delta(repo_root) -> Delta`; `history.list_scans(repo_root, limit=2)`.
- Produces: `_delta_strip(delta, prev_ts: str | None) -> str` (empty when `delta is None` or `delta.is_first`); `_gather_delta_html(repo_root) -> str` (never raises). Injected into `_posture_section`'s `delta_html`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_report_reconcile.py`:

```python
from cybergraph.history import Delta
from cybergraph.visualize import _delta_strip


def test_delta_hidden_first_scan():
    assert _delta_strip(Delta(is_first=True), None) == ""


def test_delta_hidden_when_none():
    assert _delta_strip(None, None) == ""


def test_delta_renders_counts_and_date():
    d = Delta(is_first=False, new=["a", "b"], fixed=["c"], regressed=["d"],
              persisting=["e", "f", "g"])
    out = _delta_strip(d, "2026-07-19T10:00:00+00:00")
    assert "2 new" in out and "1 fixed" in out and "1 regressed" in out and "3 persisting" in out
    assert "2026-07-19" in out
    assert "Since since" not in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_reconcile.py -q -k delta`
Expected: FAIL — `ImportError: cannot import name '_delta_strip'`.

- [ ] **Step 3: Implement**

In `visualize.py`:

```python
def _delta_strip(delta, prev_ts: str | None) -> str:
    if delta is None or getattr(delta, "is_first", True):
        return ""
    when = (prev_ts or "")[:19]
    since = f"Since scan on {html.escape(when)}" if when else "Since last scan"
    return (
        "<div class='delta-strip'>"
        f"{since}: <strong>{len(delta.new)} new</strong> · "
        f"<strong>{len(delta.regressed)} regressed</strong> · "
        f"<strong>{len(delta.fixed)} fixed</strong> · "
        f"<strong>{len(delta.persisting)} persisting</strong>"
        "</div>"
    )


def _gather_delta_html(repo_root) -> str:
    try:
        from cybergraph import history
        delta = history.scan_delta(repo_root)
        scans = history.list_scans(repo_root, limit=2)
        prev_ts = scans[1]["ts"] if len(scans) > 1 else None
        return _delta_strip(delta, prev_ts)
    except Exception:
        return ""
```

- [ ] **Step 4: Wire into the composer**

In `generate_html_report`, after `graph_data = build_graph_data(repo_root)` (and the optional `attach_source_snippets`), compute `delta_html = _gather_delta_html(repo_root)` and pass it into `_render_html` (add a trailing `delta_html` parameter). In `_render_html`, replace the posture `""` delta argument with `delta_html`.

Add CSS (uses tokens):

```css
    .delta-strip { margin: 14px 0 0; padding: 10px 12px; border-radius: 8px; background: var(--accent-bg); color: var(--accent); font-size: 13px; }
```

(If `--accent-bg`/`--accent` render poorly, fall back to `background: var(--th); color: var(--fg)`.)

- [ ] **Step 5: Run tests**

Run: `PYTHONPATH=src python -m pytest tests/test_report_reconcile.py tests/test_report_visual_identity.py tests/test_cli_analyze.py -q`
Expected: PASS.

- [ ] **Step 6: Ruff + commit**

Run: `ruff check --select F src/cybergraph/visualize.py tests/test_report_reconcile.py`

```bash
git add src/cybergraph/visualize.py tests/test_report_reconcile.py
git commit -m "feat(report): show since-last-scan delta strip in posture"
```

---

### Task 3: Honest findings cap footer

**Files:**
- Modify: `src/cybergraph/visualize.py`
- Test: `tests/test_report_reconcile.py`

**Interfaces:**
- Produces: `_findings_footer(shown: int, total: int) -> str`. New template token `__FINDINGS_FOOTER__`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_report_reconcile.py`:

```python
from cybergraph.visualize import _findings_footer


def test_findings_footer_capped():
    out = _findings_footer(100, 250)
    assert "top 100" in out.lower() and "250" in out
    assert "cybergraph sarif" in out


def test_findings_footer_all_shown():
    assert "all 4" in _findings_footer(4, 4).lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_reconcile.py -q -k footer`
Expected: FAIL — `ImportError: cannot import name '_findings_footer'`.

- [ ] **Step 3: Implement**

```python
def _findings_footer(shown: int, total: int) -> str:
    if total > shown:
        return ("<p class='muted'>Showing the top "
                f"{shown} findings by severity ({total} total) — run "
                "<code>cybergraph sarif</code> or <code>cybergraph export-json</code> "
                "for the complete set.</p>")
    return f"<p class='muted'>Showing all {total} findings.</p>"
```

- [ ] **Step 4: Wire token**

In `_render_html` `replacements`, add:

```python
        "__FINDINGS_FOOTER__": _findings_footer(len(findings), counts.get("findings", len(findings))),
```

In `_HTML_TEMPLATE`, insert `__FINDINGS_FOOTER__` on its own line immediately AFTER `__FINDINGS_TABLE__` (line 600) and before `__ATTACK_PATHS_LIST__`/the next heading.

- [ ] **Step 5: Run tests**

Run: `PYTHONPATH=src python -m pytest tests/test_report_reconcile.py tests/test_report_visual_identity.py tests/test_cli_analyze.py -q`
Expected: PASS.

- [ ] **Step 6: Ruff + commit**

Run: `ruff check --select F src/cybergraph/visualize.py tests/test_report_reconcile.py`

```bash
git add src/cybergraph/visualize.py tests/test_report_reconcile.py
git commit -m "feat(report): honest findings cap footer pointing to full-export commands"
```

---

### Task 4: Print stylesheet

**Files:**
- Modify: `src/cybergraph/visualize.py` (inline `<style>`)
- Test: `tests/test_report_print.py`

**Interfaces:** none new — CSS only.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_print.py`:

```python
from pathlib import Path

from cybergraph.cli import main
from cybergraph.visualize import generate_html_report


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/x')\n"
        "def x(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    return repo


def test_print_media_block_present_and_overrides_dark(tmp_path):
    repo = _repo(tmp_path)
    assert main(["build", str(repo)]) == 0
    text = generate_html_report(repo).read_text(encoding="utf-8")
    idx = text.find("@media print")
    assert idx != -1
    block = text[idx:text.find("</style>", idx)]
    assert "#cg-nav" in block or "#cg-theme-toggle" in block
    assert "display: none" in block
    # Must override the persisted dark theme, not just bare :root:
    assert ':root[data-theme="dark"]' in block
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_report_print.py -q`
Expected: FAIL — no `@media print`.

- [ ] **Step 3: Append the print block to the inline `<style>`**

Add at the END of the inline `<style>` (just before `</style>`):

```css
    @media print {
      #cg-nav, #cg-theme-toggle, .toolbar, .graph-head, #cy { display: none !important; }
      :root, :root[data-theme="dark"], :root[data-theme="light"] {
        --bg: #ffffff; --fg: #111827; --panel: #ffffff; --border: #d8e0ea; --muted: #444;
      }
      body { background: #fff; }
      .posture, .risk-strip, .finding-group { break-inside: avoid; box-shadow: none; }
      [data-finding-row], [data-finding-group] { display: revert !important; }
      details[data-finding-group] { }
    }
```

NOTE: `#cg-nav` may not exist on `main`'s report — if there is no nav element, the selector is harmless (matches nothing). The test asserts `#cg-nav OR #cg-theme-toggle`; `#cg-theme-toggle` DOES exist (line 511). Keep both in the hide list.

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=src python -m pytest tests/test_report_print.py tests/test_report_visual_identity.py -q`
Expected: PASS.

- [ ] **Step 5: Ruff (no python logic) + commit**

```bash
git add src/cybergraph/visualize.py tests/test_report_print.py
git commit -m "feat(report): print stylesheet for clean PDF export"
```

---

### Task 5: Full-suite regression + composition + smoke

**Files:**
- Test: `tests/test_report_reconcile.py` (append a composition guard)

- [ ] **Step 1: Append a composition guard test**

```python
def test_report_composition_self_contained(tmp_path):
    import re
    from cybergraph.cli import main as _main
    from cybergraph.visualize import generate_html_report as _gen
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/users')\n"
        "def list_users(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    assert _main(["build", str(repo)]) == 0
    text = _gen(repo, with_source=True).read_text(encoding="utf-8")
    assert 'id="posture"' in text
    assert "@media print" in text
    assert not re.search(r"__[A-Z][A-Z0-9_]*__", text)   # no unresolved tokens
    assert "<link" not in text.lower()
    assert 'src="http' not in text.lower() and "src='http" not in text.lower()
```

- [ ] **Step 2: Run the FULL suite**

Run: `PYTHONPATH=src python -m pytest tests/ -q`
Expected: PASS (all — includes `test_report_visual_identity`, `test_report_drilldown*`, `test_report_search`, `test_report_theme`). If any pre-existing test breaks, STOP and report; do not weaken it.

- [ ] **Step 3: Ruff gate over the whole change**

Run: `ruff check --select F src tests`
Expected: no errors.

- [ ] **Step 4: Manual smoke + secret-redaction check on the example repo**

```bash
PYTHONPATH=src python -c "import sys; from cybergraph.cli import main; sys.exit(main(['visualize','examples/vulnerable-fastapi','--with-source']))"
grep -io "supersecret\|password123\|sk-[a-zA-Z0-9]\{10,\}\|AKIA[0-9A-Z]\{16\}" examples/vulnerable-fastapi/.cybergraph/report.html
```
Expected: exit 0; the grep prints NOTHING (redaction intact). If it leaks, STOP (status BLOCKED), do not commit.

- [ ] **Step 5: Commit**

```bash
git add tests/test_report_reconcile.py
git commit -m "test(report): composition guard for reconciled report"
```

---

## Self-Review

**1. Spec coverage:**
- Posture grade + verdict + severity bar → Task 1. ✓
- Delta strip → Task 2. ✓
- Honest cap footer → Task 3. ✓
- Print stylesheet (overriding dark theme) → Task 4. ✓
- Drops (sortable, asset extraction) → not planned, by design. ✓
- Reuse their tokens / no hardcoded light backgrounds → chrome uses `--panel`/`--border`/`--fg`/`--muted`; severity colors are inline saturated accents on segments + the grade badge (foreground `#fff` on saturated bg, not a panel background). Task 1 Step 5 explicitly re-runs `test_report_visual_identity`. ✓
- Signature unchanged → `_render_html` gains params but `generate_html_report` is untouched externally. ✓
- Escaping / self-contained / redaction → Task 5 composition + smoke. ✓
- Grade scale exact → Task 1 boundary tests. ✓

**2. Placeholder scan:** No TBD/TODO. Every code step has real code. The one soft spot — whether `test_report_visual_identity` objects to the new CSS — is handled explicitly in Task 1 Step 5 with a concrete decision rule (move flagged value to a token; never weaken their test), not a vague "handle errors".

**3. Type consistency:** `_render_html` param order updated consistently in Task 1 (`sev_counts`) and Task 2 (`delta_html`) — both tasks show the exact call-site edit. `_posture_section(counts, top_risks, counts_by_sev, delta_html)` matches between Task 1 definition, Task 1 wiring (delta `""`), and Task 2 wiring (real `delta_html`). `_findings_footer(shown, total)` matches Task 3 definition and call site. Function names all carry the leading underscore matching their module convention.

Known risk flagged for the implementer/reviewer: if `test_report_visual_identity` scans the inline `<style>` for hardcoded background hex and objects to `.delta-strip`/badge, the fallback (tokens for chrome; inline styles for severity accents) is already the chosen design — Task 1/2 note the fallback. The composition test's token regex requires a leading letter after `__` to avoid false-positives on vendored `cytoscape.min.js` underscore runs.

# Usability Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give CyberGraph one `analyze` command and one shared result object that the CLI (text + `--json`), the HTML report, and the MCP server all consume, plus small friction-killers (`.env` loader, `config show`, consistent `repo` args, truncation/guidance banners).

**Architecture:** Build the graph once, fan in the existing analysis functions into a typed `AnalysisResult`, and render that one object to four surfaces. Everything is additive — existing commands keep working; no CLI-framework migration; no new hard dependencies.

**Tech Stack:** Python 3.10+, stdlib only (dataclasses, json, argparse), SQLite via existing `GraphStore`; pytest for tests; optional `fastmcp` for the MCP surface (already optional).

## Global Constraints

- No new hard runtime dependencies (colour/tables and `.env` parsing are hand-rolled stdlib).
- Additive & non-breaking: every existing command and its current arguments keep working.
- Deterministic default path: LLM stays opt-in; nothing here requires an API key.
- Commits authored as the user only — **no `Co-Authored-By` / Claude attribution trailer**.
- Tests run with `PYTHONPATH=src` (Windows PowerShell: `$env:PYTHONPATH="$PWD\src"`); the suite is currently 164 passed / 1 skipped and must stay green.
- Reuse existing functions verbatim — do not reimplement analyses:
  - `cybergraph.build.build_graph(repo_root: Path) -> dict[str,int]` (keys `nodes`,`edges`,`findings`)
  - `cybergraph.security.investigate.collect_top_risks(repo_root, limit=10) -> list[TopRisk]` where `TopRisk(category:str, title:str, risk_score:int, risk_label:str, detail:str)`
  - `cybergraph.security.attack_paths.find_attack_paths(repo_root, max_depth=8, limit=20, interprocedural=True) -> list[AttackPath]`
  - `cybergraph.security.secrets.find_secret_exposures(repo_root) -> list[SecretExposure]`
  - `cybergraph.security.sca.prioritize_vulnerabilities(repo_root) -> list[VulnPriority]`
  - `cybergraph.security.iac_paths.find_iac_attack_paths(repo_root, max_depth=6, limit=20) -> list[IacAttackPath]`
  - `cybergraph.security.cloud.find_cloud_code_paths(repo_root) -> list[CloudCodePath]`
  - `cybergraph.security.layers.summarize_layers(repo_root) -> list[LayerSummary]` where `LayerSummary(key,label,description,node_count,edge_count,finding_count)`
  - `cybergraph.config.load_config(repo_root) -> CyberGraphConfig`
  - `cybergraph.llm.load_llm_config_from_env() -> LLMConfig | None`
  - `cybergraph.graph.GraphStore.open_for_repo(repo_root)`

## File Structure

- Create `src/cybergraph/report_model.py` — `AnalysisResult` dataclass + `to_json`.
- Create `src/cybergraph/orchestrator.py` — `run_full_analysis` (build once, fan in).
- Create `src/cybergraph/output.py` — `render_text` + colour/table helpers.
- Create `src/cybergraph/env.py` — `load_dotenv`.
- Modify `src/cybergraph/cli.py` — `analyze` + `config show` commands, `_resolve_repo`, `--json/--no-color`, truncation + "not built" banners, call `load_dotenv` at startup.
- Modify `src/cybergraph/mcp_server.py` — new tools returning `to_json()`.
- Tests: `tests/test_report_model.py`, `tests/test_orchestrator.py`, `tests/test_output.py`, `tests/test_env.py`, `tests/test_cli_analyze.py`, `tests/test_cli_config.py`, `tests/test_mcp_parity.py`.

---

### Task 1: Shared result model (`report_model.py`)

**Files:**
- Create: `src/cybergraph/report_model.py`
- Test: `tests/test_report_model.py`

**Interfaces:**
- Produces: `AnalysisResult` dataclass with fields `repo:str`, `counts:dict`, `top_risks:list`, `attack_paths:list`, `secret_exposures:list`, `sca:list`, `iac_paths:list`, `cloud_code_paths:list`, `layers:list`, `truncated:bool`, `timings:dict[str,float]`, `llm_configured:bool`, `errors:dict[str,str]`. And `to_json(result: AnalysisResult) -> dict`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report_model.py
from cybergraph.report_model import AnalysisResult, to_json
from cybergraph.security.investigate import TopRisk
from cybergraph.security.layers import LayerSummary


def _sample() -> AnalysisResult:
    return AnalysisResult(
        repo="/x/app",
        counts={"nodes": 5, "edges": 3, "findings": 2},
        top_risks=[TopRisk("attack-path", "route -> sink", 82, "high", "why")],
        attack_paths=[object()],
        secret_exposures=[],
        sca=[object(), object()],
        iac_paths=[],
        cloud_code_paths=[],
        layers=[LayerSummary("sink", "Sensitive Sinks", "d", 1, 1, 1)],
        truncated=True,
        timings={"build": 0.1},
        llm_configured=False,
        errors={},
    )


def test_to_json_has_stable_schema_and_counts():
    doc = to_json(_sample())
    assert doc["schema"] == "cybergraph.analysis/1"
    assert doc["repo"] == "/x/app"
    assert doc["counts"] == {"nodes": 5, "edges": 3, "findings": 2}
    assert doc["truncated"] is True
    assert doc["llm_configured"] is False
    # top risks serialized fully
    assert doc["top_risks"][0] == {
        "category": "attack-path", "title": "route -> sink",
        "risk_score": 82, "risk_label": "high", "detail": "why",
    }
    # component lists represented as counts in v1
    assert doc["component_counts"] == {
        "attack_paths": 1, "secret_exposures": 0, "sca": 2,
        "iac_paths": 0, "cloud_code_paths": 0,
    }
    assert doc["layers"][0]["key"] == "sink"
    assert doc["errors"] == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_report_model.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'cybergraph.report_model'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/cybergraph/report_model.py
"""Shared analysis result consumed by the CLI, HTML report, and MCP server."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCHEMA = "cybergraph.analysis/1"


@dataclass(frozen=True)
class AnalysisResult:
    repo: str
    counts: dict[str, int]
    top_risks: list[Any]
    attack_paths: list[Any]
    secret_exposures: list[Any]
    sca: list[Any]
    iac_paths: list[Any]
    cloud_code_paths: list[Any]
    layers: list[Any]
    truncated: bool = False
    timings: dict[str, float] = field(default_factory=dict)
    llm_configured: bool = False
    errors: dict[str, str] = field(default_factory=dict)


def to_json(result: AnalysisResult) -> dict[str, Any]:
    """Stable, versioned JSON view (schema ``cybergraph.analysis/1``)."""
    return {
        "schema": SCHEMA,
        "repo": result.repo,
        "counts": dict(result.counts),
        "truncated": bool(result.truncated),
        "llm_configured": bool(result.llm_configured),
        "timings": {k: round(v, 4) for k, v in result.timings.items()},
        "errors": dict(result.errors),
        "top_risks": [
            {
                "category": r.category, "title": r.title,
                "risk_score": r.risk_score, "risk_label": r.risk_label,
                "detail": r.detail,
            }
            for r in result.top_risks
        ],
        "component_counts": {
            "attack_paths": len(result.attack_paths),
            "secret_exposures": len(result.secret_exposures),
            "sca": len(result.sca),
            "iac_paths": len(result.iac_paths),
            "cloud_code_paths": len(result.cloud_code_paths),
        },
        "layers": [
            {
                "key": l.key, "label": l.label,
                "node_count": l.node_count, "edge_count": l.edge_count,
                "finding_count": l.finding_count,
            }
            for l in result.layers
        ],
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_report_model.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/report_model.py tests/test_report_model.py
git commit -m "feat(report): add shared AnalysisResult model with stable JSON schema"
```

---

### Task 2: Orchestrator (`orchestrator.py`)

**Files:**
- Create: `src/cybergraph/orchestrator.py`
- Test: `tests/test_orchestrator.py`

**Interfaces:**
- Consumes: `AnalysisResult` (Task 1); `build_graph`, `collect_top_risks`, `find_attack_paths`, `find_secret_exposures`, `prioritize_vulnerabilities`, `find_iac_attack_paths`, `find_cloud_code_paths`, `summarize_layers`, `load_llm_config_from_env`, `GraphStore` (Global Constraints).
- Produces: `run_full_analysis(repo_root, *, limit: int = 10) -> AnalysisResult`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_orchestrator.py
from pathlib import Path

from cybergraph.orchestrator import run_full_analysis
from cybergraph.report_model import AnalysisResult


def _build_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/users')\n"
        "def list_users(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    return repo


def test_run_full_analysis_builds_once_and_populates(tmp_path: Path):
    repo = _build_repo(tmp_path)
    result = run_full_analysis(repo)
    assert isinstance(result, AnalysisResult)
    assert result.counts["nodes"] > 0
    assert result.layers  # summarize_layers always returns the ontology layers
    assert "build" in result.timings
    assert result.errors == {}  # nothing failed on a clean run


def test_one_failing_stage_is_isolated(tmp_path: Path, monkeypatch):
    repo = _build_repo(tmp_path)
    import cybergraph.orchestrator as orch

    def _boom(_repo):
        raise RuntimeError("stage down")

    monkeypatch.setattr(orch, "find_secret_exposures", _boom)
    result = run_full_analysis(repo)
    assert "secret_exposures" in result.errors
    assert result.secret_exposures == []
    assert result.counts["nodes"] > 0  # run still completed
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_orchestrator.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'cybergraph.orchestrator'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/cybergraph/orchestrator.py
"""Run every analysis once over a single graph build and return one result."""

from __future__ import annotations

import time
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.llm import load_llm_config_from_env
from cybergraph.report_model import AnalysisResult
from cybergraph.security.attack_paths import find_attack_paths
from cybergraph.security.cloud import find_cloud_code_paths
from cybergraph.security.iac_paths import find_iac_attack_paths
from cybergraph.security.investigate import collect_top_risks
from cybergraph.security.layers import summarize_layers
from cybergraph.security.sca import prioritize_vulnerabilities
from cybergraph.security.secrets import find_secret_exposures


def _stage(name, fn, timings, errors, default):
    """Run one analysis stage, isolating failures so the run always completes."""
    start = time.perf_counter()
    try:
        return fn()
    except Exception as exc:  # one bad stage must not abort the whole analysis
        errors[name] = f"{type(exc).__name__}: {exc}"
        return default
    finally:
        timings[name] = time.perf_counter() - start


def run_full_analysis(repo_root: Path, *, limit: int = 10) -> AnalysisResult:
    repo_root = Path(repo_root).resolve()
    timings: dict[str, float] = {}
    errors: dict[str, str] = {}

    counts = _stage("build", lambda: build_graph(repo_root), timings, errors,
                    {"nodes": 0, "edges": 0, "findings": 0})

    top_risks = _stage("top_risks", lambda: collect_top_risks(repo_root, limit=limit),
                        timings, errors, [])
    attack_paths = _stage("attack_paths", lambda: find_attack_paths(repo_root),
                          timings, errors, [])
    secret_exposures = _stage("secret_exposures", lambda: find_secret_exposures(repo_root),
                              timings, errors, [])
    sca = _stage("sca", lambda: prioritize_vulnerabilities(repo_root), timings, errors, [])
    iac_paths = _stage("iac_paths", lambda: find_iac_attack_paths(repo_root),
                       timings, errors, [])
    cloud_code_paths = _stage("cloud_code_paths", lambda: find_cloud_code_paths(repo_root),
                              timings, errors, [])
    layers = _stage("layers", lambda: summarize_layers(repo_root), timings, errors, [])

    return AnalysisResult(
        repo=str(repo_root),
        counts=counts,
        top_risks=top_risks,
        attack_paths=attack_paths,
        secret_exposures=secret_exposures,
        sca=sca,
        iac_paths=iac_paths,
        cloud_code_paths=cloud_code_paths,
        layers=layers,
        truncated=False,
        timings=timings,
        llm_configured=load_llm_config_from_env() is not None,
        errors=errors,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_orchestrator.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/orchestrator.py tests/test_orchestrator.py
git commit -m "feat(analysis): add run_full_analysis orchestrator (build once, fan in, isolate stage errors)"
```

---

### Task 3: Text/colour renderer (`output.py`)

**Files:**
- Create: `src/cybergraph/output.py`
- Test: `tests/test_output.py`

**Interfaces:**
- Consumes: `AnalysisResult` (Task 1).
- Produces: `render_text(result: AnalysisResult, *, color: bool = True) -> str`; `should_color(stream=None) -> bool`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_output.py
import os

from cybergraph.output import render_text, should_color
from cybergraph.report_model import AnalysisResult
from cybergraph.security.investigate import TopRisk


def _result(**over):
    base = dict(
        repo="/x/app", counts={"nodes": 5, "edges": 3, "findings": 2},
        top_risks=[TopRisk("attack-path", "route -> sink", 82, "high", "reachable")],
        attack_paths=[1], secret_exposures=[], sca=[], iac_paths=[], cloud_code_paths=[],
        layers=[], truncated=False, timings={}, llm_configured=False, errors={},
    )
    base.update(over)
    return AnalysisResult(**base)


def test_render_text_plain_lists_top_risks_and_counts():
    out = render_text(_result(), color=False)
    assert "route -> sink" in out
    assert "HIGH" in out and "82" in out
    assert "Nodes: 5" in out
    assert "\x1b[" not in out  # no ANSI when color=False


def test_render_text_color_emits_ansi():
    out = render_text(_result(), color=True)
    assert "\x1b[" in out


def test_truncation_banner_shown_only_when_truncated():
    assert "truncated" in render_text(_result(truncated=True), color=False).lower()
    assert "truncated" not in render_text(_result(truncated=False), color=False).lower()


def test_should_color_respects_no_color_env(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert should_color() is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_output.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'cybergraph.output'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/cybergraph/output.py
"""Human-facing rendering of an AnalysisResult (colour + plain, no dependencies)."""

from __future__ import annotations

import os
import sys
from typing import TextIO

from cybergraph.report_model import AnalysisResult

_LEVEL_COLOR = {"critical": "31", "high": "31", "medium": "33", "low": "36"}


def should_color(stream: TextIO | None = None) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def _c(text: str, code: str, color: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if color else text


def render_text(result: AnalysisResult, *, color: bool = True) -> str:
    lines: list[str] = []
    lines.append(_c(f"CyberGraph analysis — {result.repo}", "1", color))
    c = result.counts
    lines.append(
        f"Nodes: {c.get('nodes', 0)} | Edges: {c.get('edges', 0)} | "
        f"Findings: {c.get('findings', 0)}"
    )
    if result.truncated:
        lines.append(_c("! graph truncated — raise --max-nodes to see more", "33", color))

    lines.append("")
    lines.append(_c(f"Top risks ({len(result.top_risks)}):", "1", color))
    if not result.top_risks:
        lines.append("  none found")
    for r in result.top_risks:
        label = _c(f"{r.risk_label.upper()} {r.risk_score}/100",
                   _LEVEL_COLOR.get(r.risk_label.lower(), "0"), color)
        lines.append(f"  [{label}] {r.category}: {r.title}")
        if r.detail:
            lines.append(f"      {r.detail}")

    if result.errors:
        lines.append("")
        lines.append(_c(f"Stages with errors: {', '.join(sorted(result.errors))}", "33", color))
    return "\n".join(lines)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_output.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/output.py tests/test_output.py
git commit -m "feat(cli): add colour/plain AnalysisResult text renderer"
```

---

### Task 4: `.env` loader (`env.py`)

**Files:**
- Create: `src/cybergraph/env.py`
- Test: `tests/test_env.py`

**Interfaces:**
- Produces: `load_dotenv(repo_root: Path | None = None) -> int` (returns number of vars set).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_env.py
from pathlib import Path

from cybergraph.env import load_dotenv


def test_load_dotenv_sets_absent_and_ignores_comments(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("CYBERGRAPH_LLM_API_KEY", raising=False)
    (tmp_path / ".env").write_text(
        "# a comment\n"
        "\n"
        'CYBERGRAPH_LLM_API_KEY="sk-abc123"\n'
        "CYBERGRAPH_LLM_PROVIDER=anthropic\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    n = load_dotenv(tmp_path)
    assert n == 2
    import os
    assert os.environ["CYBERGRAPH_LLM_API_KEY"] == "sk-abc123"  # quotes stripped
    assert os.environ["CYBERGRAPH_LLM_PROVIDER"] == "anthropic"


def test_load_dotenv_never_overrides_existing_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CYBERGRAPH_LLM_PROVIDER", "openai")
    (tmp_path / ".env").write_text("CYBERGRAPH_LLM_PROVIDER=anthropic\n", encoding="utf-8")
    load_dotenv(tmp_path)
    import os
    assert os.environ["CYBERGRAPH_LLM_PROVIDER"] == "openai"  # real env wins


def test_load_dotenv_noop_when_absent(tmp_path: Path):
    assert load_dotenv(tmp_path) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_env.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'cybergraph.env'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/cybergraph/env.py
"""Minimal .env loader (no dependency). Sets only vars absent from the environment."""

from __future__ import annotations

import os
from pathlib import Path


def _parse(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            out[key] = value
    return out


def load_dotenv(repo_root: Path | None = None) -> int:
    """Load ``.env`` from ``repo_root`` and cwd; set only keys not already set.

    Returns the number of environment variables newly set. Never overrides an
    existing environment value; non-fatal on any read/parse error."""
    candidates = []
    if repo_root is not None:
        candidates.append(Path(repo_root) / ".env")
    candidates.append(Path.cwd() / ".env")

    set_count = 0
    seen: set[Path] = set()
    for path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved in seen or not resolved.is_file():
            continue
        seen.add(resolved)
        try:
            pairs = _parse(resolved.read_text(encoding="utf-8"))
        except OSError:
            continue
        for key, value in pairs.items():
            if key not in os.environ:
                os.environ[key] = value
                set_count += 1
    return set_count
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_env.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/env.py tests/test_env.py
git commit -m "feat(cli): add minimal .env loader for CYBERGRAPH_LLM_* config"
```

---

### Task 5: `analyze` command + `.env` startup hook (`cli.py`)

**Files:**
- Modify: `src/cybergraph/cli.py` (add parser in `build_parser` before `return parser`; add dispatch branch in `main`; call `load_dotenv` at the top of `main`)
- Test: `tests/test_cli_analyze.py`

**Interfaces:**
- Consumes: `run_full_analysis` (Task 2), `render_text`/`should_color` (Task 3), `to_json` (Task 1), `load_dotenv` (Task 4).
- Produces: CLI command `analyze [repo] [--json] [--limit N] [--no-color] [--no-report]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli_analyze.py
import json
from pathlib import Path

import pytest

from cybergraph.cli import main


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


def test_analyze_text_prints_summary(tmp_path, capsys):
    repo = _repo(tmp_path)
    code = main(["analyze", str(repo), "--no-color", "--no-report"])
    out = capsys.readouterr().out
    assert code == 0
    assert "CyberGraph analysis" in out
    assert "Top risks" in out


def test_analyze_json_is_valid_and_versioned(tmp_path, capsys):
    repo = _repo(tmp_path)
    code = main(["analyze", str(repo), "--json", "--no-report"])
    out = capsys.readouterr().out
    assert code == 0
    doc = json.loads(out)
    assert doc["schema"] == "cybergraph.analysis/1"
    assert doc["counts"]["nodes"] > 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli_analyze.py -v`
Expected: FAIL — `argument command: invalid choice: 'analyze'`

- [ ] **Step 3: Write minimal implementation**

In `build_parser`, immediately before `return parser`, add:

```python
    analyze = sub.add_parser(
        "analyze", help="Build the graph and run every analysis, then print top risks"
    )
    analyze.add_argument("repo", nargs="?", default=".", help="Repository root to analyze")
    analyze.add_argument("--json", action="store_true", help="Emit the result as JSON")
    analyze.add_argument("--limit", type=int, default=10, help="Maximum top risks to show")
    analyze.add_argument("--no-color", action="store_true", help="Disable coloured output")
    analyze.add_argument("--no-report", action="store_true", help="Skip writing the HTML report")
```

At the very top of `main` (immediately after `parser = build_parser()` and before `args = parser.parse_args(argv)`), add the `.env` hook:

```python
    from .env import load_dotenv
    load_dotenv(Path(".").resolve())
```

Add this dispatch branch to the `if/elif` chain in `main` (e.g. right before the final `else`):

```python
    elif args.command == "analyze":
        import json as _json

        from .orchestrator import run_full_analysis
        from .output import render_text, should_color
        from .report_model import to_json

        result = run_full_analysis(repo, limit=args.limit)
        if args.json:
            print(_json.dumps(to_json(result), indent=2, sort_keys=True))
        else:
            color = (not args.no_color) and should_color()
            print(render_text(result, color=color))
            if not args.no_report:
                from .visualize import generate_html_report

                output = generate_html_report(repo, repo / ".cybergraph" / "report.html")
                print(f"\nHTML report: {output}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli_analyze.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/cli.py tests/test_cli_analyze.py
git commit -m "feat(cli): add 'analyze' one-shot command and .env startup loading"
```

---

### Task 6: `config show` command + "graph not built" guidance (`cli.py`)

**Files:**
- Modify: `src/cybergraph/cli.py` (add `config` parser with a `show` sub-action; add dispatch; add a graph-exists guard helper)
- Test: `tests/test_cli_config.py`

**Interfaces:**
- Consumes: `load_config` (Global Constraints), `load_llm_config_from_env`, `GraphStore`.
- Produces: CLI command `config show [repo]`; helper `_graph_built(repo: Path) -> bool`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli_config.py
from pathlib import Path

from cybergraph.cli import main


def test_config_show_reports_llm_and_graph_state(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("CYBERGRAPH_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("CYBERGRAPH_LLM_API_KEY", raising=False)
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / ".cybergraph.toml").write_text(
        "[security]\nsinks = [\"run_report\"]\n", encoding="utf-8"
    )
    code = main(["config", "show", str(repo)])
    out = capsys.readouterr().out
    assert code == 0
    assert "LLM configured: no" in out
    assert "Graph built: no" in out
    assert "run_report" in out  # effective custom sink shown
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli_config.py -v`
Expected: FAIL — `argument command: invalid choice: 'config'`

- [ ] **Step 3: Write minimal implementation**

In `build_parser`, before `return parser`, add:

```python
    config_cmd = sub.add_parser("config", help="Inspect CyberGraph configuration")
    config_sub = config_cmd.add_subparsers(dest="config_action", required=True)
    config_show = config_sub.add_parser("show", help="Show the effective configuration")
    config_show.add_argument("repo", nargs="?", default=".", help="Repository root")
```

Add a module-level helper near `_validate_json_report`:

```python
def _graph_built(repo: Path) -> bool:
    return (repo / ".cybergraph" / "graph.db").is_file()
```

Add this dispatch branch in `main`:

```python
    elif args.command == "config":
        from .config import load_config
        from .llm import load_llm_config_from_env

        cfg = load_config(repo)
        print(f"Repo: {repo}")
        print(f"LLM configured: {'yes' if load_llm_config_from_env() is not None else 'no'}")
        print(f"Graph built: {'yes' if _graph_built(repo) else 'no'}")
        print(f"Ignored paths: {list(cfg.ignored_paths)}")
        print(f"Custom sinks: {list(cfg.custom_sinks)}")
        print(f"Suppressed rules: {list(cfg.suppressed_rules)}")
        print(f"Suppressed paths: {list(cfg.suppressed_paths)}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli_config.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/cli.py tests/test_cli_config.py
git commit -m "feat(cli): add 'config show' and a graph-built helper"
```

---

### Task 7: "Graph not built" guidance on read commands (`cli.py`)

**Files:**
- Modify: `src/cybergraph/cli.py` (guard `explain`, `paths`, `layers`, `sca` dispatch branches)
- Test: extend `tests/test_cli_config.py` with a new test (same file is fine — related CLI-UX guardrails)

**Interfaces:**
- Consumes: `_graph_built` (Task 6).

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_cli_config.py
from pathlib import Path

from cybergraph.cli import main


def test_read_command_without_graph_prints_guidance(tmp_path, capsys):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    code = main(["layers", "--repo", str(repo)])
    out = capsys.readouterr().out
    assert code == 0
    assert "cybergraph build" in out  # tells the user to build first
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli_config.py::test_read_command_without_graph_prints_guidance -v`
Expected: FAIL — output is a bare empty layer summary with no guidance.

- [ ] **Step 3: Write minimal implementation**

At the start of `main`, immediately after `repo = Path(getattr(args, "repo", ".")).resolve()`, add a guard for the read-only commands:

```python
    _READ_COMMANDS = {"explain", "paths", "layers", "sca", "ask"}
    if args.command in _READ_COMMANDS and not _graph_built(repo):
        print(f"No graph found at {repo / '.cybergraph' / 'graph.db'}. "
              f"Run 'cybergraph build {repo}' first (or 'cybergraph analyze {repo}').")
        return 0
```

(`_graph_built` is defined in Task 6; this task depends on Task 6 being merged first.)

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli_config.py -v`
Expected: PASS (both config tests)

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/cli.py tests/test_cli_config.py
git commit -m "feat(cli): guide users to build the graph before read-only commands"
```

---

### Task 8: MCP full-workflow parity (`mcp_server.py`)

**Files:**
- Modify: `src/cybergraph/mcp_server.py` (add tools inside the existing `if FastMCP is not None:` block)
- Test: `tests/test_mcp_parity.py`

**Interfaces:**
- Consumes: `run_full_analysis` (Task 2), `to_json` (Task 1), `collect_top_risks`, `find_secret_exposures`, `prioritize_vulnerabilities`, `find_iac_attack_paths`.
- Produces: MCP tools `analyze_repo_tool`, `top_risks_tool`, `secret_exposures_tool`, `prioritize_dependencies_tool`, `iac_attack_paths_tool`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mcp_parity.py
import pytest


def test_mcp_exposes_full_workflow_tools():
    pytest.importorskip("fastmcp")
    from cybergraph import mcp_server

    # The new orchestrator-backed tool functions are defined at import time.
    for name in [
        "analyze_repo_tool",
        "top_risks_tool",
        "secret_exposures_tool",
        "prioritize_dependencies_tool",
        "iac_attack_paths_tool",
    ]:
        assert hasattr(mcp_server, name), f"missing MCP tool: {name}"


def test_analyze_repo_tool_returns_versioned_json(tmp_path):
    pytest.importorskip("fastmcp")
    from cybergraph import mcp_server

    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/x')\ndef h(request):\n    return db.execute(request.query['q'])\n",
        encoding="utf-8",
    )
    doc = mcp_server.analyze_repo_tool(str(repo))
    assert doc["schema"] == "cybergraph.analysis/1"
    assert doc["counts"]["nodes"] > 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_mcp_parity.py -v`
Expected: FAIL — `AttributeError: module 'cybergraph.mcp_server' has no attribute 'analyze_repo_tool'` (or skipped if `fastmcp` absent; install with `pip install fastmcp` to run it).

- [ ] **Step 3: Write minimal implementation**

Inside the `if FastMCP is not None:` block in `mcp_server.py`, after the existing `grounded_security_answer_tool`, add:

```python
    @mcp.tool()
    def analyze_repo_tool(repo_root: str = ".", limit: int = 10) -> dict[str, Any]:
        """Build the graph and run every analysis; return the full result as JSON."""
        from .orchestrator import run_full_analysis
        from .report_model import to_json

        return to_json(run_full_analysis(Path(repo_root).resolve(), limit=limit))

    @mcp.tool()
    def top_risks_tool(repo_root: str = ".", limit: int = 10) -> dict[str, Any]:
        """Return the ranked top security risks across all graph layers."""
        from .security.investigate import collect_top_risks

        risks = collect_top_risks(Path(repo_root).resolve(), limit=limit)
        return {"top_risks": [
            {"category": r.category, "title": r.title, "risk_score": r.risk_score,
             "risk_label": r.risk_label, "detail": r.detail}
            for r in risks
        ]}

    @mcp.tool()
    def secret_exposures_tool(repo_root: str = ".") -> dict[str, Any]:
        """Return prioritized secret-exposure paths (reachable secret -> sink)."""
        from .security.secrets import find_secret_exposures, format_secret_exposures

        exposures = find_secret_exposures(Path(repo_root).resolve())
        return {"count": len(exposures), "text": format_secret_exposures(exposures)}

    @mcp.tool()
    def prioritize_dependencies_tool(repo_root: str = ".") -> dict[str, Any]:
        """Return dependency vulnerabilities ranked by severity x reachability."""
        from .security.sca import format_sca, prioritize_vulnerabilities

        priorities = prioritize_vulnerabilities(Path(repo_root).resolve())
        return {"count": len(priorities), "text": format_sca(priorities)}

    @mcp.tool()
    def iac_attack_paths_tool(repo_root: str = ".", max_depth: int = 6) -> dict[str, Any]:
        """Return cloud attack paths (public exposure -> privileged IaC resource)."""
        from .security.iac_paths import find_iac_attack_paths, format_iac_attack_paths

        paths = find_iac_attack_paths(Path(repo_root).resolve(), max_depth=max_depth)
        return {"count": len(paths), "text": format_iac_attack_paths(paths)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_mcp_parity.py -v`
Expected: PASS (or SKIPPED if `fastmcp` is not installed)

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/mcp_server.py tests/test_mcp_parity.py
git commit -m "feat(mcp): expose analyze/top-risks/secrets/sca/iac tools for full-workflow parity"
```

---

### Task 9: Full-suite verification + docs note

**Files:**
- Modify: `README.md` (add `analyze` + `config show` to the Quick start)
- Modify: `docs/architecture.md` (one line: "one `analyze` command + shared `AnalysisResult` consumed by CLI/report/MCP")

- [ ] **Step 1: Run the full suite**

Run (PowerShell): `$env:PYTHONPATH="$PWD\src"; python -m pytest -q`
Expected: all prior tests plus the new ones PASS (target ≥ 176 passed / 1 skipped), no regressions.

- [ ] **Step 2: End-to-end smoke**

Run: `python -c "import sys; from cybergraph.cli import main; sys.exit(main(['analyze','examples/vulnerable-fastapi','--no-color','--no-report']))"`
Expected: prints "CyberGraph analysis …", "Top risks (N):" with at least one risk.

Run: `python -c "import sys; from cybergraph.cli import main; sys.exit(main(['analyze','examples/vulnerable-fastapi','--json','--no-report']))" | python -m json.tool`
Expected: valid JSON with `"schema": "cybergraph.analysis/1"`.

- [ ] **Step 3: Update docs**

In `README.md` Quick start, add near the top:
```
cybergraph analyze .          # build + run every analysis, print top risks
cybergraph config show .      # inspect effective config + LLM/graph state
```
In `docs/architecture.md`, add under "Pipeline": `6. One 'analyze' command builds once and fans every analysis into a shared AnalysisResult consumed by the CLI, HTML report, and MCP server.`

- [ ] **Step 4: Commit**

```bash
git add README.md docs/architecture.md
git commit -m "docs: document the analyze command and shared analysis result"
```

---

## Self-Review

**Spec coverage:**
- `analyze` orchestrator + shared `AnalysisResult` → Tasks 1, 2, 5. ✓
- `--json`/`--format` + coloured/tabular output → Tasks 3, 5 (`--json`, `--no-color`; text renderer). ✓
- Consistent `repo` positional → **partially**: `analyze`/`config show` use positional; the spec's "positional on every command" is deferred detail — the dispatch already unifies via `args.repo`, and every command in Task 5/6 uses positional `repo`. Existing flag-only commands keep working. (If full positional parity across all 29 commands is wanted, add a follow-up task; it is low-risk mechanical argparse edits.)
- `.env` loader → Task 4 + startup hook in Task 5. ✓
- `config show` → Task 6. ✓
- Truncation banner → Task 3 (renderer shows it when `result.truncated`). NOTE: `run_full_analysis` currently sets `truncated=False`; wiring the real cap flag from `build_graph_data` is a follow-up (the banner path + test exist now). ✓ (banner mechanism), follow-up (real flag).
- "Graph not built" guidance → Task 7. ✓
- MCP parity → Task 8. ✓
- Tests + verification → each task + Task 9. ✓

**Placeholder scan:** no TBD/TODO; every code step shows complete code. ✓

**Type consistency:** `AnalysisResult` fields and `to_json` keys match across Tasks 1/2/3/5/8; `TopRisk`/`LayerSummary` field names match the Global Constraints signatures; `_graph_built` defined in Task 6 and consumed in Task 7 (ordering noted). ✓

**Two follow-ups surfaced (small, optional, out of this plan's critical path):** (a) thread the real truncation flag from `build_graph_data` into `AnalysisResult.truncated`; (b) make `repo` positional across all remaining commands. Both are mechanical; add as a Spec-1.1 if desired.

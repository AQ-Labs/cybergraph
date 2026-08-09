# Verdict Surfaces Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the verdict through the MCP surface and close out the plan's CI/audit/docs — completing the entire 20-task verdict-core roadmap. The MCP tool mirrors `cybergraph check --json`; CI runs `cybergraph check` on PRs as a non-gating notification; the audit and README are made honest.

**Architecture:** `mcp_server.py` gains a thin `@mcp.tool()` over the shared `check_change` orchestrator (C6: no CLI import). The CI workflow keeps its inventory-only SARIF filter and adds a PR `check` step. Docs record honest statuses and usage.

**Tech Stack:** Python 3.10–3.13, standard library + FastMCP (optional, import-guarded), pytest, ruff, GitHub Actions YAML.

**Spec:** `docs/superpowers/specs/2026-08-09-verdict-surfaces-design.md`
**Parent roadmap:** `docs/superpowers/plans/2026-08-08-verdict-core.md` (Task 1 below is that plan's Task 19 verbatim; Task 2 is that plan's Task 20 with its SARIF step revised per a ruling — see Task 2).

## Global Constraints

- **Python 3.10–3.13.** `from __future__ import annotations` in any new/modified module that needs it.
- **Zero runtime dependencies** on the default path; FastMCP is optional and import-guarded (`if FastMCP is not None:`). Tests touching MCP start with `pytest.importorskip("fastmcp")`.
- **Ruff:** line-length 100, `select = ["E","F","I","N","W","UP"]`.
- **No "safe to ship"** anywhere in `src/` or the README (case-insensitive); the guard test from the verdict-layer slice stays green. The README must not claim the MCP tool provides automatic verification.
- **C6:** `mcp_server.py` must not import from `cli.py`; both call `check_change`.
- **Commits:** author `Laraib <lxh417bham@gmail.com>` only. Never `azizur@sirio-strategies.com`, never `-c user.email=…`, no `Co-Authored-By`, no AI attribution. Multiple small commits.
- **Baseline:** full suite green (1153 passed, 1 skipped); `run_precision.py` GATE PASSED exit 0; `run_eval.py` 1.0/1.0/1.0; mutation harness all CAUGHT. None may regress. Revert any `benchmark/results.json` churn before committing.

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `src/cybergraph/mcp_server.py` (modify) | `check_change_tool` — MCP wrapper over `check_change` | 1 |
| `tests/test_mcp_parity.py` (append) | tool exposed, agrees with CLI `--json`, no CLI import | 1 |
| `.github/workflows/cybergraph.yml` (modify) | keep inventory-only SARIF filter; add PR `check` step | 2 |
| `tests/test_sarif.py` (append) | filter matches no verdict rule; `check` step present | 2 |
| `docs/CRITICAL_AUDIT.md` (modify) | honest audit statuses + before/after + shas | 2 |
| `README.md` (modify) | document `check`/`policy`, Phase 1 contract, verified languages | 2 |

---

## Task 1: MCP `check_change` tool

**Files:** Modify `src/cybergraph/mcp_server.py`; test `tests/test_mcp_parity.py` (append).

**Interfaces:** `check_change_tool(repo_root: str = ".", base: str = "") -> dict[str, Any]`, byte-identical to `cybergraph check --json`.

**Match this file's three conventions exactly:** tools are defined **inside** the `if FastMCP is not None:` block; the decorator is `@mcp.tool()`; the repository parameter is `repo_root: str = "."`. Every test starts with `pytest.importorskip("fastmcp")`.

**This is interoperability, not automatic verification.** An agent may never call it. Reliable invocation needs a client hook, which is Phase 2 — the README must not claim otherwise.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_mcp_parity.py`:

```python
def test_check_change_tool_is_exposed():
    pytest.importorskip("fastmcp")
    from cybergraph import mcp_server

    assert hasattr(mcp_server, "check_change_tool")


def test_check_change_tool_and_cli_agree(tmp_path):
    """Two surfaces over one orchestrator must never disagree."""
    pytest.importorskip("fastmcp")
    import contextlib
    import io
    import json as _json
    import subprocess

    from cybergraph import mcp_server
    from cybergraph.cli import main

    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "b"],
        cwd=tmp_path, check=True,
    )

    tool_result = mcp_server.check_change_tool(str(tmp_path))
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        main(["check", str(tmp_path), "--json"])
    assert tool_result == _json.loads(buffer.getvalue())


def test_mcp_server_does_not_import_from_the_cli():
    """C6: the MCP surface must not reach into CLI internals."""
    from pathlib import Path

    source = Path("src/cybergraph/mcp_server.py").read_text(encoding="utf-8")
    assert "from .cli import" not in source
    assert "from cybergraph.cli import" not in source
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_mcp_parity.py -v`
Expected: FAIL — `AttributeError: module 'cybergraph.mcp_server' has no attribute 'check_change_tool'` (or the whole file skips if `fastmcp` is absent — if so, note it and verify by importing the module directly that the attribute is missing pre-implementation).

- [ ] **Step 3: Write minimal implementation**

Add to the module-level imports at the top of `src/cybergraph/mcp_server.py`:

```python
from .security.check import check_change
from .security.verdict import verdict_to_dict
```

Add inside the `if FastMCP is not None:` block:

```python
    @mcp.tool()
    def check_change_tool(repo_root: str = ".", base: str = "") -> dict[str, Any]:
        """Check whether the current change preserves this project's guarantees.

        Returns the same object as `cybergraph check --json`. `state` is
        "accept" or "review"; `checks` gives a per-capability result; and
        `not_evaluated` lists what CyberGraph could not check on this change.
        An "accept" means the checks that ran found nothing — read
        `not_evaluated` before treating it as broader assurance.
        """
        verdict = check_change(Path(repo_root).resolve(), base=base or None)
        return verdict_to_dict(verdict)
```

**Note for the implementer:** confirm `Path` and `Any` are already imported at the top of `mcp_server.py` (they are used elsewhere); add whichever is missing. If `check_change_tool` must be reachable by the parity test even when it is defined inside the `if FastMCP is not None:` block, confirm the test environment has `fastmcp` installed (the tests `importorskip` it) — if `fastmcp` is not installed in this environment, the parity tests will skip; in that case ALSO add a direct import-level assertion path or run the equivalent check by importing `check_change`/`verdict_to_dict` and comparing, and report that the fastmcp-gated tests skipped here.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_mcp_parity.py -v` — PASS (or SKIPPED if `fastmcp` absent; report which).

- [ ] **Step 5: Commit**

```bash
git add src/cybergraph/mcp_server.py tests/test_mcp_parity.py
git commit -m "feat(mcp): expose check_change through the shared orchestrator"
```

---

## Task 2: CI, audit and docs (SARIF step revised)

**Files:** Modify `.github/workflows/cybergraph.yml`, `tests/test_sarif.py`, `docs/CRITICAL_AUDIT.md`, `README.md`.

**RULING that changes the parent plan's Task 20 Step 1:** the parent plan says *delete the SARIF filter — "the rule it filtered no longer exists."* That premise is false. The filter (`^CG-.*SINK-CALL$`) still matches four **live** rules — `CG-GO-SINK-CALL`, `CG-JAVA-SINK-CALL`, `CG-JS-SINK-CALL`, `CG-CSHARP-SINK-CALL` — the substring-based *inventory* findings from the four non-Python analyzers (inventory-grade until Phase 2). Python's verdict rules (`CG-SQL-EXEC`, `CG-CMD-EXEC`, `CG-PATH-TRAVERSAL`, `CG-TEMPLATE-INJECT`, `CG-CODE-EXEC`, `CG-DESERIALIZE`) do **not** match the filter and already reach code scanning. So §4.1 ("the tool deletes its own real findings") is already resolved for Python; deleting the filter now would upload the four non-Python substring-inventory rules as `medium` code-scanning results — reintroducing noise. **Keep the filter, scoped to inventory-only.**

- [ ] **Step 1: Keep the SARIF filter; guard that it never filters a verdict rule**

Do NOT remove the `Drop informational sink-inventory findings` step in `.github/workflows/cybergraph.yml`. Leave the `jq` filter (`test("^CG-.*SINK-CALL$")`) in place — it suppresses only the four non-Python inventory rules. Append to `tests/test_sarif.py`:

```python
def test_sarif_filter_targets_only_inventory_not_verdicts():
    """The CI filter must drop only *-SINK-CALL inventory, never an actionable
    verdict rule; and Python's verdict findings must reach code scanning."""
    import re
    from pathlib import Path

    workflow = Path(".github/workflows/cybergraph.yml").read_text(encoding="utf-8")
    # The filter still exists and still targets the inventory rule family.
    assert "SINK-CALL" in workflow, "the inventory filter must remain"
    filter_pattern = re.compile(r"CG-.\*SINK-CALL|\^CG-\.\*SINK-CALL\$")
    assert filter_pattern.search(workflow), "filter must target the *-SINK-CALL family"

    # No Python verdict rule id may match the filter pattern (they must upload).
    verdict_rules = (
        "CG-SQL-EXEC", "CG-CMD-EXEC", "CG-PATH-TRAVERSAL",
        "CG-TEMPLATE-INJECT", "CG-CODE-EXEC", "CG-DESERIALIZE",
    )
    for rule in verdict_rules:
        assert not re.fullmatch(r"CG-.*SINK-CALL", rule), rule


def test_workflow_runs_check_on_pull_requests():
    from pathlib import Path

    workflow = Path(".github/workflows/cybergraph.yml").read_text(encoding="utf-8")
    assert "cybergraph check" in workflow
    assert "merge-base" in workflow
```

**Note for the implementer:** if a test in `test_sarif.py` from an earlier plan asserts `"SINK-CALL" not in workflow` (the deletion the parent plan expected), that assertion now contradicts this ruling — update it to the kept-filter expectation above and note the change in the report. If no such test exists, just append the two tests above.

- [ ] **Step 2: Add `check` to CI in explicit merge-base mode**

C7: `--base` alone selected worktree mode, so the documented merge-base path was never exercised. After the build step in `.github/workflows/cybergraph.yml`:

```yaml
      - name: Check the change
        if: github.event_name == 'pull_request'
        env:
          BASE_REF: ${{ github.base_ref }}
        run: |
          git fetch --no-tags --depth=0 origin "$BASE_REF"
          cybergraph check . --mode merge-base --base "origin/$BASE_REF" \
            | tee cybergraph-check.txt
```

The full-depth `fetch` matters: a shallow checkout has no common ancestor, which now reports a failure rather than an empty diff. **No `--fail-on-review`** — a REVIEW stays a notification until the field false-positive rate is measured; gating here would contradict the plan's own trust argument.

- [ ] **Step 3: Transition audit statuses honestly**

In `docs/CRITICAL_AUDIT.md` use three states: `OPEN`, `MITIGATED`, `VERIFIED RESOLVED`. Set:
- §4.1 (substring detector) → **VERIFIED RESOLVED** — the Task 7 gate passed (recall ≥ 0.95, safe-abstention ≤ 0.15) for Python and the substring detector is gone; graphify scanned 2,739 → 0 confirmed findings. Add: the CI SARIF filter no longer suppresses any Python/verdict rule (verdicts reach code scanning); it now suppresses only the four non-Python `*-SINK-CALL` inventory rules, which remain inventory-grade until their Phase-2 verdict upgrade.
- §4.3 (suppressions ignored in ranking) → **VERIFIED RESOLVED** (Task 6 of verdict-core has a direct regression test).
- §4.2 (entrypoints), §4.4 (call resolution), §4.5 (four languages without parse trees) → **OPEN**. Note §4.5 is why the four non-Python inventory rules are still filtered from code scanning.

Append the measured before/after numbers and the commit sha for each.

- [ ] **Step 4: Update the README**

Add `cybergraph check` and `cybergraph policy` to Quick start (above `analyze`). Add a "Security policy" section covering `cybergraph policy --init-policy`, that the file (`cybergraph.policy.toml`) is committed, and that any agent can read it. State the Phase 1 contract sentence verbatim and say plainly which languages are verified today (Python produces verdicts; Go/JS/Java/C# are inventory-grade). The README must **not** say the MCP tool provides automatic verification (it is an interoperability surface an agent may decline to call), and must contain nothing matching `safe to ship`.

- [ ] **Step 5: Final verification**

```
python -m pytest -q
python -m ruff check src tests
python benchmark/run_precision.py
python benchmark/run_eval.py
python benchmark/mutation_harness.py
```
Expected: all green; precision ≥ 0.90, recall ≥ 0.95, safe-abstention ≤ 0.15; eval 1.0/1.0/1.0; harness all CAUGHT. Revert any `benchmark/results.json` churn.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ docs/ README.md tests/
git commit -m "docs+ci: run cybergraph check on PRs; keep inventory-only SARIF filter; record audit status"
```

---

## Notes for the executor

- Task 1 (MCP) then Task 2 (CI/docs). They are independent; keep them separate commits.
- This slice completes the 20-task verdict-core plan. Do not build anything from the parent plan's "Out of scope" table.
- The SARIF-filter ruling (Task 2 Step 1) reverses the parent plan's literal instruction on purpose — keeping the filter is correct because the four non-Python languages still emit substring inventory rules. If a reviewer flags the kept filter as contradicting the parent plan, that is the documented ruling, not a defect.
- No "safe to ship" phrasing; no claim that MCP is automatic verification; no `--fail-on-review` in CI.

# Verdict Surfaces — Design (Milestone 1B, slice 4 — final)

**Status:** approved for planning
**Slice:** Tasks 19, 20 of `docs/superpowers/plans/2026-08-08-verdict-core.md` (Task 20's SARIF step revised per the ruling below). Completing these finishes the entire 20-task verdict-core plan.
**Predecessors:** #38, #39 merged; #40 policy-graph in review; verdict-layer done (this branch stacks on it).

## What this slice does

Exposes the verdict through the second surface and closes out the plan's CI/audit/docs:

- **MCP `check_change_tool`** — a thin `@mcp.tool()` wrapper returning byte-identical output to `cybergraph check --json`, so an agent can call the same orchestrator the CLI does. It is *interoperability, not automatic verification* — an agent may never call it; reliable invocation is a client hook (Phase 2). The README must not claim otherwise. C6: the MCP surface must not import from the CLI; both call `check_change`.
- **CI wiring** — run `cybergraph check . --mode merge-base --base origin/<base>` on pull requests (with a full-depth fetch so a shallow checkout reports a failure, not an empty diff). No `--fail-on-review`: review stays a notification until a field false-positive rate is measured.
- **Audit + README** — record honest audit statuses and document `cybergraph check` / `cybergraph policy`, the Phase 1 contract, and which languages are verified.

## The one revised decision (ruled with the user)

Task 20 as written says *delete the CI SARIF filter — "the rule it filtered no longer exists."* That premise is **false**: the filter (`^CG-.*SINK-CALL$`) still matches four live rules — `CG-GO-SINK-CALL`, `CG-JAVA-SINK-CALL`, `CG-JS-SINK-CALL`, `CG-CSHARP-SINK-CALL` — the substring-based *inventory* findings from the four non-Python analyzers, which remain inventory-grade until Phase 2. Python no longer emits `CG-SINK-CALL`; its verdict rules (`CG-SQL-EXEC`, …) do not match the filter and already reach code scanning. So the audit's §4.1 "the tool deletes its own real findings" is **already resolved for Python** — deleting the filter now would instead upload the four non-Python substring-inventory rules as `medium` code-scanning results, reintroducing exactly the noise the project fought.

**Ruling: keep the filter, scoped to inventory-only; do NOT delete it.** The revised Task 2 asserts that no *verdict* rule id is matched by the filter (the real §4.1 fix — actionable findings reach code scanning) and that the filter still catches only `*-SINK-CALL` inventory rules, and documents in the audit that the four non-Python languages stay inventory-grade until their Phase-2 verdict upgrade.

## Architecture / boundaries

- `mcp_server.py` gains `check_change_tool` inside the `if FastMCP is not None:` block; imports `check_change` + `verdict_to_dict`; imports nothing from `cli.py` (C6). The parity test asserts the tool and `cybergraph check --json` produce the identical dict.
- `.github/workflows/cybergraph.yml` keeps the SARIF filter and adds the PR `check` step.
- `docs/CRITICAL_AUDIT.md` and `README.md` are updated for honesty and usage.

## Error handling

- The CI `check` step must not gate the build on a REVIEW (no `--fail-on-review`); a REVIEW is a notification. The build fails only on a real tool error.
- The full-depth fetch ensures merge-base mode has a common ancestor; a missing ancestor reports a failure (REVIEW), never a silent empty diff.

## Testing

- MCP: `tests/test_mcp_parity.py` — the tool is exposed, agrees byte-for-byte with `cybergraph check --json`, and the MCP module imports nothing from the CLI. Each test `pytest.importorskip("fastmcp")`.
- SARIF/CI: `tests/test_sarif.py` — assert the filter matches no *verdict* rule id (so real Python findings reach code scanning) and still targets only `*-SINK-CALL` inventory; assert the PR `check` step exists in the workflow.
- Full suite, precision gate, eval, and mutation harness stay green.

## Global constraints (inherited)

- Python 3.10–3.13; `from __future__ import annotations`; zero runtime dependencies; ruff line-length 100; no network/API keys on a default path.
- No "safe to ship" phrasing anywhere in `src/` or the README; the guard test (from the verdict-layer slice) stays green.
- Commits authored `Laraib <lxh417bham@gmail.com>` only; no AI attribution; multiple small commits; never squash.

## Roadmap alignment

Completes Tasks 19–20 and thus the whole verdict-core plan. Everything in the parent plan's "Out of scope" table (non-Python verdicts, client hooks, config posture, authorization ontology, BLOCK, ASVS/ISO evidence, …) remains deferred to its stated phase. The non-Python inventory-grade status and the receiver-variable guard follow-up (from #40) are documented, not resolved here.

## Success criteria

1. `check_change_tool` exists, returns the same dict as `cybergraph check --json`, and `mcp_server.py` imports nothing from `cli.py` (C6).
2. The CI SARIF filter is kept and scoped to inventory-only; a test asserts no verdict rule is filtered and the PR `check` step runs in merge-base mode.
3. `docs/CRITICAL_AUDIT.md` records honest statuses (§4.1 resolved for Python / non-Python inventory-grade; §4.2/4.4/4.5 open) with before/after numbers and commit shas.
4. README documents `cybergraph check` and `cybergraph policy`, the Phase 1 contract, and verified languages; contains no "safe to ship" and no claim that MCP is automatic verification.
5. Full suite, precision gate, eval, and mutation harness all green.

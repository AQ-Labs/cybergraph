# Verdict Layer — Design (Milestone 1B, slice 3)

**Status:** approved for planning
**Slice:** Tasks 15, 16, 17, 18 of `docs/superpowers/plans/2026-08-08-verdict-core.md`, plus a mutation-harness task
**Predecessors:** verdict-core (#38, merged), coverage-honesty (#39, merged), policy-graph (#40, CI-green, in review — this branch stacks on it).

## The sentence this slice is judged against

> Given a supported AI-generated change, CyberGraph returns a single verdict — ACCEPT or
> REVIEW — assembled from every capability it evaluated, with the specific reasons for a
> REVIEW and an explicit list of what it could not verify; and it never ACCEPTs by default,
> silence, or a failure to look.

This is the product's headline: the decision at the Accept button. It consumes everything
built so far — the per-sink detector (#38), coverage/capability honesty (#39), and the
policy graph (#40) — and turns it into one call. There is **no BLOCK state**: BLOCK requires
a measured field false-positive rate and is deferred (roadmap). ACCEPT and REVIEW only.

## Why now / dependencies

Every input this slice needs exists on the branch base (policy-graph tip): `capability.py`,
`coverage.py`, `policy.py` (`evaluate_policy`, `diff_policies`/`diff_configs`), `revisions.py`
(`resolve_revisions`), `attack_paths.py` (`find_attack_paths`), `review.py`
(`review_security_delta`), and the analyzers. The verdict layer is the first consumer that
ties them together.

## Architecture — evaluate → decide → orchestrate → surface

```
security/checks.py    (Task 1)  evaluate_capabilities(...) -> list[CheckResult]
security/verdict.py   (Task 2)  decide(checks, policy_changes, provenance) -> Verdict (ACCEPT/REVIEW)
security/check.py     (Task 3)  check_change(repo_root, base, mode) -> Verdict   (the one orchestrator)
cli.py (modify)       (Task 4)  cybergraph check [--base --mode --json --fail-on-review --init-policy]
benchmark/mutation_harness.py (Task 5)  seed verdict fail-open mutations
```

- **checks.py — capability evaluation (B2/B4).** Every capability either has an evaluator or
  is not in the list. `sql_construction` etc. from findings with the matching rule prefix,
  UNKNOWN when an `-UNVERIFIED` finding exists or a covering file failed to analyze;
  `declared_login_rules` from `protected_set.unprotected`, UNKNOWN when the policy has
  problems or routes exist with no policy; `reachable_data_paths` from `review_security_delta`
  risk deltas, UNKNOWN when the graph holds no entrypoints at all (the honest non-web answer);
  `source_analysis_support` NOT_SUPPORTED when a changed source file has no analyzer. A
  `revisions_failure` makes the whole evaluation UNKNOWN — a comparison that could not be
  established never reads as PASS.
- **verdict.py — assembly.** `decide` folds the checks and policy changes into ACCEPT or
  REVIEW: any check in a review state (FAIL / UNKNOWN / NOT_SUPPORTED) or any weakening policy
  change → REVIEW, otherwise ACCEPT. One reason per real issue (no duplicate finding+check
  lines). Carries a `not_evaluated` list (the honest "what I could not check") and a
  `Provenance` record (tool version, refs, mode, policy hash, capabilities). ACCEPT is only
  reachable when every relevant capability actually PASSed or was NOT_APPLICABLE.
- **check.py — the one orchestrator (C6).** `check_change` runs the whole pipeline:
  `resolve_revisions` → analyze the change (with a **cached base analysis** under
  `.cybergraph/base/<sha>/`, O(diff) not O(repo)) → coverage → `evaluate_policy` →
  `review_security_delta` → `evaluate_capabilities` → `decide`. Both the CLI and a future MCP
  tool call this; neither imports the other. A base-materialisation failure fails closed
  (a distinguishable failure, never an empty pass).
- **cli.py — `cybergraph check`.** The visible surface. Exit `0` for ACCEPT, `0` for REVIEW
  (unless `--fail-on-review`, then `1`), `2` for usage errors. `--json` for machine output,
  `--init-policy` to write a starter policy. **C5:** no "safe to ship" phrasing anywhere; the
  guard test is case-insensitive and scans all of `src/`.

## The governing invariant

Uncertainty never becomes safety, at the decision layer: ACCEPT is the *earned* state, never
the default. A missing evaluator, a parse failure, an unsupported language, an unestablished
comparison, or a policy problem each forces REVIEW — never a silent ACCEPT. This is B2 (the
"no evaluator → PASS" release blocker) closed at the point it matters most.

## Error handling

- `revisions_failure` → every capability UNKNOWN → REVIEW, with the failure as a reason.
- base analysis cannot be materialised → fail closed (REVIEW with a distinguishable reason),
  never an empty diff that reads as ACCEPT.
- no policy file → `declared_login_rules` is NOT_APPLICABLE if no routes exist, UNKNOWN if
  routes exist (a promise the app should probably make but hasn't) — never a silent PASS.
- no entrypoints → `reachable_data_paths` UNKNOWN (the honest CLI/library answer), not PASS.

## Testing

- Each task keeps its parent-plan unit tests (checks, verdict, orchestrator, CLI).
- End-to-end: a change that FAILs a sink check → REVIEW with the reason; a clean supported
  change → ACCEPT; a Go-only change → REVIEW (NOT_SUPPORTED); an unparseable file → REVIEW
  (UNKNOWN); a bad `--base` → REVIEW/failure, never ACCEPT; `--fail-on-review` exit code.
- The mutation harness gains verdict fail-open mutations — a review-state check that still
  ACCEPTs; a `revisions_failure` that reads as PASS; the "no evaluator → PASS" regression —
  each caught by its guard test, verified red-under-mutation.

## Global constraints (inherited, unchanged)

- Python 3.10–3.13; `from __future__ import annotations`; zero runtime dependencies; ruff
  line-length 100; no network / API keys on any default path.
- Commits authored `Laraib <lxh417bham@gmail.com>` only — never `azizur@sirio-strategies.com`,
  no AI attribution. Multiple small commits; never squash.
- The full suite, `run_precision.py`, `run_eval.py`, and the mutation harness stay green.

## Roadmap alignment — what this does NOT touch

Closes B2 and B5, C5 and C6. Deliberately excluded: the MCP `check_change` tool (Task 19)
and the CI/audit/docs task (Task 20) — a following slice; non-Python verdicts, config posture,
the typed authorization ontology, and BLOCK (all later phases). `require_authz` remains
rejected upstream; the receiver-variable guard false-positive noted in #40 remains a separate
follow-up.

## Success criteria

1. `evaluate_capabilities` gives every capability a real evaluator; a `revisions_failure` or a
   failed/unsupported covering file forces UNKNOWN/NOT_SUPPORTED, never PASS.
2. `decide` returns ACCEPT only when every relevant capability PASSed or was NOT_APPLICABLE;
   any review-state check or weakening policy change → REVIEW; reasons are de-duplicated; the
   `not_evaluated` list and provenance are populated.
3. `check_change` is the single orchestrator (CLI and future MCP both call it, neither imports
   the other), uses a cached base analysis, and fails closed on a base-materialisation error.
4. `cybergraph check` exits 0/0/2 (ACCEPT/REVIEW/usage), 1 on REVIEW with `--fail-on-review`;
   no "safe to ship" phrasing; the guard test is case-insensitive over all of `src/`.
5. Full suite, precision gate, eval, and mutation harness all green; the seeded verdict
   fail-open mutations are all caught.

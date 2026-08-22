# Accountable Suppressions — Design

**Status:** design of record. **Date:** 2026-08-19.

## Goal

A suppression may hide a finding, but never *silently* and never *forever*. Extend
CyberGraph's existing suppression model so a config suppression can carry a **reason**
(required), an **expiry** (optional), and an **approver** (optional, recorded). Consistent with
the product's cardinal rule — *uncertainty never becomes safety* — a suppression that is
**invalid or expired fails open**: it stops suppressing and the finding re-surfaces through the
existing machinery, rather than continuing to hide risk on a broken or stale entry.

## Current state (what exists on `main`)

- `src/cybergraph/config.py`: `CyberGraphConfig` (frozen dataclass) with flat
  `suppressed_rules: tuple[str,...]` and `suppressed_paths: tuple[str,...]`, parsed from
  `[suppressions] rules = [...]` / `paths = [...]` in `.cybergraph.toml`.
- `src/cybergraph/suppressions.py`: `is_config_suppressed`, `filter_suppressed_findings`,
  `config_conceals` (returns which config key concealed a finding — used by `history.py` and
  `security/review.py` to say *"hidden by config, not fixed"*), `is_inline_suppressed`
  (`# cybergraph: ignore RULE` on the finding line or up to two lines above). Inline reason text
  is *allowed* after the rule id but neither required nor recorded. Nothing expires.
- `security/policy.py::diff_configs` compares `suppressed_rules`/`suppressed_paths` across a diff
  to flag newly-added suppressions as a weakening.

## Design

### New accountable config form (array-of-tables), alongside the flat lists

```toml
[[suppressions.rule]]
id       = "CG-SQL-EXEC"
reason   = "test-only fixture query, not user-reachable"   # required
expires  = "2026-12-31"                                     # optional, ISO 8601 date
approver = "security-team"                                  # optional, recorded

[[suppressions.path]]
pattern  = "legacy/**"
reason   = "scheduled for deletion in Q4"
expires  = "2026-10-01"
```

### Semantics

1. **Reason required.** An accountable `rule`/`path` entry without a non-empty `reason` is
   *invalid*: it does **not** suppress, and is recorded as a `SuppressionProblem`.
2. **Expiry enforced, fail-open.** `expires` is compared against an injected "today"
   (`date.today()` by default). An entry whose `expires` is in the past does not suppress. A
   `expires` that is not a valid ISO date is *invalid* (fails open + recorded) — never silently
   honored. An entry with no `expires` never expires (but still needs a reason).
3. **Approver** is free-text metadata, recorded and surfaced; not enforced (no identity system).
4. **Backward compatible.** The flat `[suppressions] rules`/`paths` lists keep working exactly as
   today — grandfathered as *unaccountable, never-expiring* suppressions. No existing repo breaks.
   A future strict mode (require the accountable form) is out of scope here.
5. **Determinism.** Expiry is the one time-dependent input. Every suppression-checking function
   gains a `today: date | None = None` parameter (default `date.today()`), so tests are
   deterministic and the offline/deterministic property holds for a given day.
6. **Fail-open is the safe direction.** Invalid/expired/malformed → the finding re-appears and
   flows through the normal `check_change` path (driving REVIEW where it is in scope). This is the
   product's invariant: a broken suppression must never keep hiding a real finding.
7. **Surfaced, not silent.** Expired and invalid suppressions are reported by
   `cybergraph policy` and via the config-honesty path, so a human sees *"this suppression
   expired / lacks a reason"* rather than a finding merely reappearing without explanation.
8. **Inline symmetry.** Inline markers gain optional `expires=YYYY-MM-DD` and record their reason
   text; an expired inline marker stops suppressing. A bare `# cybergraph: ignore RULE` still
   works (grandfathered). Inline reason stays optional (backward compat) — the accountability
   bar (required reason) applies to the config form.
9. **No dependency on PR #58.** No new verdict `reason_class`; re-surfacing uses the existing
   finding flow. Lands cleanly off `main`.

### Components / files

- `config.py`: add `Suppression` and `SuppressionProblem` dataclasses; parse
  `[[suppressions.rule]]` / `[[suppressions.path]]` into `CyberGraphConfig.suppressions` and
  `.suppression_problems`; keep `suppressed_rules`/`suppressed_paths` unchanged (legacy). Handle
  both `tomllib` (nested array-of-tables) and the 3.10 `_load_simple_toml` fallback (which cannot
  represent array-of-tables — it will simply yield no accountable entries there, documented).
- `suppressions.py`: `active_suppressions(config, today)`; teach `_rule_suppresses` /
  `_path_suppresses` / `is_config_suppressed` / `config_conceals` / `filter_suppressed_findings`
  to (a) honor active accountable suppressions in addition to legacy lists, (b) skip
  invalid/expired ones, (c) accept `today`. Add `suppression_problems(config, today)` returning
  the invalid + expired entries for surfacing. Extend inline parsing for `expires=`.
- `security/policy_report.py` (or the `policy` CLI path): render expired/invalid suppressions.
- Callers of the suppression helpers (`triage.py`, `security/review.py`, `history.py`,
  `attack_paths.py`, …) keep working unchanged via the `today` default; only surfacing is wired.

### Testing

- Config parsing: valid accountable entry; missing reason → problem; malformed `expires` →
  problem; legacy flat lists still parse; array-of-tables under `tomllib`.
- Semantics (deterministic `today`): active entry suppresses; expired does not; missing-reason
  does not; malformed-expiry does not; legacy still suppresses. `config_conceals` returns `None`
  for an expired/invalid entry (so the finding is *not* labelled "hidden by config").
- Surfacing: expired/invalid entries appear in the policy report; an approver is shown.
- Inline: `expires=` in the past stops suppressing; bare marker still suppresses.
- Regression: full suite stays green; no behavior change for repos using only the legacy form.

### Out of scope (future)

Strict mode (require accountable form); per-suppression audit trail/history; approver identity
verification; inline `approver=`; migrating the flat lists automatically.

## Process constraints

Commits authored as `azizur100389` via the repo git config (GitHub noreply); no AI-attribution
trailer; never squash; push only to `AQ-Labs/cybergraph`. No work/session email in any file.

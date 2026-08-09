# Coverage Honesty — Design (Milestone 1B, slice 1)

**Status:** approved for planning
**Slice:** Tasks 8, 9, 14 of `docs/superpowers/plans/2026-08-08-verdict-core.md`, plus a thin read-only surface
**Predecessor:** Milestone 1A (the verdict-core detector), merged as AQ-Labs/cybergraph#38

## The sentence this slice is judged against

> When CyberGraph looks at an AI-generated change, it can state exactly which files it
> actually analyzed, which it could not, and which of its declared checks are therefore
> blind on this change — and it can never mistake "I could not look" for "nothing to see."

This is the second half of the Phase 1 contract ("…and explicitly admit what it could not
verify"). Milestone 1A made findings trustworthy. This slice makes *coverage* honest. It
does **not** make an ACCEPT / REVIEW / BLOCK decision — that is the verdict layer (Tasks
15–17) and is deliberately out of scope.

## Why this is the right next slice

The three release-blockers it removes all produce **false assurance** — a clean bill of
health over code that was never examined, which for a verification tool is worse than a
false positive:

- **B1** — an untracked new file is invisible to `git diff HEAD`, so a brand-new endpoint
  gets zero changed files and accepts. Creating files is what coding agents do most.
- **B3** — a change in a language with no analyzer (`main.go`) matches no capability, so
  nothing triggers a review.
- **B4** — a `.py` file that fails to parse produces zero findings, which reads as clean.
- **C7** — `--base origin/main` silently fell back to worktree mode, so the documented
  merge-base path was never exercised.

## Architecture — four units, strictly layered

```
revisions.py   (Task 14)   what changed, fail-closed         pure git subprocess, no deps
capability.py  (Task 8)    what we claim to check + scope    pure data, no deps
coverage.py    (Task 9)    which changed files we analyzed   reads the graph store
──────────────────────────────────────────────────────────────────────────────────────
coverage_report.py (new)   composes the three into a report  no decision logic
cli `cybergraph coverage`                                     renders the report only
```

Each unit has one responsibility and a well-defined interface:

- **`security/capability.py`** — the five-state model (`PASS` / `FAIL` / `NOT_APPLICABLE`
  / `UNKNOWN` / `NOT_SUPPORTED`), the declared `CAPABILITIES` and their file globs, and
  `relevance()` / `triggers_review()` / `label_for()`. Pure data and pure functions; no
  imports beyond the stdlib. Coverage is **declared, never inferred**: a capability states
  the globs it claims. `source_analysis_support` covers every executable-source extension
  so that general language blindness is represented directly rather than implied by
  whichever future capability happens to list an extension. `runtime_exploitability` is
  **not** in the list (it was previously listed and then special-cased to
  `NOT_APPLICABLE`, bending a state's meaning; it stays in the roadmap).

- **`security/revisions.py`** — resolves the changed-file set and the comparison mode
  (`worktree` / `merge-base` / `range`), unioning `git ls-files --others
  --exclude-standard` so untracked files are seen (B1), honouring an explicit `--mode`
  (C7), and returning a non-empty `failure` string rather than an empty diff when the
  comparison cannot be established. Pure git subprocess; no deps on the other units.

- **`security/coverage.py`** — for each changed *source* file, reports
  `analyzed` / `failed` / `unsupported` / `missing`. A file is `analyzed` only when the
  graph holds a `File` node for it **and** no `PY-SYNTAX` parse failure is recorded against
  it. Depends on `GraphStore.open_for_repo` and on `capability.SOURCE_GLOBS` /
  `VERIFIED_GLOBS`.

- **`security/coverage_report.py`** (new) — composes the three into a `CoverageReport`
  dataclass. Assembly is separated from rendering on purpose: the same object will later
  feed the verdict (Task 16) and the MCP surface (Task 19) without either importing CLI
  internals (the C6 defect the roadmap flags). Contains **no** accept/block logic.

- **CLI `cybergraph coverage`** — resolves, builds the graph for the current tree, assesses
  coverage, composes the report, renders it. No decision.

## Data flow

```
cybergraph coverage [--base REF] [--mode worktree|merge-base|range]
  → resolve_revisions(repo_root, base, mode)   → changed_files  OR  failure
  → build_graph(repo_root)                     → populate the store for the current tree
  → assess_coverage(repo_root, changed_files)  → per-file: analyzed|failed|unsupported|missing
  → relevance(changed_files)                   → which capabilities are in scope
  → compose CoverageReport                     → render
```

**Capability status at the coverage layer** is derived from coverage, *not* from running
predicates (that is the verdict's job). For each capability:

- not relevant (no covered file changed) → `NOT_APPLICABLE` (reported quietly or omitted)
- relevant and every covered file `analyzed` → reported as **checked** (the analyzer ran;
  the coverage surface makes no pass/fail claim)
- relevant and a covered file `failed` → `UNKNOWN`
- a changed source file is `unsupported` → `source_analysis_support: NOT_SUPPORTED`

## Error handling — fail-closed is the whole point

| Situation | Result | Must never be |
|---|---|---|
| bad ref / not a git repo / missing merge-base | print the failure, **exit non-zero** | empty diff → "all clear" |
| untracked new file | included in the change set (B1) | invisible → accept |
| changed `.py` fails to parse | `failed` → its capabilities `UNKNOWN` (B4) | zero findings → clean |
| changed `.go`/`.java`/`.cs` | `unsupported` → `source_analysis_support: NOT_SUPPORTED` (B3) | matches nothing → accept |
| README-only change | nothing relevant, **exit 0** | — |

**Exit codes.** `0` on a successful report — *even when files are unsupported*, because
this is a report, not a verdict. Non-zero **only** when the tool could not establish the
comparison (a `revisions.failure`). This keeps "I could not look" (non-zero) distinct from
"nothing to look at" (zero). A `--strict` mode that fails on any blind spot is a natural
later extension and is intentionally **not** built here (YAGNI until the verdict exists).

## Testing

- Each primitive keeps its plan unit tests: `capability` (12), `coverage` (5),
  `revisions` (11).
- The composition/CLI adds end-to-end tests for every row of the fail-closed table:
  untracked file appears; unparseable `.py` → `UNKNOWN`; `.go` → `NOT_SUPPORTED`; bad ref →
  failure + non-zero exit; README-only → nothing relevant + exit 0.
- Every new test must go **red** under the mutation it guards, verified not assumed.
- The slice extends `benchmark/mutation_harness.py` with the fail-open mutations that would
  resurrect these bugs — `revisions` returning `()` on failure, `coverage` mapping
  `failed → analyzed`, `relevance` dropping `source_analysis_support` — each seeded and
  confirmed caught.

## Global constraints (inherited, unchanged)

- Python 3.10–3.13; TOML via `tomllib` with the flat fallback.
- **Zero runtime dependencies** (`dependencies = []`). Stdlib only.
- Ruff line-length 100; `from __future__ import annotations` in every file.
- No network, no API keys on any default path.
- Commits authored `Laraib <lxh417bham@gmail.com>` only — never `azizur@sirio-strategies.com`,
  no `Co-Authored-By`, no AI attribution. Multiple small commits; never squash a PR.

## Roadmap alignment — what this does NOT touch

Builds precisely B1/B3/B4/C7 and introduces the capability model that Tasks 10–17 consume.
`VERIFIED_GLOBS = ("*.py",)` preserves the shipped honesty that Python produces verdicts
while the other four languages remain inventory-grade. Deliberately excluded and left to
their roadmap slices: the policy graph (Tasks 10–13), capability evaluation and verdict
assembly (15–16), the cached base analysis (17), the `cybergraph check` decision CLI (18),
the MCP `check_change` tool (19), non-Python verdicts (Phase 2), and client hooks for
reliable invocation (Phase 2). None of those is a dependency of this slice; this slice is a
dependency of several of them.

## Success criteria

1. `resolve_revisions` sees untracked files, honours `--mode`, and fails closed on a git
   error (all 11 unit tests).
2. `assess_coverage` distinguishes analyzed / failed / unsupported / missing (all 5).
3. `CAPABILITIES` is wildcard-free, `runtime_exploitability`-free, and
   `source_analysis_support` claims every source extension (all 12).
4. `cybergraph coverage` renders the honest report and its exit code separates "could not
   look" from "nothing to look at" (end-to-end tests).
5. Full suite green; ruff clean; the mutation harness catches every seeded fail-open
   mutation; `run_precision.py` and `run_eval.py` unchanged.

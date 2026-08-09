# Policy Graph — Design (Milestone 1B, slice 2)

**Status:** approved for planning
**Slice:** Tasks 10, 11, 12, 13 of `docs/superpowers/plans/2026-08-08-verdict-core.md`, plus a read-only `cybergraph policy` surface
**Predecessors:** verdict-core detector (#38), coverage-honesty (#39), both merged.

## The sentence this slice is judged against

> CyberGraph can read the security promises an application declares, check them against
> what the code actually does — keyed to the function, so a rename cannot smuggle a guard
> away — and report when a change weakens a promise, without ever silently dropping a
> promise the user wrote or faking one it cannot verify.

This is the "security policy graph" the product vision centres on — the legible "you dropped
the login check on `/admin/export`" story. It does **not** make an ACCEPT/REVIEW/BLOCK
decision; that is the verdict layer (Tasks 15–17). It is the hard prerequisite for it:
Task 15's `evaluate_capabilities` imports `Policy`, `PolicyProblem`, and `ProtectedSet` from
the module this slice builds.

## Why this is the right next slice

- The verdict layer (15–17) is blocked on it — `evaluate_capabilities` takes `policy` and
  `protected_set` as inputs and evaluates `declared_login_rules` from them.
- It removes two recorded release defects:
  - **C1** — identity keyed on the *route string*, so renaming `/admin/export` → `/export`
    while dropping the guard made the old route vanish (read as a deletion) and the new
    route fall outside `/admin/*` (never constrained): a silent pass on exactly the
    AI-generated regression the product exists to catch.
  - **C4** — policy *problems* were mis-reported as `rule_removed` (and validation-marker
    removal used the `auth_marker_removed` headline), so the delta lied about what changed.

## Architecture — one subsystem, four capabilities, one surface

```
src/cybergraph/security/policy.py           the whole policy subsystem
  ├─ model + strict loading      (Task 10)  Policy / PolicyRule / PolicyProblem, load_policy
  ├─ entity-keyed evaluation     (Task 11)  evaluate_policy → ProtectedSet (reads the graph)
  ├─ policy + config delta       (Task 12)  diff_policies / diff_configs → PolicyChange[]
  └─ baseline extraction         (Task 13)  extract_baseline → TOML text (never writes)
────────────────────────────────────────────────────────────────────────────────────────
src/cybergraph/cli.py (modify)   `cybergraph policy`  loads, renders rules/problems/
                                                       protected+unprotected; `--baseline`
                                                       prints proposed TOML. Read-only.
```

The parent plan and its tests import everything from `cybergraph.security.policy`, so that
remains the public surface. If the file grows unwieldy, graph-reading helpers may move to an
internal module while the public import path is preserved — not a public-API restructure.

Each unit has one responsibility:

- **model + strict loading (10)** — parse `cybergraph.policy.toml` (via `tomllib` with the
  `config.py` flat-parser fallback), producing `Policy(version, rules, problems, source_hash,
  exists)`. Only `kind = "require_auth"` is supported. An unknown kind, `require_authz`,
  `secret_server_only`, a missing `patterns`, or an unsupported `version` becomes a visible
  `PolicyProblem` — never a silently dropped rule. Records a 64-char `source_hash`.
- **entity-keyed evaluation (11)** — `evaluate_policy(repo_root, policy)` reads the graph
  (Function nodes carrying `route`/`entrypoint` props, `GUARDS` edges) and returns a
  `ProtectedSet` of `ProtectedEntity` keyed by **function key** (`rel::name`), with the
  `constrained` set and the `unprotected` `PolicyViolation`s. Function-key identity is the C1
  fix: it survives a route rename.
- **policy + config delta (12)** — `diff_policies` and `diff_configs` return `PolicyChange`
  tuples. Weakening is *semantic* — computed over the resolved constrained set, so a
  narrowed pattern reads as the protection loss it is. Deleted entities are excluded from
  weakening; a *renamed* entity whose function key survives but lost its guard or constraint
  is `protection_lost`. Policy problems get `policy_problem`, never `rule_removed` (C4).
- **baseline extraction (13)** — `extract_baseline(repo_root)` reads the graph and returns
  proposed TOML text; it never writes. The generated header asks the user to confirm each
  promise, because current behaviour can itself be accidental (it is baseline *extraction*,
  not policy inference).

## The visible surface — `cybergraph policy`

A read-only report, mirroring `cybergraph coverage` from the previous slice:

```
$ cybergraph policy
Policy: cybergraph.policy.toml (1 rule)
  admin-requires-login  require_auth  /admin/*, /internal/*

Protected entities: 2 guarded, 1 unprotected
  x app/admin.py::export  (/admin/export)  no login check; rule "admin-requires-login"

$ cybergraph policy --baseline    # prints proposed TOML to stdout; writes nothing
```

Exit `0` on a rendered report — **policy problems are reported, not a tool failure**. Exit
non-zero only when the command genuinely cannot run (e.g. the graph is not built). It makes
no ACCEPT/REVIEW/BLOCK call and prints no verdict vocabulary; the "declared promise weakened
→ review" behaviour belongs to Task 16, out of this slice.

## Data flow (the surface)

```
cybergraph policy [--baseline] [--repo R]
  → load_policy(repo)                     → Policy (rules + problems)
  → build_graph(repo)                     → populate the store (for evaluation)
  → evaluate_policy(repo, policy)         → ProtectedSet (guarded / unprotected)
  → render rules, problems, protected/unprotected
  --baseline:  extract_baseline(repo)     → print proposed TOML, write nothing
```

## Error handling

- `load_policy` on a missing file → an empty policy with `exists=False` and no problems (a
  repo without a policy is not an error).
- A malformed policy → rules that parse are kept where safe, but every rejected rule and
  every structural fault becomes a `PolicyProblem`. Parsing never raises to the caller.
- `evaluate_policy` with no graph / no entrypoints → an empty `ProtectedSet` (the honest
  "nothing to evaluate"), distinct from "evaluated and all guarded".
- The CLI surfaces a non-zero exit only when it cannot perform the read at all.

## Testing

- Each task keeps its parent-plan unit tests: policy load (10), entity evaluation including
  the rename-escape case (11), policy/config delta (12), baseline extraction (13).
- The `cybergraph policy` surface gets end-to-end tests: a guarded route, an unprotected
  route, a policy with a problem, and `--baseline` output.
- The slice extends `benchmark/mutation_harness.py` with policy fail-open mutations — an
  unknown kind silently dropped instead of raised as a `PolicyProblem`, and `protection_lost`
  not detected when a guarded function is renamed — each caught by its guard test, verified
  red-under-mutation.

## Global constraints (inherited, unchanged)

- Python 3.10–3.13; TOML via `tomllib` with the `config.py` flat fallback (they return
  different shapes for `[rule.x]` — normalise, never assume).
- Zero runtime dependencies (`dependencies = []`). Standard library only.
- Ruff line-length 100; `from __future__ import annotations` in every file.
- No network, no API keys on any default path.
- Commits authored `Laraib <lxh417bham@gmail.com>` only — never `azizur@sirio-strategies.com`,
  no `Co-Authored-By`, no AI attribution. Multiple small commits; never squash a PR.

## Roadmap alignment — what this does NOT touch

Builds C1/C4 and the `security/policy.py` module that Task 15 imports. Deliberately excluded:
capability evaluation and verdict assembly (15–16), the cached base analysis (17), the
`cybergraph check` decision CLI (18), the MCP surface (19), config posture and the typed
authorization ontology (Phase 3), and `secret_server_only` evaluation (Phase 3 — it loads as
an explicit problem here, never as a silently inert rule). `require_authz` is deliberately
absent from the supported kinds rather than faked.

## Success criteria

1. `load_policy` keeps supported rules, turns every unknown kind / authz / `secret_server_only`
   / missing-patterns / future-version into a visible `PolicyProblem`, and records a
   64-char `source_hash` (all Task 10 unit tests).
2. `evaluate_policy` keys entities on the function key so a route rename that drops a guard
   is caught, not read as a deletion (Task 11 tests, including the C1 rename-escape case).
3. `diff_policies`/`diff_configs` report semantic weakening and accurate change kinds; a
   policy problem is `policy_problem`, not `rule_removed` (Task 12 tests).
4. `extract_baseline` proposes TOML with a confirm-me header and never writes (Task 13 tests).
5. `cybergraph policy` renders the policy graph read-only and exits non-zero only on a real
   read failure (end-to-end tests).
6. Full suite green; ruff clean; the mutation harness catches every seeded policy fail-open
   mutation; `run_precision.py` and `run_eval.py` unchanged.

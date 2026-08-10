# Client Hooks for Reliable Invocation — Design (Phase 2, slice 1)

**Status:** approved for planning
**Slice:** the parent plan's out-of-scope row "Client hooks for reliable invocation" (Phase 2)
**Predecessors:** the entire 20-task verdict-core plan, merged to `main` — `cybergraph check`
(`check_change`), the worktree/merge-base/range revision modes, and the MCP `check_change_tool`
all exist and are green.

## The sentence this slice is judged against

> CyberGraph can install itself into the two places code is accepted — the Claude Code turn
> and the git commit — so `cybergraph check` runs on its own at that moment, surfaces a REVIEW
> loudly without blocking by default, and can never clobber a hook it did not write or verify
> code that is not actually being committed.

This is the step that makes "AI writes, we verify" *literally true* instead of aspirational.
Today verification is opt-in twice over: CI runs `cybergraph check` only after a PR is opened
(after the fact), and the MCP `check_change_tool` is *availability, not adoption* — an agent
may simply never call it. A client hook fires verification itself, at the latency-sensitive
accept-the-diff moment, with no one having to remember to ask.

## Why this is the right next slice

- It closes the roadmap's own "biggest adoption gap": the parent plan's Task 19 note says in
  as many words that the MCP tool is interoperability, not automatic verification, and that
  *reliable invocation needs a client hook, which is Phase 2*.
- It reuses what verdict-core already shipped — `check_change(repo, base, mode)` and the
  revision resolver — rather than building new analysis. The only analysis-layer change is one
  honest addition (`MODE_STAGED`), forced by correctness, not scope creep.
- It is editor-agnostic where it needs to be (git) and editor-native where it pays off most
  (Claude Code), so it lands adoption in the one client the team uses *and* every other one.

## Decisions already made (do not re-litigate in planning)

1. **Both targets, one installer.** A single `cybergraph hook` command group with pluggable
   targets — `claude-code` and `pre-commit` — not two ad-hoc commands.
2. **Advisory by default, `--strict` opts into blocking.** A REVIEW is surfaced loudly and
   returns success unless the hook was installed `--strict`. This mirrors the CI decision
   exactly (no `--fail-on-review` until a field false-positive rate is measured): uncertainty
   is made loud, but it does not halt real work on an unproven FP rate. ACCEPT is always silent.
3. **Nested command group, refuse-on-foreign.** `cybergraph hook install|uninstall|status`
   (the `gh auth login/logout/status` shape), and install *refuses* to overwrite a hook
   CyberGraph did not write (`--force` backs up first). The project is fail-closed by identity;
   it never silently destroys a hook it was trusted alongside.

## Architecture — one subsystem, two targets, one surface

```
src/cybergraph/hooks/                     the whole hook subsystem
  ├─ __init__.py       TARGETS registry: name -> Target; resolve_target(name)
  ├─ base.py           InstallResult, Target protocol, MARKER, invocation-resolver,
  │                    JSON-settings read/merge/write helpers (stdlib json)
  ├─ claude_code.py    Stop-hook entry in <repo>/.claude/settings.json
  └─ pre_commit.py     <repo>/.git/hooks/pre-commit script
src/cybergraph/__main__.py (create)       `from .cli import main; raise SystemExit(main())`
────────────────────────────────────────────────────────────────────────────────────────
src/cybergraph/cli.py (modify)              `cybergraph hook install|uninstall|status <target>`
src/cybergraph/security/revisions.py (mod)  add MODE_STAGED (git diff --cached vs HEAD)
src/cybergraph/cli.py `check` (modify)       add `staged` to `--mode` choices
```

`__main__.py` exists so the installed hooks can invoke `sys.executable -m cybergraph …`, which
resolves whenever the package is importable in that interpreter — no dependence on the
`cybergraph` console script being on the hook's `PATH` (git hooks and the Claude Code hook shell
often run with a bare environment). Today only the console script `cybergraph = cybergraph.cli:main`
exists; `python -m cybergraph` would fail without this file.

`cybergraph.hooks` is the public surface for the subsystem; the CLI is the human surface.
Each unit has one responsibility:

- **base.py** — the shared machinery every target needs and must share so the two targets
  cannot drift: the stable `MARKER` string that identifies a CyberGraph-written hook, the
  `resolve_invocation()` that emits `"<sys.executable>" -m cybergraph` (which resolves without
  the `cybergraph` console script being on the hook's PATH, given the new `__main__.py`), and
  `read_json`/`merge`/`write_json` for settings files. `InstallResult` carries a
  status enum (`installed` / `already_present` / `refused_foreign` / `not_a_repo` / `error`)
  and a human message — the CLI never invents its own wording.
- **claude_code.py** — install merges a **Stop** hook into `<repo>/.claude/settings.json`,
  preserving every sibling key and any pre-existing hooks; it is idempotent (re-install never
  duplicates our entry, keyed by `MARKER`). Uninstall removes only our entry. The hook command
  runs `cybergraph check . --mode worktree`; `--strict` is encoded in the installed command so
  the running hook needs no external state.
- **pre_commit.py** — install writes `<repo>/.git/hooks/pre-commit` (executable) running
  `cybergraph check . --mode staged`. If the file is absent, or present *and ours* (carries
  `MARKER`), install writes/refreshes it idempotently. If present and **foreign**, install
  returns `refused_foreign` and writes nothing — unless `--force`, which copies the existing
  file to `pre-commit.cybergraph.bak` first, then writes ours. Uninstall removes the file only
  if it is ours; a foreign hook is left untouched.

### Why a Stop hook, not PostToolUse

PostToolUse fires after every `Edit`/`Write`, so a single multi-file turn would rebuild the
security graph N times — O(repo) work per edit, at the worst possible moment for latency. The
Stop hook fires once when the agent finishes its turn: it batches the turn's edits into one
`check`, which is exactly the "diff was accepted" boundary. One check per turn, not per keystroke.

### Why MODE_STAGED is not optional

The existing worktree mode diffs `git diff --name-only HEAD` plus untracked files — i.e. staged
*and unstaged* changes. A pre-commit hook that used it would verify files the commit is not
taking, and could pass a change whose unsafe half is unstaged. `MODE_STAGED` diffs
`git diff --cached --name-only` against HEAD, so the hook verifies exactly the index that is
about to become a commit. It mirrors worktree structurally (base is HEAD in both); the only
difference is `--cached`.

## The visible surface — `cybergraph hook`

```
$ cybergraph hook install claude-code
Installed the CyberGraph Stop hook (advisory) in .claude/settings.json.
It runs `cybergraph check` when an agent turn ends; a REVIEW is surfaced, not blocked.

$ cybergraph hook install pre-commit --strict
Installed the CyberGraph pre-commit hook (strict) in .git/hooks/pre-commit.
A REVIEW will now block the commit; run with --no-verify to bypass once.

$ cybergraph hook install pre-commit
A pre-commit hook already exists and was not written by CyberGraph.
Refusing to overwrite it. Re-run with --force to back it up and replace it.

$ cybergraph hook status
claude-code   installed (advisory)   .claude/settings.json
pre-commit    not installed

$ cybergraph hook uninstall pre-commit
Removed the CyberGraph pre-commit hook. No other hook was present.
```

`hook status` exits 0 whatever it finds — reporting "not installed" is not a failure. `install`
and `uninstall` exit 0 on success and on the benign `already_present` / `not-ours-so-left-alone`
cases; they exit non-zero only on a real fault (not a git repo for `pre-commit`, an unwritable
settings file, a foreign hook without `--force`). No verdict vocabulary here — this command
wires the hook; the verdict is `check`'s job when the hook fires.

## What the installed hooks do when they fire (the verdict contract)

Both hooks call the same orchestrator the CLI and MCP already share, so behaviour cannot drift:

```
Claude Code Stop hook:  cybergraph check . --mode worktree   [encoded --strict?]
  ACCEPT  -> exit 0, silent
  REVIEW  -> advisory: findings to the user, success (agent continues)
             strict:   findings fed back so the agent must address them before finishing

git pre-commit hook:    cybergraph check . --mode staged      [encoded --strict?]
  ACCEPT  -> exit 0, commit proceeds
  REVIEW  -> advisory: findings printed, exit 0 (commit proceeds)
             strict:   findings printed, exit non-zero (commit blocked; --no-verify bypasses)
```

**Risk pinned for planning:** the exact Claude Code Stop-hook contract — the JSON/exit
convention for "surface context without blocking" versus "block and return a reason to the
agent" — must be verified against the *current* Claude Code hooks documentation before
`claude_code.py` is wired; this design's knowledge of it may be stale. The installer must be
**inert-safe**: if the contract differs from what is assumed, the worst case is a hook that
prints its findings and does not block, never one that blocks spuriously or corrupts settings.

## Error handling

- `pre-commit` outside a git repo → `not_a_repo`, clear message, non-zero, writes nothing.
- `claude-code` with no `.claude/` directory → create it; with an existing `settings.json`,
  merge; with a malformed `settings.json` → refuse with a message, never overwrite the user's
  file blind.
- A foreign `pre-commit` hook → `refused_foreign` (or backup+replace under `--force`).
- The installed hook itself, at fire time, treats a `check` failure as fail-closed for
  `--strict` (a check that cannot run is not an ACCEPT) and as a visible warning for advisory —
  it never swallows an error into a silent pass.
- Uninstall of an absent or foreign hook → success with an honest message; it removes only ours.

## Testing

- **Installer units** (per target): fresh install; idempotent re-install (no duplicate entry);
  `status` reflecting each state; uninstall removing only ours. For `pre-commit`: foreign-hook
  refusal writes nothing; `--force` creates the `.bak` then replaces; uninstall leaves a foreign
  hook byte-for-byte intact. For `claude-code`: a `settings.json` with unrelated keys and an
  unrelated hook keeps every sibling across install *and* uninstall (merge, not replace).
- **`MODE_STAGED` unit** (revisions): a repo with one staged and one unstaged change reports
  only the staged file; parity with worktree structure otherwise.
- **End-to-end**: install → introduce a guard-dropping change → the hook's `check` returns
  REVIEW; advisory exits 0, `--strict` blocks. A clean change → ACCEPT, silent.
- **Mutation harness** (`benchmark/mutation_harness.py`): seed two fail-opens — (a) the
  pre-commit installer overwrites a foreign hook without backing up (data loss), and (b)
  `MODE_STAGED` falls back to worktree semantics (verifies unstaged files) — each verified red
  under its guard test.

## Global constraints (inherited, unchanged)

- Python 3.10–3.13. **Zero runtime dependencies** (`dependencies = []`); standard library only —
  `json` for settings, `subprocess`/`pathlib` for git and files. No `pre-commit` framework or
  `husky`/`lefthook` dependency.
- Ruff line-length 100; `from __future__ import annotations` in every file.
- No network, no API keys on any default path.
- Cross-platform: the repo runs on Windows. The pre-commit script is a POSIX `sh` script (git
  runs it via its bundled shell on Windows too); paths are written forward-slash-safe and the
  file is marked executable via git's mode bits.
- Commits authored `Laraib <lxh417bham@gmail.com>` only — never `azizur@sirio-strategies.com`,
  no `Co-Authored-By`, no AI attribution. Multiple small commits; never squash a PR. Push only
  to `https://github.com/AQ-Labs/cybergraph`.

## Roadmap alignment — what this does NOT touch

Builds only the hook installer, its two targets, and the `MODE_STAGED` correctness fix.
Deliberately excluded: the non-Python verdict upgrade (still inventory-grade), config posture
(Supabase RLS / Firebase / CORS / buckets — Phase 3), the typed authorization ontology, the
`BLOCK` verdict state (awaits a measured field FP rate — `--strict` is a *user-chosen* gate on
the existing REVIEW, not a new verdict), and any editor other than Claude Code (Cursor and the
`pre-commit` *framework* config are future targets the registry is shaped to accept, not built
here).

## Success criteria

1. `cybergraph hook install claude-code` merges a Stop hook into `.claude/settings.json`,
   preserving all sibling keys and other hooks; re-install is idempotent; uninstall removes only
   our entry (installer units green).
2. `cybergraph hook install pre-commit` writes an executable `.git/hooks/pre-commit`; a foreign
   hook is refused without `--force` and backed up with it; uninstall never touches a foreign
   hook (installer units green).
3. `--strict` is encoded into the installed hook so a REVIEW blocks; without it a REVIEW is
   advisory and work proceeds — matching the CI posture.
4. `MODE_STAGED` verifies the index, not the working tree, so the pre-commit hook checks exactly
   what is being committed (revisions unit + end-to-end).
5. `cybergraph hook status` reports each target's state and exits 0 regardless.
6. Full suite green; ruff clean; the mutation harness catches both seeded hook fail-opens;
   `run_precision.py` and `run_eval.py` unchanged.

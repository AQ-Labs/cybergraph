# Design Spec — Temporal Analysis: persistence + delta (Theme D, Spec 3)

**Status:** approved design, pre-implementation
**Author:** Laraib
**Date:** 2026-07-19
**Depends on:** Spec 1 "Usability Core" (`analyze` command / `run_full_analysis`). Branches off
`feat/usability-core`.
**Scope:** first slice of Theme D — persist scan history and answer "what changed since last scan".
Trends/MTTR/aging charts and a bitemporal graph are explicit non-goals (later slices).

---

## Context

CyberGraph's SQLite store (`nodes`/`edges`/`findings`) has **zero timestamp columns**; every build
wipes and regenerates the graph (`clear_for_rebuild` keeps only externally-imported findings). The
only time-aware capability is `review.py`'s on-demand A-vs-B git diff (rebuilds both trees, persists
nothing). So today CyberGraph cannot answer "what's new / fixed / regressed since last week."

**Two enabling facts (confirmed in `graph/store.py`):** the schema is created with
`CREATE TABLE IF NOT EXISTS` (additive tables are idempotent, zero-migration), and
`clear_for_rebuild()` only deletes `nodes`/`edges`/`cybergraph`-findings — so **any new history
tables simply survive rebuilds untouched.**

**Outcome:** every `build`/`scan`/`analyze` records a lightweight, line-stable snapshot of findings;
a `history` command lists snapshots and reports **new / fixed / regressed / persisting** since the
previous scan; `analyze` gains a one-line delta.

## Decisions (from brainstorming + critical review)

- **Finding identity:** line-independent fingerprint `sha1("{rule_id}|{tool}|{file_path}|{message}")`
  (line kept as metadata, not identity). `tool` is included so distinct evidence sources don't merge.
- **Recording:** automatic, at the **CLI** `build`/`scan`/`analyze` handlers — never inside the
  internal `build_graph` function (so tests and internal rebuilds write no history).
- **Scope:** persistence + delta only. No trend charts, no MTTR view, no bitemporal graph.

## Principles / constraints

- Additive & non-breaking: new tables + a new command + a new module; existing tables, commands,
  and the 200+ tests untouched. Baseline suite must stay green.
- No new dependencies (stdlib `sqlite3`, `hashlib`, `datetime`, `subprocess`).
- History tables must survive `clear_for_rebuild` (they are simply not referenced by it).
- Deterministic/offline; `git` use is best-effort (non-git repo degrades, never crashes).
- Commits authored as the user only (no trailer), on `feat/temporal-analysis`.

## Architecture

### New tables (in the existing `graph.db`, via `CREATE TABLE IF NOT EXISTS` in `SCHEMA`)

```sql
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY, value TEXT
);  -- seed: ('schema_version', '2')  -- anchor for future migrations
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,                 -- ISO-8601 UTC
    git_sha TEXT DEFAULT '', git_branch TEXT DEFAULT '',
    node_count INTEGER DEFAULT 0, edge_count INTEGER DEFAULT 0, finding_count INTEGER DEFAULT 0,
    top_risk_score INTEGER DEFAULT 0, top_risk_label TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scan_findings (
    scan_id INTEGER NOT NULL, fingerprint TEXT NOT NULL,
    PRIMARY KEY (scan_id, fingerprint)
);  -- per-scan membership -> exact set-math deltas
CREATE TABLE IF NOT EXISTS finding_history (
    fingerprint TEXT PRIMARY KEY,
    rule_id TEXT, tool TEXT, file_path TEXT, severity TEXT, message TEXT, line_start INTEGER DEFAULT 0,
    first_seen_scan INTEGER, last_seen_scan INTEGER,
    first_seen_ts TEXT, last_seen_ts TEXT, fixed_ts TEXT DEFAULT '',
    status TEXT DEFAULT 'open',       -- open | fixed
    reopened_count INTEGER DEFAULT 0
);
```
(`meta`/`fixed_ts`/`reopened_count`/timestamps are written now so the deferred trends/MTTR slice is a
pure read with no re-migration.) These tables are **not** referenced by `clear_for_rebuild`.

### New module `src/cybergraph/history.py`

- `fingerprint(rule_id, tool, file_path, message) -> str` — `sha1` hex of the joined fields.
- `record_scan(repo_root) -> ScanResult` — reads the current `findings` rows, computes the current
  fingerprint set, and:
  1. If the set **and** git SHA equal the most recent scan's: do **not** insert a new `scans` row;
     just bump `last_seen_ts` on those `finding_history` rows (accurate "still open"), return a
     `no_change=True` result.
  2. Otherwise insert a `scans` row (with counts + top risk from `collect_top_risks`) and its
     `scan_findings`; then per current fingerprint update `finding_history`:
     - unseen → insert `open`, `first_seen_*` = this scan;
     - present & `open` → bump `last_seen_*`;
     - present & `fixed` → `open`, clear `fixed_ts`, `reopened_count++` (**regression**);
     - and every `open` fingerprint **absent** this scan → `fixed`, set `fixed_ts` = this scan ts.
  Returns `ScanResult(scan_id, no_change, new, fixed, regressed, persisting)` (each a fingerprint list).
- `scan_delta(repo_root) -> Delta` — the change between the two most recent scans, from `scan_findings`
  set math + `finding_history` (new vs regressed distinguished by prior existence). First-ever scan →
  everything `new`, empty `fixed`/`regressed`.
- `list_scans(repo_root, limit=20) -> list[ScanRow]`; `format_history(rows, delta)`; `format_delta(delta)`.
- `_git_head(repo_root) -> tuple[str, str]` — best-effort `git rev-parse HEAD` + branch; `("","")` if
  not a git repo (wrapped `subprocess`, never raises).

### `graph/store.py`

- Add the four tables to `SCHEMA`; seed `meta.schema_version` on open (idempotent `INSERT OR IGNORE`).
- Small helpers used by `history.py` (or history.py may use `store.conn` directly with parameterized
  SQL). `clear_for_rebuild` and `clear` are unchanged — they must never touch the history tables.

### `cli.py`

- After a successful `build` / `scan` / `analyze`, call `record_scan(repo)` (best-effort; a history
  failure prints a warning but never fails the command).
- `analyze` text output gains: `Δ since last scan: +{new} new, -{fixed} fixed, {regressed} regressed`
  (omitted on the first scan / when history is empty).
- New command `history [repo] [--limit N]` — prints the recent scans table and the delta-since-previous.

## Data flow

`build`/`scan`/`analyze` → findings persisted → `record_scan` fingerprints them → `scans` +
`scan_findings` + `finding_history` updated. `history` / `analyze` read `scan_delta` for the summary.

## Error handling

- `record_scan` is best-effort: any failure (locked DB, git error) logs a one-line warning and leaves
  the primary command's exit code unchanged.
- Non-git repo → empty SHA/branch, still records (fingerprint set captures uncommitted changes too).
- Imported findings (Semgrep/Strix) persist across rebuilds, so they stay `open` in history until
  re-imported or cleared — matching current `clear_for_rebuild` semantics (documented, expected).

## Testing (add ~14–18; keep the suite green)

- `fingerprint` is line-independent: same rule/tool/file/message on a different line → same hash;
  different `tool` → different hash.
- `record_scan`: first scan marks all `new`; a second scan with one finding removed → `fixed`
  (status flips, `fixed_ts` set); a `fixed` finding reappearing → `regressed` (`reopened_count`
  becomes 1, `fixed_ts` cleared); an unchanged rerun → `no_change` (no new `scans` row, `last_seen_ts`
  advanced).
- `scan_delta`: correct new/fixed/regressed/persisting between the last two scans; first-ever scan →
  all new.
- History tables **survive `clear_for_rebuild`** (record, rebuild the graph, history still present).
- Non-git `tmp_path` repo records with empty SHA and does not raise.
- CLI: `history` prints scans + delta; `analyze` prints the `Δ since last scan` line on the 2nd run
  and omits it on the 1st.
- Additive: an existing DB opened after the upgrade gains the tables (no error), and the existing
  `counts()`/queries are unaffected.

## Verification (end-to-end)

1. `analyze <repo>` twice with an edit between → 2nd run prints `Δ since last scan: …`.
2. `history <repo>` lists both scans with timestamps + the new/fixed/regressed summary.
3. Introduce, then remove, a vulnerable line across two scans → it shows as `new` then `fixed`;
   re-introduce → `regressed`.
4. Full `pytest` green.

## Out of scope / follow-ups (next Theme-D slices)

Trend charts + risk-over-time + MTTR + aging-findings view (reads the timestamps this slice already
records); a report "history" section; scan retention/prune; MCP recording of history; bitemporal
versioned graph with time-travel queries.

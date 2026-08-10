# Config Posture (Declarative Trio) — Design (Phase 2, slice 2)

**Status:** approved for planning
**Slice:** the parent plan's out-of-scope row "Config posture (Supabase RLS, Firebase rules,
Next.js boundary, CORS, buckets)" (Phase 3 there; pulled forward as Phase-2 slice 2) — the
*declarative-config* subset only.
**Predecessors:** the 20-task verdict-core plan and Phase-2 slice 1 (client hooks), both merged
to `main`. The capability model (`security/capability.py`), the coverage machinery
(`security/coverage.py`/`checks.py`), the analyzer registry (`analysis/registry.py`), the
Terraform analyzer (`analysis/terraform.py`), and `cybergraph check`/the hooks all exist.

## The sentence this slice is judged against

> CyberGraph can read the three declarative config surfaces where a single line silently
> exposes everything — a Firebase rule opened to the world, a table with row-level security
> switched off, a storage bucket made public — and turn a change that weakens one into an
> earned REVIEW at the accept-the-diff moment, never a silent ACCEPT, and never a false alarm
> on a config it could not actually parse.

## Why this is the right slice

- These are the roadmap's "most common real failure modes": an open Firestore rule or a table
  with RLS off exposes an entire database; a public bucket leaks whatever it holds. They cause
  real breaches far more often than the subtle code-level flaws the graph already models.
- It makes the client hooks shipped in slice 1 *pay off on config*: because a
  `secure_configuration` regression now reaches the verdict, `cybergraph check` — and therefore
  the Stop hook and the pre-commit hook — flag "you just disabled RLS" at the moment the change
  is accepted, not in a later audit.
- The capability already exists as a declared-but-absent placeholder: `cloud_configuration`
  (`capability.py:71`, `supported=False`). This slice largely *activates* scaffolding the
  design deliberately left in place, rather than inventing a new subsystem.

## Decisions already made (do not re-litigate in planning)

1. **Declarative trio only.** Firebase rules, Supabase RLS, and public storage buckets — the
   three that live in dedicated config/migration files. CORS and the Next.js client/server
   boundary (the `client_secret_boundary` capability) stay out; they live in code files and are
   a different analysis shape (slice 3).
2. **Detection + verdict, not detection alone.** The analyzers emit findings AND the
   `cloud_configuration` capability consumes them, so a posture regression on a changed config
   file returns REVIEW from `cybergraph check`. (A findings-only surface would leave the hooks
   silent on config — the opposite of the point.)
3. **Fold in Terraform.** The activated capability's rule-set includes the Terraform analyzer's
   existing `CG-IAC-*` findings as well as the new trio, so a Terraform change that opens a
   bucket / adds wildcard IAM / opens ingress *also* produces REVIEW. The label is "Cloud and
   database configuration"; it would be incoherent for a config-file bucket to review while an
   identical HCL bucket does not. This changes verdict behavior for Terraform-only changes and
   updates the tests that assert `cloud_configuration` is `NOT_SUPPORTED`.

## Architecture — three analyzers, one activated capability

```
src/cybergraph/analysis/firebase_rules.py  (create)  firestore.rules / storage.rules / firebase.json
src/cybergraph/analysis/supabase_rls.py    (create)  Supabase SQL migrations (RLS on/off)
src/cybergraph/analysis/bucket_policy.py   (create)  standalone S3/GCS bucket-policy / IAM JSON
src/cybergraph/analysis/registry.py        (modify)  dispatch the three by name/suffix/path
src/cybergraph/analysis/collector.py       (modify)  recognise the new config files (scoped)
src/cybergraph/security/capability.py      (modify)  cloud_configuration -> supported=True; covers globs
src/cybergraph/security/checks.py          (modify)  _FINDING_RULES value becomes a set; generic branch matches any
```

Each analyzer follows the `terraform.py` contract exactly: it returns
`(nodes, edges, findings)`; it is regex / brace / `json`-parse based with **no new
dependency**; it is conservative — an unrecognised or malformed file still yields a valid
`File` node so the build never crashes (an unreadable file is reported, never silently
skipped); and every finding carries a stable `rule_id`, a `severity`, a CWE, and a **verbatim
evidence line**, and honors `suppressions.is_inline_suppressed`.

### The three checks

- **Firebase rules — `CG-FIREBASE-RULES-OPEN` (CWE-732).** In `firestore.rules` /
  `storage.rules` (the Firebase security-rules DSL) and the `rules` references in
  `firebase.json`: a `match` block whose `allow read`, `allow write`, or `allow read, write`
  resolves to `if true` (or a condition that is unconditionally true). A rule guarded by
  `request.auth != null` or any real condition is secure and produces no finding.
- **Supabase RLS — `CG-SUPABASE-RLS-DISABLED` (CWE-1230).** In Supabase SQL migrations: an
  explicit `ALTER TABLE <t> DISABLE ROW LEVEL SECURITY`; a `CREATE TABLE` in the migration set
  with no corresponding `ENABLE ROW LEVEL SECURITY` anywhere in scope; or a `CREATE POLICY …
  USING (true)` that re-opens a table to everyone. RLS enabled with a real `USING`/`WITH CHECK`
  predicate is secure.
- **Public buckets — `CG-STORAGE-BUCKET-PUBLIC` (CWE-732).** In standalone bucket-policy / IAM
  config (NOT Terraform — `terraform.py` owns HCL): an S3 bucket-policy JSON `Statement` with
  `"Effect":"Allow"`, `"Principal":"*"` (or `{"AWS":"*"}`), and a public action
  (`s3:GetObject`/`s3:*`/…); or a GCS IAM binding granting a storage role to `allUsers` /
  `allAuthenticatedUsers`.

### File matching is scoped, never broad

`.sql` and `.json` appear all over a repo; parsing every one as a config surface would be both
slow and false-positive-prone. The collector recognises these files **only** by path/name
heuristics, handled in `registry._dispatch` and `collector.is_supported_source`:

- `firestore.rules`, `storage.rules`, any `*.rules` → firebase analyzer; `firebase.json` (by
  name) → firebase analyzer.
- `*.sql` **only** under a `supabase/` path component (Supabase's migration convention) →
  supabase analyzer. A stray application `*.sql` elsewhere is not treated as a migration.
- bucket-policy files by name convention (e.g. `*bucket-policy*.json`, `*.iam.json`, or a
  `gcs`/`s3` policy path) → bucket analyzer. When a JSON file's *shape* is ambiguous the
  analyzer inspects content (an S3 `Statement`/`Principal` shape, or a GCS `bindings`/`members`
  shape) and emits nothing — plus a plain `File` node — when it does not match, so a random
  JSON never yields a spurious finding.

The exact glob/name/path predicates are pinned in the plan; the principle is: **recognise
narrowly, fall back to a bare File node, and never let a broad extension pull unrelated files
into config analysis.**

## Verdict integration — activating `cloud_configuration`

- `capability.py`: `cloud_configuration` → `supported=True`. Its `covers` globs extend
  `INFRA_GLOBS` to include the trio's surfaces: add `*.rules`, `firebase.json` (already
  present), and the Supabase migration path. (`supabase/*` is present; confirm `fnmatch`
  matches nested migration paths and widen to `supabase/**` semantics via an explicit
  `supabase/` component test if needed — pinned in the plan.)
- `checks.py`: `_FINDING_RULES["cloud_configuration"]` becomes a **set** —
  `{CG-FIREBASE-RULES-OPEN, CG-SUPABASE-RLS-DISABLED, CG-STORAGE-BUCKET-PUBLIC,
  CG-IAC-PUBLIC-BUCKET, CG-IAC-WILDCARD-IAM, CG-IAC-OPEN-INGRESS, CG-IAC-HARDCODED-SECRET}`.
  The generic evaluator branch (`checks.py:194+`) currently does
  `rule = _FINDING_RULES.get(id)` then `confirmed = [f for f in findings if f.rule_id == rule]`;
  it changes to treat the value as a set of rule ids and match membership (`f.rule_id in rules`,
  with the `-UNVERIFIED` suffix handled the same way). Capabilities that map to a single rule
  keep working — a one-element set, or a small normalisation, whichever keeps the other
  capabilities' evaluation byte-identical.
- Five-state result (unchanged machinery, via `_coverage_summary`):
  - **FAIL** — a changed, in-scope config file carries a finding whose `rule_id` is in the set.
  - **UNKNOWN** — a changed in-scope config file has a failed/missing coverage record (we could
    not parse what changed; it is never assumed safe).
  - **NOT_APPLICABLE** — no config file in the capability's scope changed.
  - **PASS** — changed in-scope config files were analyzed and clean (positive evidence; an
    empty coverage set is not a PASS).

## Coverage honesty

The three analyzers must produce coverage records the same way the code analyzers do, so a
changed config file that could not be parsed becomes **UNKNOWN**, not a silent PASS. This is
the single most important correctness property of the slice and gets an explicit test and a
seeded mutation. If the coverage pipeline keys on analyzer participation, the new analyzers
inherit it by registering; the plan verifies the record actually appears for a `firestore.rules`
/ Supabase `.sql` / bucket-policy file.

## Surfaces

No new command. Findings flow through the existing pipelines automatically:
`cybergraph sarif` (new rule ids as first-class results — note the CyberGraph self-scan SARIF
filter only drops `*-SINK-CALL`, so these are unaffected), the HTML report, `cybergraph review`
(the security delta), and now `cybergraph check` / the client hooks (REVIEW on a posture
regression). `cybergraph coverage` and `cybergraph policy` are untouched.

## Error handling

- A malformed or unparseable config file → a `File` node and, where the file is clearly in
  scope but could not be read, the existing `CG-FILE-UNREADABLE` info finding; the capability
  reads it as UNKNOWN, never PASS. Parsing never raises to the caller (contained by
  `registry.analyze_source_file`).
- A JSON file whose shape does not match S3/GCS policy → no finding, bare `File` node (not a
  false positive, not an error).
- A `.rules` / Supabase `.sql` that parses but declares nothing insecure → no finding; if it is
  a changed in-scope file, it contributes positive PASS evidence.

## Testing

- **Per-analyzer units:** open rule → finding (correct rule id, CWE, evidence line); secure rule
  → no finding; unparseable/ambiguous file → `File` node only, no spurious finding; inline
  suppression respected. For Supabase: disable-RLS, create-without-enable, and `USING (true)`
  each caught; enable-with-real-predicate clean. For buckets: `Principal:"*"` and `allUsers`
  caught; a scoped principal clean; a non-policy JSON silent.
- **Capability five-state** (`test_checks.py` / `test_capability.py`): FAIL on a changed config
  file with a posture finding; UNKNOWN on a changed-but-unparsed config file; NOT_APPLICABLE on
  a README-only change; PASS on a changed-and-clean config file. Plus the Terraform fold-in:
  a changed `.tf` with `CG-IAC-PUBLIC-BUCKET` now yields FAIL for `cloud_configuration`.
- **Updated existing tests:** every test asserting `cloud_configuration` is `NOT_SUPPORTED`
  flips to its new supported behavior (this is expected, not a regression).
- **End-to-end:** `cybergraph check` on a diff that disables RLS (or opens a Firebase rule)
  returns REVIEW with the finding as the reason; a clean config change ACCEPTs.
- **Mutation harness** (`benchmark/mutation_harness.py`): two seeded fail-opens, each red under
  its guard test — (a) a posture finding that the capability reads as PASS (e.g. the rule-set
  membership test inverted), and (b) an unparsed/failed-coverage config file that reads PASS
  instead of UNKNOWN.
- Full suite green; ruff clean on touched files; `run_precision.py` and `run_eval.py` unchanged
  (they exercise the Python corpus, which this slice does not touch).

## Global constraints (inherited, unchanged)

- Python 3.10–3.13. **Zero runtime dependencies** (`dependencies = []`); standard library only
  (`re`, `json`, `pathlib`). No HCL/YAML/SQL parser dependency — regex/brace/`json` like the
  existing lightweight analyzers.
- Ruff line-length 100; `from __future__ import annotations` first line of every new file.
- No network; no API keys on any default path.
- Commits authored `Laraib <lxh417bham@gmail.com>` only — never `azizur@sirio-strategies.com`,
  no `Co-Authored-By`, no AI attribution. Many small commits; never squash a PR. Push only to
  `https://github.com/AQ-Labs/cybergraph`.

## Roadmap alignment — what this does NOT touch

Builds the declarative trio and activates `cloud_configuration`. Deliberately excluded: CORS
detection and the Next.js `client_secret_boundary` (slice 3 — code-file analysis); the
non-Python verdict upgrade; any new CLI command; the `secret_server_only` policy rule; the
`BLOCK` verdict state (`--strict` on the existing REVIEW remains the only gate). `require_authz`
and the typed authorization ontology remain future work.

## Success criteria

1. `firestore.rules` / `storage.rules` with `allow …: if true` → `CG-FIREBASE-RULES-OPEN`; a
   guarded rule is clean.
2. A Supabase migration that disables RLS, creates a table without enabling it, or opens it with
   `USING (true)` → `CG-SUPABASE-RLS-DISABLED`; RLS with a real predicate is clean.
3. A standalone S3/GCS policy granting public/`allUsers` access → `CG-STORAGE-BUCKET-PUBLIC`; a
   scoped policy and a non-policy JSON are clean.
4. Config files are recognised **narrowly** (no unrelated `.sql`/`.json` pulled in); an
   unparseable in-scope config reads UNKNOWN, never PASS.
5. `cloud_configuration` is `supported=True`, consumes the trio's + Terraform's `CG-IAC-*` rule
   ids, and returns FAIL→REVIEW on a changed config file that weakens posture, PASS on
   analyzed-clean, NOT_APPLICABLE off-scope, UNKNOWN on unparsed.
6. `cybergraph check` returns REVIEW on a diff that disables RLS / opens a rule / makes a bucket
   public (verified end-to-end, so the client hooks catch it).
7. Full suite green; ruff clean; the mutation harness catches both seeded config fail-opens;
   `run_precision.py` and `run_eval.py` unchanged.

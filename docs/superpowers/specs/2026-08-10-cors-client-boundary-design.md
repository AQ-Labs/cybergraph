# CORS + Next.js Client-Secret Boundary — Design (Phase 2, slice 3)

**Status:** approved for planning
**Slice:** the config-posture roadmap's two *in-code* targets — CORS and the Next.js client/server
boundary — deferred from slice 2 (declarative trio).
**Predecessors:** verdict-core (merged), client hooks (#43, merged), config-posture declarative
trio (#44, open). This branch is **stacked on `feat/config-posture`** because it edits
`capability.py`/`checks.py`, which #44 also changed; it rebases onto `main` once #44 merges.

## The sentence this slice is judged against

> CyberGraph can catch the two most common web exposures that live in code — a CORS policy that
> lets any origin call a credentialed API, and a secret marked to ship to the browser via
> `NEXT_PUBLIC_` — turning either regression into a REVIEW, precisely, without false alarms on a
> scoped CORS config or a public-by-design value.

## Why this is the right slice

- CORS misconfiguration and client-bundled secrets are among the most frequent real web
  vulnerabilities, and both are *code*, not declarative config — so they complete the
  config-posture theme where slice 2's file-parsers could not reach.
- The `client_secret_boundary` capability already exists as a declared-but-absent placeholder
  (`capability.py:80`, `supported=False`, label "Secrets reaching the browser", covers
  `WEB_GLOBS`) — precisely for the Next.js case. This slice activates it.
- Combined with the client hooks, a CORS or client-secret regression now surfaces as REVIEW at
  the accept-the-diff moment.

## Decisions already made (do not re-litigate in planning)

1. **Two targets, two capabilities.** CORS is a Python-*and*-JS access-control concern, distinct
   from "secrets reaching the browser" (JS/TS only). CORS gets a NEW `cross_origin_policy`
   capability; the Next.js boundary activates the existing `client_secret_boundary`. Folding
   both into one capability would be semantically wrong and would misattribute a Python CORS
   finding to a browser-secret capability.
2. **Precision over recall — the credentialed-wildcard combo only.** CORS flags only a wildcard
   (or reflect-all) origin *together with* credentials enabled — the combination that actually
   lets any site make authenticated cross-origin calls. A scoped origin list, or a wildcard
   *without* credentials, is clean. (Wildcard-without-credentials as a separate medium-severity
   finding is explicitly deferred.)
3. **Next.js: `NEXT_PUBLIC_<secret-name>` only.** A `NEXT_PUBLIC_`-prefixed identifier whose name
   also matches the secret heuristic is a definite client-bundle leak. The harder "server-only
   value imported into a `"use client"` component" needs import-graph analysis and is FP-prone —
   deferred to a follow-up.

## Architecture — extend two analyzers, wire two capabilities

```
src/cybergraph/analysis/python.py       (modify)  FastAPI CORSMiddleware credentialed-wildcard
src/cybergraph/analysis/javascript.py   (modify)  Express cors() credentialed-wildcard; NEXT_PUBLIC_ secret
src/cybergraph/security/capability.py   (modify)  activate client_secret_boundary; add cross_origin_policy
src/cybergraph/security/checks.py       (modify)  _FINDING_RULES: add both rule ids
```

New rule ids (findings carry a CWE + verbatim evidence line, honor inline suppressions, mirror
the existing analyzers' `Finding(...)` shape):

- **`CG-CORS-CREDENTIALED-WILDCARD`** (CWE-942) — emitted by both `python.py` and `javascript.py`.
- **`CG-CLIENT-SECRET-EXPOSED`** (CWE-200) — emitted by `javascript.py`.

### CORS detection (`CG-CORS-CREDENTIALED-WILDCARD`, CWE-942)

- **Python / FastAPI (`python.py`):** an `add_middleware(CORSMiddleware, …)` or
  `CORSMiddleware(…)` call where `allow_origins` contains `"*"` (or `allow_origin_regex` is an
  all-matching pattern such as `".*"`/`"*"`) **and** `allow_credentials=True`. Because
  `python.py` is AST-based, read the keyword arguments precisely: the finding requires BOTH the
  wildcard-origin keyword and the credentials-true keyword on the same call. Neither alone fires.
- **JavaScript / Express (`javascript.py`):** a `cors({ … })` call with `origin: "*"` or
  `origin: true` **and** `credentials: true`, or a bare `cors()` (no options → allows all
  origins) used as middleware. `javascript.py` is line/regex-based; match the `cors(` call and
  its option object conservatively, requiring both signals (or the bare-`cors()` all-origins
  case, which is credential-permissive by default in common setups — pinned in the plan).
- Evidence is the call's line; the CWE is 942 (permissive cross-domain policy).

### Next.js client-secret boundary (`CG-CLIENT-SECRET-EXPOSED`, CWE-200)

- In `javascript.py`: a `NEXT_PUBLIC_`-prefixed identifier (typically `process.env.NEXT_PUBLIC_…`,
  but any `NEXT_PUBLIC_<NAME>` token) whose `<NAME>` matches the secret heuristic
  (`SECRET`/`KEY`/`TOKEN`/`PASSWORD`/`PASSWD`/`APIKEY`, case-insensitive — reuse/extend the
  existing `SECRET_MARKERS` logic). `NEXT_PUBLIC_` inlines the value into the browser bundle, so
  a secret-named one is a definite leak. `NEXT_PUBLIC_API_URL`, `NEXT_PUBLIC_APP_NAME`, etc. are
  public by design → no finding. CWE-200 (exposure of sensitive information).

## Verdict integration — one activation, one new capability

- `capability.py`: `client_secret_boundary` → `supported=True` (covers `WEB_GLOBS`, unchanged).
  Add `Capability("cross_origin_policy", "Cross-origin resource sharing", CORS_GLOBS, True)`
  where `CORS_GLOBS = PYTHON_GLOBS + WEB_GLOBS` (CORS occurs in both).
- `checks.py`: `_FINDING_RULES["client_secret_boundary"] = "CG-CLIENT-SECRET-EXPOSED"` and
  `_FINDING_RULES["cross_origin_policy"] = "CG-CORS-CREDENTIALED-WILDCARD"` (single-rule strings;
  the slice-2 set-normalization in `_evaluate` handles both str and set values already).
- Five-state via the existing coverage machinery: **FAIL** when a changed in-scope file carries
  the finding; **UNKNOWN** when a changed in-scope file failed/has no analysis record;
  **NOT_APPLICABLE** when no in-scope file changed; **PASS** on analyzed-clean positive evidence.
- Coverage already tracks `*.py` (VERIFIED_GLOBS) and — since Python's analyzer finds these —
  the web globs must be covered too. Web files are in `SOURCE_GLOBS` but only `*.py` is in
  `VERIFIED_GLOBS`, so a changed `.ts`/`.js` currently reads `UNSUPPORTED` for source analysis.
  This slice must ensure the two web capabilities can reach PASS/FAIL on web files rather than
  perpetual UNKNOWN/NOT_SUPPORTED. **The plan pins how** (e.g. the JS analyzer already produces
  File nodes and findings, so treat web globs as verified for these capabilities' coverage
  lookup, mirroring how slice 2 added `CONFIG_GLOBS` to the coverage verified set) — without
  making the unrelated `source_analysis_support` capability claim JS is fully verified.

> This coverage subtlety is the load-bearing correctness point (as it was in slice 2): a web
> file that could not be analyzed must read UNKNOWN, and an analyzed-clean one must be able to
> PASS. The plan resolves it explicitly and tests it.

## Error handling

- A `.py`/`.js` that fails to parse → the analyzer's existing containment (`CG-FILE-UNREADABLE`
  / `PY-SYNTAX`) → coverage FAILED → UNKNOWN, never a silent PASS.
- A `cors(` call whose options CyberGraph cannot resolve (dynamic origin, a variable) → no
  finding (precision-first; an unresolved config is not asserted insecure). Documented recall gap.
- A `NEXT_PUBLIC_` name that is ambiguous (not clearly secret) → no finding.

## Testing

- **Python CORS units:** credentialed wildcard → finding; scoped origins → none; wildcard
  without credentials → none; `allow_origin_regex=".*"` + credentials → finding.
- **JS CORS units:** `cors({origin:"*", credentials:true})` → finding; `cors({origin:["https://x"]})`
  → none; bare `cors()` middleware → finding (pinned); scoped → none.
- **Next.js units:** `process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY` → finding; `NEXT_PUBLIC_API_URL`
  → none; a non-`NEXT_PUBLIC_` secret (server-side, `process.env.STRIPE_SECRET_KEY`) → none for
  this rule (it is not a client-boundary leak).
- **Capability five-state** for both `cross_origin_policy` and `client_secret_boundary`.
- **End-to-end:** `cybergraph check` returns REVIEW on a diff that opens credentialed-wildcard
  CORS, and on a diff that adds a `NEXT_PUBLIC_` secret; a scoped/clean change ACCEPTs.
- **Mutation harness:** two seeded fail-opens (a CORS/credentialed finding read as PASS; a web
  file that failed analysis read PASS instead of UNKNOWN), each red under its guard test.
- Full suite green; ruff clean; `run_precision.py`/`run_eval.py` unchanged (they exercise the
  Python security corpus, which this slice's new rules do not alter — confirm the CORS rule does
  not fire on any corpus fixture).

## Global constraints (inherited, unchanged)

- Python 3.10–3.13. **Zero runtime dependencies**; standard library only (`ast`, `re`).
- Ruff line-length 100; `from __future__ import annotations` in every file.
- No network; no API keys on any default path.
- **Precision over recall:** an ambiguous or unresolved config yields no finding; document the
  recall gap rather than risk a false alarm.
- Commits authored `Laraib <lxh417bham@gmail.com>` only; no `Co-Authored-By`, no AI attribution.
  Many small commits; never squash. Push only to `https://github.com/AQ-Labs/cybergraph`.

## Roadmap alignment — what this does NOT touch

Builds CORS + the `NEXT_PUBLIC_` secret boundary and activates the two capabilities. Deliberately
excluded: wildcard-CORS-without-credentials (deferred medium-severity), server-only-import-into-
client-component (needs import-graph analysis), the non-Python verdict upgrade, the declarative
trio (shipped in slice 2), and any new CLI command. `secret_server_only` policy and the typed
authorization ontology remain future work.

## Success criteria

1. FastAPI credentialed-wildcard CORS → `CG-CORS-CREDENTIALED-WILDCARD`; scoped or
   non-credentialed is clean.
2. Express `cors()` credentialed-wildcard (and the bare-`cors()` all-origins case) → the same
   rule; a scoped `cors({origin:[…]})` is clean.
3. `NEXT_PUBLIC_<secret-name>` → `CG-CLIENT-SECRET-EXPOSED`; a public-by-design `NEXT_PUBLIC_`
   name and a server-side secret are clean.
4. `client_secret_boundary` is `supported=True`; `cross_origin_policy` is added and supported;
   both return FAIL→REVIEW on a changed file that regresses, PASS on analyzed-clean,
   NOT_APPLICABLE off-scope, UNKNOWN on unparsed — and a changed web file can actually reach
   PASS/FAIL (not perpetual UNKNOWN).
5. `cybergraph check` returns REVIEW end-to-end on both regressions (so the hooks catch them).
6. Full suite green; ruff clean; the mutation harness catches both seeded fail-opens;
   `run_precision.py`/`run_eval.py` unchanged.

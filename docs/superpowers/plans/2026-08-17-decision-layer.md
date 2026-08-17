# CyberGraph Security Decision Layer — Implementation Plan (P0)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn CyberGraph's existing verdict into a **security decision layer** — one command, one canonical result object, honest collapsed projections, and an assurance program that lets claims strengthen by measurement — without ever letting simplification manufacture confidence.

**Architecture:** Extend the existing `Verdict` (already shared by CLI + MCP) into the canonical result object from the spec (separate `epistemics` / `impact` / `policy` / `gate`), add an `assurance` module that owns the vocabulary + claim-language + trust-composition rules, make `format_verdict` the collapsed default projection, add a policy layer that computes the CI `gate` (never the `decision`), add a `cybergraph .` entry, refactor `pr_comment` onto the canonical object, and scaffold the metric suite + adversarial harness.

**Spec:** `docs/superpowers/specs/2026-08-17-decision-layer-design.md` (the Seven Laws, the canonical object, §3 claim/collapse rules, §4 policy semantics, §5 staged program). This plan implements **P0** (P0A→P0E). P1/P2 are a roadmap section at the end and get their own plans.

**Tech Stack:** Python 3.10+, stdlib only, `from __future__ import annotations`, ruff-clean, pytest. Reuses `security/verdict.py`, `security/check.py`, `security/checks.py`, `security/capability.py`, `security/coverage.py`, `graph/models.py` (`Finding`, `UNVERIFIED_SUFFIX`), `cli.py`, `pr_comment.py`, `mcp_server.py`, `benchmark/run_precision.py`.

## Global Constraints (the Seven Laws — every task is bound by these)

1. **No epistemic upgrades.** No presentation string may strengthen status (`UNKNOWN→possible`, `possible→confirmed`, `reachable→exploitable`, `sink→vulnerability`, `finding→breach`). Enforced by `assurance.phrase_for` + a lint guard.
2. **Proposal ≠ verification.** No task adds AI that authors a fix CyberGraph then blesses.
3. **Assurance earned; trust composes to the weaker factor.** No invented numeric confidence; `effective_trust = min(evidence_strength, capability_assurance)`.
4. **UI cannot manufacture engine semantics.** Projections expose existing signals only.
5. **Evidence/uncertainty always inspectable.** Collapse detail, never limitation; drill-down is a strict superset.
6. **Assume the verifier is gamed.** Barrier/sanitizer by *name* is weak evidence, never SAFE; adversarial tests required.
7. **Epistemic state ≠ enforcement policy, and policy never launders uncertainty.** Policy sets `gate` only; it can never change `decision`, present review as accept, or drop it from the record.

Additional: stdlib only; `from __future__ import annotations`; ruff clean; **`test_mcp_parity.py` must stay green** (CLI and MCP JSON are byte-identical — both go through `verdict_to_dict`); commit as `Laraib <lxh417bham@gmail.com>` (plain `git commit`, no `-c user.email`, no AI attribution); never squash; don't push during task work.

## Naming hazard (call it out to every implementer)

Three unrelated "verdict/status" vocabularies already exist and must **not** be conflated: `verdict.py` change states (`accept`/`review`), `predicates.py` sink-safety (`VERDICT_SAFE/UNSAFE/UNKNOWN`), and `capability.py` five-state `CheckResult.status`. This plan adds a fourth axis set (`assurance` module). Keep them in separate modules with distinct names; never import one where another is meant.

## File structure

- Create: `src/cybergraph/security/assurance.py` (vocabulary + claim-language + trust composition + matrix). Test: `tests/test_assurance.py`.
- Modify: `src/cybergraph/security/verdict.py` (extend `Reason`/`Verdict`; `decide`; `verdict_to_dict` v2; `format_verdict` as collapsed projection). Tests: `tests/test_verdict.py`.
- Modify: `src/cybergraph/security/checks.py` (populate epistemic fields from existing signals). Tests: `tests/test_check.py`.
- Create: `src/cybergraph/security/policy_gate.py` (`gate_for`). Test: `tests/test_policy_gate.py`.
- Modify: `src/cybergraph/cli.py` (`cybergraph .` / `start`; wire gate to exit code). Tests: `tests/test_cli_start.py`, `tests/test_cli_check.py`.
- Modify: `src/cybergraph/pr_comment.py` (consume `Verdict`). Tests: `tests/test_pr_comment.py`.
- Modify: `benchmark/run_precision.py` + create `benchmark/change_assurance.py`, `benchmark/patch_to_pass.py`. Tests: `tests/test_assurance_metrics.py`.

---

### Task 1: The assurance vocabulary, trust composition & claim-language (P0A core)

Pure, dependency-free semantics module — the foundation Laws 1/3/6 are enforced from.

**Files:** Create `src/cybergraph/security/assurance.py`; Test `tests/test_assurance.py`.

**Interfaces — Produces (later tasks consume):**
- Enums (str constants): `EVIDENCE_STRONG/PARTIAL/WEAK/NONE`; `ASSURANCE_BENCHMARKED="benchmark_backed"`, `ASSURANCE_BETA="beta"`, `ASSURANCE_INVENTORY="inventory"`, `ASSURANCE_UNSUPPORTED="unsupported"`; `REASON_CONFIRMED_REGRESSION`, `REASON_UNRESOLVED`, `REASON_UNSUPPORTED`; status `STATUS_CONFIRMED/UNRESOLVED/UNSUPPORTED`.
- `effective_trust(evidence: str, assurance: str) -> str` — min on the ordered scale.
- `phrase_for(status: str, evidence: str, assurance: str) -> str` — returns one of `"confirmed"|"possible"|"could not verify"|"not evaluated"` per spec §3 table.
- `FORBIDDEN_ON_UNCONFIRMED: frozenset[str]` and `has_epistemic_upgrade(text: str, status: str) -> bool` (Law 1 lint).

- [ ] **Step 1: failing tests** — `tests/test_assurance.py`:

```python
from __future__ import annotations
from cybergraph.security import assurance as A


def test_trust_composes_to_the_weaker_factor():
    assert A.effective_trust(A.EVIDENCE_STRONG, A.ASSURANCE_BETA) == A.ASSURANCE_BETA
    assert A.effective_trust(A.EVIDENCE_WEAK, A.ASSURANCE_BENCHMARKED) == A.EVIDENCE_WEAK
    assert A.effective_trust(A.EVIDENCE_STRONG, A.ASSURANCE_BENCHMARKED) == A.EVIDENCE_STRONG


def test_confirmed_language_requires_strong_and_benchmarked():
    assert A.phrase_for(A.STATUS_CONFIRMED, A.EVIDENCE_STRONG, A.ASSURANCE_BENCHMARKED) == "confirmed"
    # strong evidence but beta capability -> NOT confirmed
    assert A.phrase_for(A.STATUS_CONFIRMED, A.EVIDENCE_STRONG, A.ASSURANCE_BETA) == "possible"
    assert A.phrase_for(A.STATUS_UNRESOLVED, A.EVIDENCE_PARTIAL, A.ASSURANCE_BENCHMARKED) == "could not verify"
    assert A.phrase_for(A.STATUS_UNSUPPORTED, A.EVIDENCE_NONE, A.ASSURANCE_UNSUPPORTED) == "not evaluated"


def test_law1_forbidden_upgrade_detected():
    assert A.has_epistemic_upgrade("this is confirmed SQL injection", A.STATUS_UNRESOLVED) is True
    assert A.has_epistemic_upgrade("input may reach a SQL sink", A.STATUS_UNRESOLVED) is False
```

- [ ] **Step 2: run → fail** (`python -m pytest tests/test_assurance.py -q`).
- [ ] **Step 3: implement** the constants, the ordered scale `[unsupported/none, inventory/weak, beta/partial, benchmark_backed/strong]`, `effective_trust` (index-min), the `phrase_for` table (only `strong+benchmark_backed+confirmed → "confirmed"`; else graded down), `FORBIDDEN_ON_UNCONFIRMED = {"confirmed","is vulnerable","will","can be exploited","exploitable","breach"}`, and `has_epistemic_upgrade` (substring scan, case-insensitive, skipped when `status==STATUS_CONFIRMED`).
- [ ] **Step 4: run → pass**; ruff clean.
- [ ] **Step 5: commit** — `feat(assurance): epistemic vocabulary, trust composition, claim-language rules`.

---

### Task 2: The assurance matrix (P0A)

Where the per-(language × framework × capability) maturity lives — today's honest map: Python injection classes `benchmark_backed`, the rest `beta`/`inventory`.

**Files:** Modify `src/cybergraph/security/assurance.py`; Test `tests/test_assurance.py`.

**Interfaces:** `assurance_for(capability_id: str, language: str | None, framework: str | None) -> str` returning an `ASSURANCE_*` tier; backed by a `_MATRIX` dict defaulting unknown cells to the conservative tier (`beta` for a verdict capability, `inventory`/`unsupported` otherwise). Consumes `capability.py` capability ids.

- [ ] **Step 1: failing tests**:

```python
def test_matrix_python_is_benchmarked_others_beta():
    assert A.assurance_for("sql_construction", "python", "fastapi") == A.ASSURANCE_BENCHMARKED
    assert A.assurance_for("sql_construction", "javascript", "express") == A.ASSURANCE_BETA
    assert A.assurance_for("command_execution", "csharp", None) == A.ASSURANCE_BETA
    # unknown capability/lang -> conservative, never benchmarked
    assert A.assurance_for("sql_construction", "rust", None) != A.ASSURANCE_BENCHMARKED
```

- [ ] **Step 2–4:** implement `_MATRIX` (Python×{fastapi,flask,django,None} × injection capabilities → benchmark_backed; JS/Go/Java/C# × injection → beta; everything else → inventory/unsupported), `assurance_for` with conservative default; run → pass; ruff.
- [ ] **Step 5: commit** — `feat(assurance): capability×language×framework maturity matrix`.

---

### Task 3: Extend the canonical result object (`Verdict`) — P0B

Add the spec's separated blocks to the already-shared object. **This is the load-bearing refactor; keep `test_mcp_parity.py` green.**

**Files:** Modify `src/cybergraph/security/verdict.py`; Tests `tests/test_verdict.py`.

**Interfaces — Consumes:** `assurance.*` (Tasks 1–2). **Produces:**
- Extend `Reason` (frozen) with: `status: str=""`, `evidence: str=""`, `assurance: str=""`, `impact: str=""`, `reason_class: str=""`.
- Extend `Verdict` (frozen) with: `gate: str=""` (set by the policy layer, Task 8; default empty), `primary_reason: str=""` (computed), and keep `reasons`, `checks`, `not_evaluated`, `provenance`.
- `verdict_to_dict` becomes **v2** with a `"schema_version": 2` key and nested blocks per spec §2: each reason serializes `{headline, file, line, rule, kind, status, evidence, assurance, impact, reason_class}`; top-level adds `decision` (alias of `state`, kept for back-compat), `gate`, `reasons[]`, `primary_reason`. Keep the existing keys (`state`, `checks`, `not_evaluated`, `provenance`) so old consumers don't break within a compatibility window (spec open-Q4).

- [ ] **Step 1: failing tests** in `tests/test_verdict.py`:

```python
def test_verdict_to_dict_is_schema_v2_with_epistemic_blocks():
    v = _sample_review_verdict()  # helper builds a Verdict with one confirmed_regression reason
    d = verdict_to_dict(v)
    assert d["schema_version"] == 2
    assert d["decision"] == d["state"] == "review"
    r = d["reasons"][0]
    for k in ("headline", "status", "evidence", "assurance", "impact", "reason_class"):
        assert k in r
    assert d["primary_reason"] in {rr["reason_class"] for rr in d["reasons"]}


def test_gate_defaults_empty_until_policy_sets_it():
    assert verdict_to_dict(_sample_review_verdict())["gate"] in ("", None)
```

- [ ] **Step 2: run → fail.**
- [ ] **Step 3: implement** the dataclass field additions (defaults keep existing constructors valid), `primary_reason` computed in `decide` (Task 4 fills the inputs; here just carry the field), and the v2 `verdict_to_dict`. Do **not** change `format_verdict` yet (Task 5).
- [ ] **Step 4: run → pass**; run `tests/test_mcp_parity.py` and `tests/test_cli_check.py` → **must stay green** (MCP uses `verdict_to_dict`, so parity holds automatically; if a test pins the exact old dict, update it to assert the v2 superset, never to weaken it).
- [ ] **Step 5: commit** — `feat(verdict): canonical result object v2 (epistemics/gate/primary_reason)`.

---

### Task 4: Populate epistemics from existing signals — P0B

Map what the engine already knows onto the new fields — no new analysis.

**Files:** Modify `src/cybergraph/security/checks.py` (`evaluate_capabilities` / `_evaluate`) and `src/cybergraph/security/verdict.py` (`decide`, `load_changed_findings`). Tests `tests/test_check.py`.

**Mapping (exact):**
- `status`: `CheckResult.status` `FAIL→STATUS_CONFIRMED`, `UNKNOWN→STATUS_UNRESOLVED`, `NOT_SUPPORTED→STATUS_UNSUPPORTED`.
- `evidence`: a finding whose `rule_id` ends with `UNVERIFIED_SUFFIX` → `EVIDENCE_PARTIAL`; a confirmed finding with resolved path (evidence non-empty) → `EVIDENCE_STRONG`; else `EVIDENCE_WEAK`; no finding → `EVIDENCE_NONE`.
- `assurance`: `assurance_for(capability_id, language, framework)` — derive language from the changed file's extension, framework from the graph if available else `None`.
- `impact`: from the finding `severity` (map `critical/high/medium/low`); auth/secret/reachability reasons keep their existing severities.
- `reason_class`: `STATUS_CONFIRMED→REASON_CONFIRMED_REGRESSION`, `STATUS_UNRESOLVED→REASON_UNRESOLVED`, `STATUS_UNSUPPORTED→REASON_UNSUPPORTED`.
- `primary_reason` (in `decide`): the reason maximizing `(impact_rank, protected_boundary, reason_severity)` — **not** a fixed enum order (spec §4). Protected-boundary flag comes from whether the reason's route/entity is in the policy's `ProtectedSet`.

- [ ] **Step 1: failing tests** — assert a Python confirmed SQL regression carries `status=confirmed, evidence=strong, assurance=benchmark_backed`; a JS one carries `assurance=beta`; a `-UNVERIFIED` finding carries `evidence=partial` and `status=unresolved`; a NOT_SUPPORTED change carries `reason_class=unsupported_change`; and `primary_reason` picks a protected-boundary unsupported over a low-impact confirmed regression.
- [ ] **Step 2–4:** implement mapping + `primary_reason` computation; run full `tests/test_check.py` + `tests/test_verdict.py` green; ruff.
- [ ] **Step 5: commit** — `feat(verdict): derive epistemics/impact/reason-class from existing signals`.

---

### Task 5: Collapsed default projection + claim-language enforcement — P0B/§3

`format_verdict` becomes the spec's collapsed default (one line + reason + top gap + drill-down), with language bounded by `effective_trust` and Law 1 enforced.

**Files:** Modify `src/cybergraph/security/verdict.py` (`format_verdict`). Tests `tests/test_verdict.py`.

- [ ] **Step 1: failing tests:**

```python
def test_default_projection_is_collapsed_and_language_bounded():
    out = format_verdict(_sample_beta_sql_review())      # beta capability
    assert "possible" in out.lower() and "confirmed" not in out.lower()  # Law 1 + Law 3
    assert out.count("\n") <= 8                          # collapsed: headline + reason + top gap + [Why?]
    assert "Why?" in out or "why" in out.lower()

def test_thin_result_names_the_gaps_not_bare_unknown():
    out = format_verdict(_sample_all_unresolved_review())
    assert "could not" in out.lower()
    assert "UNKNOWN" not in out            # never a bare UNKNOWN in the default view

def test_no_forbidden_upgrade_in_any_rendered_reason():
    for v in (_sample_beta_sql_review(), _sample_all_unresolved_review()):
        out = format_verdict(v)
        for r in v.reasons:
            assert not has_epistemic_upgrade(_line_for(out, r), r.status)
```

- [ ] **Step 2–4:** implement the collapsed layout using `assurance.phrase_for` for every headline verb, a "confirmed / not established" evidence split behind a `[Why?]` section, and thin-result guidance that lists each `unresolved`/`unsupported` with its *reason string* (from `CheckResult.detail`). Add an internal assertion (or a test-only hook) that every rendered reason passes `has_epistemic_upgrade`. Keep a `--verbose`/drill-down flag that prints the full epistemic block. Run → pass; ruff.
- [ ] **Step 5: commit** — `feat(verdict): collapsed default projection with claim-language bounded by trust`.

---

### Task 6: `cybergraph .` one-command entry — P0C

Remove the "must know a subcommand" barrier; add the golden-path start flow.

**Files:** Modify `src/cybergraph/cli.py` (`build_parser`, `main`); add `_run_start`. Tests `tests/test_cli_start.py`.

**Interfaces — Consumes:** `quickstart.run_quickstart`, `check.check_change`, `verdict.format_verdict`.

- [ ] **Step 1: failing test** — `cybergraph .` (argv `["."]`) exits 0/1 (not argparse error 2) and prints the collapsed verdict + a "Framework/routes/sinks" one-liner + a suggested next command (`explain` / `visualize`).

```python
def test_bare_path_runs_start(tmp_path, capsys):
    _write_fastapi_app(tmp_path)
    rc = cli.main([str(tmp_path)])
    out = capsys.readouterr().out
    assert rc in (0, 1)
    assert "REVIEW" in out or "ACCEPT" in out
    assert "cybergraph" in out.lower()  # suggests a next command
```

- [ ] **Step 2–4:** set `subparsers(dest="command", required=False)`; in `main`, if `command is None` and a bare path (or no arg) is given, dispatch `_run_start(repo)`. `_run_start` = detect (existing framework detection) → build (if no graph) → `check_change` → `format_verdict` → framework summary → suggested next step. Keep every existing subcommand working (regression-run `tests/test_cli_check.py`). Ruff.
- [ ] **Step 5: commit** — `feat(cli): 'cybergraph .' one-command start (detect → check → collapsed verdict)`.

---

### Task 7: Policy layer & CI gate — §4

The `gate` is computed from the verdict + config and never mutates the decision (Law 7).

**Files:** Create `src/cybergraph/security/policy_gate.py`; modify `cli.py` (`_run_check`, `_run_start` exit codes) and the `[verification]` config load. Tests `tests/test_policy_gate.py`.

**Interfaces — Produces:** `GATE_BLOCK/WARN/INFO`; `gate_for(verdict: Verdict, config: VerificationConfig) -> str`. `VerificationConfig` fields: `block_confirmed_regressions: bool=True`, `block_unknown_on_protected_routes: bool=True`, `block_general_unknown: bool=False` (parsed from `cybergraph.policy.toml [verification]`).

- [ ] **Step 1: failing tests (Law-7 invariants are the point):**

```python
def test_policy_sets_gate_never_decision():
    v = _sample_review_verdict()
    g = gate_for(v, VerificationConfig(block_confirmed_regressions=True))
    assert g == GATE_BLOCK
    assert v.state == "review"            # decision unchanged by policy
    # no config can turn review into accept:
    g2 = gate_for(v, VerificationConfig(block_confirmed_regressions=False,
                                        block_general_unknown=False))
    assert g2 in (GATE_WARN, GATE_INFO)   # advisory, but still review
    assert v.state == "review"

def test_unsupported_on_protected_boundary_blocks_when_configured():
    v = _sample_unsupported_on_protected_route()
    assert gate_for(v, VerificationConfig(block_unknown_on_protected_routes=True)) == GATE_BLOCK

def test_general_unknown_is_advisory_by_default():
    v = _sample_unresolved_non_protected()
    assert gate_for(v, VerificationConfig()) in (GATE_WARN, GATE_INFO)
```

- [ ] **Step 2–4:** implement `gate_for` (block if a confirmed_regression and `block_confirmed_regressions`; block if unresolved/unsupported on a protected boundary and `block_unknown_on_protected_routes`; else warn/info). Wire `--strict`/`--fail-on-review` to exit non-zero only when `gate==GATE_BLOCK`. **Ensure `verdict_to_dict` records `policy.action`/`gate` but the default projection, when `gate!=block` over a `review`, still prints the review (e.g. "2 items surfaced — not blocking per policy"), never "ACCEPT."** Add a test asserting that string. Ruff.
- [ ] **Step 5: commit** — `feat(policy): CI gate layer (block/warn/info) that never launders the decision`.

---

### Task 8: Security-diff PR view on the canonical object — P0D

Refactor `pr_comment` to consume `Verdict` (not re-derive), rendering reason-classed, gate-aware "what changed / proven / not proven / to review."

**Files:** Modify `src/cybergraph/pr_comment.py` (`generate_pr_comment`, `write_pr_comment`). Tests `tests/test_pr_comment.py`.

- [ ] **Step 1: failing tests** — `generate_pr_comment` on a change that drops an auth guard emits a concise comment containing the decision, `primary_reason` in bounded language, a before/after boundary line, the evidence citation, and the gate line; and it must contain **no** forbidden-upgrade string for a beta-stack finding. Assert the comment is derived from `check_change`'s `Verdict` (mock `check_change`, assert `generate_pr_comment` renders its reasons).
- [ ] **Step 2–4:** rewrite `generate_pr_comment(repo_root, base)` to call `check_change(repo_root, base)` and render its `Verdict` via a PR projection (reuse `assurance.phrase_for`); keep the "what changed" delta by pairing with `history`/`_risk_deltas` but drive the headline from `Verdict`. Run `tests/test_pr_comment.py` green; ruff.
- [ ] **Step 5: commit** — `feat(pr): security-diff PR comment projected from the canonical verdict`.

---

### Task 9: Assurance metric suite + Change Assurance Benchmark skeleton — P0A

Report the metric suite explicitly (no blended score) and stand up the patch-pair harness on a seed corpus (the `demos/` reproduce a real change each).

**Files:** Modify `benchmark/run_precision.py`; create `benchmark/change_assurance.py`. Tests `tests/test_assurance_metrics.py`.

- [ ] **Step 1: failing tests** — `change_assurance.evaluate(cases) -> Metrics` returns a dataclass with `false_accept_rate`, `review_precision`, `abstention_rate`, `unsupported_rate`, `recall` (no single blended number), and correctly classifies a seeded patch-pair where the head introduces a tainted SQL sink as `should_review` and a policy-preserving refactor as `should_accept`.
- [ ] **Step 2–4:** implement a patch-pair case format `{repo_state_a, patch, expected ∈ {regression,no_regression,ambiguous}, class, language, framework}`; the runner applies the patch in a temp git repo, runs `check_change`, and tallies the confusion matrix with **false-ACCEPT as the primary reported metric**. Seed 3 cases from the existing demo scenarios (auth regression, injection). Extend `run_precision.py` to print the metric suite. Ruff.
- [ ] **Step 5: commit** — `test(assurance): change-verdict metric suite (false-ACCEPT primary) + patch-pair harness`.

---

### Task 10: Adversarial Patch-to-Pass harness — P0A/Law 6

Prove the verifier resists gaming on the vectors where gaming ≠ fixing.

**Files:** Create `benchmark/patch_to_pass.py`. Tests `tests/test_patch_to_pass.py`.

- [ ] **Step 1: failing tests:**

```python
def test_detector_evasion_does_not_flip_review_to_accept(tmp_path):
    # same tainted SQL, alternate construction ("".join / % / .format) must still REVIEW
    for construction in EVASIONS:
        assert not _flips_to_accept(tmp_path, construction)

def test_name_only_sanitizer_does_not_manufacture_safe(tmp_path):
    # def sanitize(x): return x  ;  execute(sanitize(user_input)) -> not ACCEPT
    assert not _flips_to_accept(tmp_path, IDENTITY_SANITIZER_CASE)
```

- [ ] **Step 2–4:** implement `_flips_to_accept` (build → check_change baseline REVIEW → apply the "fix" → re-check → assert it did **not** become ACCEPT unless the vuln is genuinely gone). Include the `EVASIONS` set (`"".join([...])`, `%`-format, `.format`) and the identity-`sanitize` case. Where a real gap is found (e.g. `.join` slips past), record it as a **known finding** for the classifier backlog rather than forcing a fix in this task. Ruff.
- [ ] **Step 5: commit** — `test(adversarial): Patch-to-Pass — evasion & name-only sanitizer must not flip to ACCEPT`.

---

### Task 11 (P0E): UX comprehension check — process, not code

Not a code task; a gate before the simplified copy is called done.

- [ ] **Step 1:** capture the exact P0C/P0D default-projection output for three fixtures (Python confirmed regression; JS beta possible; unsupported change).
- [ ] **Step 2:** put each in front of ~5 target users (mix of vibe coder → senior dev); ask only: *"Did security get better or worse, and what should you do?"*
- [ ] **Step 3:** record pass/fail per user; a projection passes if ≥4/5 answer correctly **and** nobody reads a `review`/`unresolved` as "safe."
- [ ] **Step 4:** file wording fixes as follow-ups; **do not** relax Laws 1/3/5 to improve comprehension — reword within them.
- [ ] **Step 5:** record the result in the plan's ledger; this gates shipping the simplified copy, not the engine work.

---

## Self-review notes (against the spec)

- Spec §1 Seven Laws → Global Constraints + enforced concretely (Law 1: Task 1 `has_epistemic_upgrade` + Task 5 assertion; Law 3: Task 1 `effective_trust` + Task 2 matrix; Law 7: Task 7 invariants).
- Spec §2 canonical object → Tasks 3–4. Spec §3 claim/collapse → Task 5. Spec §4 policy/gate → Task 7. Spec §5 program → Tasks 9–10 (+ graduation matrix Task 2), P0E → Task 11.
- P0 ordering honored: semantics (T1–2) → canonical object (T3–4) → projection (T5) → surfaces (T6, T8) → policy (T7) → assurance program (T9–10) → comprehension gate (T11).
- `test_mcp_parity.py` protected in Task 3. No task reintroduces mandatory LLM/tokens (Law 2). No task claims to graduate a language (only Task 2 records today's honest tiers).

---

## Roadmap beyond P0 (own specs/plans later — not decomposed here)

- **P1:** framework-native summaries; accountable suppressions (reason+expiry+approver) extending today's suppression model; automatic baseline/policy generation; "send remediation to an agent" handoff (Law 2 naming); grounded attack **stories** with per-segment epistemic labels (headline = weakest load-bearing segment); NL investigation surfaced; **graph-delta** architecture-change (cheap: new entrypoint/removed guard/new sink/new path over existing `history` + `_risk_deltas`). Progressive disclosure over explicit Beginner/Dev/Security modes.
- **P2 (real engine work):** security **invariants** (`requires_role`, `secret may_flow_to <domain>`, `db public_access=false`); `cybergraph test` (invariants as a friendlier interface); **semantic** architecture-change detection. Each needs its own labelled benchmark cell before its claims strengthen.
- **Ongoing:** grow the Change Assurance Benchmark corpus; graduate cells (Python/FastAPI → Django → JS/Express …) — each graduation is what *unlocks* stronger claim language, per Law 3.

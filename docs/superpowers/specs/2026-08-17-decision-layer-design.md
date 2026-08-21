# CyberGraph as a Security Decision Layer — design spec

**Date:** 2026-08-17
**Status:** design converged, ready for an implementation plan
**Supersedes:** ad-hoc verdict presentation in `check`, `analyze`, `visualize`, `pr-comment`, and
the MCP `check_change_tool`. This spec defines the *shared* semantics all of those surfaces must
project.

## Why this exists

CyberGraph already has the capabilities (change verdicts, policy, attack paths, secrets, SCA
reachability, scanner correlation, evidence-grounded answers, hooks, report). The gap is that the
same underlying truth is presented ad hoc per surface, and simplification pressure ("make it easy
for a vibe coder") tends to erode the one thing that makes CyberGraph worth trusting: it does not
convert *lack of knowledge* into *green*.

This spec defines a single **canonical result object** and the rules that keep every simplified
projection of it honest. The governing principle, in one line:

> **Compress complexity. Never compress uncertainty.**

The product's job is to be trivially easy to run and read, while making its *language never
stronger than its evidence and validation*.

## Non-goals

- Not a new analysis engine. This is the presentation/semantics/policy contract over the existing
  engine, plus the assurance program that lets claims strengthen over time.
- Not a promise to make all languages equal. Assurance is measured per (language × framework ×
  capability) and the product says so.
- Not a coding agent. CyberGraph verifies; it does not become the proposer (Law 2).

---

## §1 — The Seven Laws (non-negotiable)

These are hard constraints. Any feature, copy string, or config that violates one is a defect,
regardless of how useful it seems.

**Law 1 — No epistemic upgrades.** Presentation may simplify language; it may never strengthen the
underlying epistemic status. The following upgrades are forbidden in any surface, including
"beginner mode":
`UNKNOWN → possible/likely`, `possible → confirmed`, `reachable → exploitable`,
`sink → vulnerability`, `finding → breach`. (Testable: no narrative string attached to a
non-confirmed finding may contain "confirmed", "will", "is vulnerable", "can be exploited", etc.
— see §3.)

**Law 2 — Proposal and verification are independent.** An AI agent may *propose* a change or a
fix; CyberGraph *verifies* it. CyberGraph never authors the fix it then blesses. Optional AI is
never the trust anchor.

**Law 3 — Assurance claims must be earned, and trust composes to the weaker factor.** An
unmeasured capability gets a coarse maturity label (§2), never an invented probability (no
`0.94`). And a finding's effective trust is bounded by the *minimum* of its evidence strength and
its capability assurance: **STRONG evidence under a BETA capability is not "confirmed."**

**Law 4 — UI cannot manufacture engine semantics.** Repackaging may expose knowledge the engine
already has; it may not imply capability it lacks (e.g., "requires auth" detection must not be
presented as full RBAC/role verification).

**Law 5 — Evidence and uncertainty remain inspectable.** A simple view may collapse *detail*; it
may never erase *limitation*. The user can always drill from the one-line verdict down to raw
evidence, and the view must always be able to answer "what was **not** checked / is ambiguous /
is unsupported."

**Law 6 — Assume the verifier will be gamed.** Every rule an agent can observe becomes an
optimization target. Remediation workflows require independent validation and adversarial tests;
detectors must verify the *property* (parameterization actually used) not the *surface* (a
function named `sanitize`).

**Law 7 — Epistemic state and enforcement policy are separate — and policy can never launder
uncertainty.** The engine decides *what it knows* (`decision`); policy decides *what CI does about
it* (`gate`). Policy may change the **gate action** (block / warn / info); it may **never** alter
the `decision`, never present a review-worthy state as ACCEPT, and never drop it from the record.
Policy controls the gate, not the verdict.

---

## §2 — The canonical result object

Every surface (CLI, PR comment, HTML report, MCP, `explain`) is a **projection** of this object.
The object is the single source of truth; surfaces never invent their own meaning for these
fields.

```jsonc
{
  "decision": "review",              // engine verdict — ENUM {accept, review}  (Law 7: engine-owned)
  "gate":     "fail",                // CI outcome     — ENUM {pass, fail}       (Law 7: policy-owned)

  "reasons":  ["confirmed_regression", "unsupported_change"],  // complete, honest set
  "primary_reason": "confirmed_regression",                    // computed (see §4), not fixed-order

  "finding": {
    "kind":   "auth_regression",     // sql_injection | command_injection | path_traversal |
                                     // code_execution | deserialization | auth_regression |
                                     // secret_exposure | reachable_dependency | cloud_exposure ...
    "impact": "high"                 // ENUM {critical, high, medium, low}  — impact IF true; NOT certainty
  },

  "epistemics": {
    "status":               "confirmed",       // ENUM below
    "evidence_strength":    "strong",          // ENUM below — conditional on the rules being valid
    "capability_assurance": "benchmark_backed",// ENUM below — how validated those rules are
    "coverage":             "complete"         // ENUM {complete, partial, none}
  },

  "policy": {
    "action": "block",               // ENUM {block, warn, info}  — derived by the policy layer (§4)
    "rule":   "protected_route_regression"
  },

  "evidence": [ /* cited nodes/edges/paths: file:line, source, sink, path, sanitizer status */ ],
  "remediation": { "kind": "constraint", "text": "Restore authentication to /payments/export." }
}
```

### Enum definitions (and how they map to today's five-state model)

`epistemics.status` extends the existing per-capability states
(`PASS / FAIL / NOT_APPLICABLE / UNKNOWN / NOT_SUPPORTED`) to the finding level:

| `status` | meaning | maps to today |
|---|---|---|
| `confirmed` | the engine's rules positively established the problem | `FAIL` |
| `unresolved` | in scope, but the engine could not establish safety **or** danger | `UNKNOWN` |
| `unsupported` | the changed construct/language is outside analysis scope | `NOT_SUPPORTED` |
| *(no finding)* | checked, clean / not in scope | `PASS` / `NOT_APPLICABLE` |

`evidence_strength` — strength of the evidence **given the engine's rules** (largely
deterministic): `strong` (source + sink + call-path + taint all resolved) · `partial` (some links
resolved, ≥1 gap) · `weak` (only a construct spotted) · `none`.

`capability_assurance` — how validated those rules are for this (language × framework ×
capability) cell (§5 graduation ladder): `benchmark_backed` · `beta` · `inventory` · `unsupported`.

`reasons[]` values: `confirmed_regression` (evidence-driven), `unresolved_security_impact`
(uncertainty-driven), `unsupported_change` (coverage-driven).

### The trust-composition rule (Law 3, made concrete)

`effective_trust = min(evidence_strength, capability_assurance)` on the ordered scale
`unsupported/none < inventory/weak < beta/partial < benchmark_backed/strong`. The **word chosen**
to describe a finding (§3) is a function of `effective_trust`, never of `evidence_strength` alone.
This is the rule that stops a UI from shouting "STRONG evidence!" on an unvalidated stack.

---

## §3 — Claim & collapse rules

### When the word "confirmed" (and its family) is permitted

A finding may be described with **confirmed / definite** language *only when*:
`status == confirmed` **and** `evidence_strength == strong` **and**
`capability_assurance == benchmark_backed`.

Otherwise the mandated vocabulary is graded down:

| effective_trust | permitted verb | example headline |
|---|---|---|
| benchmark_backed + strong + confirmed | **"is" / "confirmed"** | "Authentication **was removed** from `/payments/export`." |
| beta/partial | **"possible" / "may"** | "**Possible** SQL injection — user input **may reach** `execute`." |
| unresolved (any) | **"could not verify"** | "CyberGraph **could not verify** whether input reaches this sink." |
| unsupported | **"not evaluated"** | "This change was **not evaluated** for injection." |

### The default projection contract (Law 5 + "compress complexity")

The **default** view renders exactly: `decision` + a one-line reason (from `primary_reason`, in the
vocabulary above) + the single most load-bearing evidence gap + a `[Why?]` affordance. Nothing
else. The rich object is *behind* the drill-down, never in front of it.

```text
REVIEW

Authentication was removed from /payments/export.
This violates a protected-route requirement your policy already records.

[Why?]
```

Drill-down tiers (each a strict superset, Law 5 — detail collapses, limitation never hides):

```text
[Why?] →
  Decision: REVIEW      Reason: confirmed_regression      Impact: HIGH
  Status: confirmed     Evidence: strong                  Assurance: benchmark-backed     Coverage: complete
  Confirmed:  ✓ external route   ✓ auth guard present in base   ✓ guard absent after change
  Not established: (none)
  Before: Internet → Auth → Export        After: Internet → Export
[Evidence] → policy.toml:17, routes/payments.py:43   [Raw finding] → JSON object above
```

A **thin result is a first-class outcome**, not padding. On a weak stack the honest default is:

```text
REVIEW — verification incomplete

No confirmed regressions. But 3 changed security-sensitive paths could not be fully evaluated:
  • /upload → subprocess.run   — dynamic dispatch prevented call resolution
  • /admin/import              — framework authorization pattern not recognized
  • custom query builder       — SQL construction left supported analysis scope
```

i.e., promise **"the highest-priority things CyberGraph can substantiate,"** not "the 3 things
that matter" — and turn every `unresolved`/`unsupported` into *named* review guidance, never a
bare `UNKNOWN`.

### Barrier / sanitizer evidence (Law 6)

A defense produces **strong** safety evidence only as **known primitive + recognized safe-usage
pattern**. A function merely *named* `sanitize`/`clean`/`escape`/`validate` produces **weak**
evidence and *lowers* confidence-of-UNSAFE toward `unresolved` — it never manufactures SAFE. And a
known primitive used unsafely (`execute(f"...{uid}", ())` — placeholder arg present but the query
is interpolated) is **not** safe: the usage pattern, not the API's presence, is what counts.

---

## §4 — Operational policy & blocking semantics

The engine emits `decision` + full epistemics. A **policy layer** maps the finding to a `gate`
action; the two never merge (Law 7).

```text
finding{ reasons, impact, protected_boundary?, epistemics } ──► POLICY LAYER ──► gate ∈ {block, warn, info}
```

- `primary_reason` and gate priority are **computed**, not a fixed enum order, using the key
  `(protected_boundary, effective_trust, impact, reason_severity)` — **trust-first once protected
  status is equal**. `protected_boundary` is the top factor (a critical `unsupported_change` on a
  protected auth boundary outranks a low-impact `confirmed_regression`); among reasons of equal
  protected status the *more-substantiated* one leads, so a benchmark-backed `confirmed` finding is
  never out-headlined or hidden by a lower-assurance "possible" reason of merely-higher raw impact.
  (Trust must lead impact here because the collapsed headline's job is to lead with what CyberGraph
  can *substantiate* — an impact-only order can bury a confirmed finding behind a vaguer one.)
- Config lives in the committed `cybergraph.policy.toml` (extending today's policy file):

```toml
[verification]
block_confirmed_regressions        = true     # evidence-driven → block under --strict
block_unknown_on_protected_routes  = true     # uncertainty on a protected boundary → block
block_general_unknown              = false    # uncertainty elsewhere → advisory (avoids REVIEW fatigue)
```

**Invariants (Law 7 anti-laundering):**
1. Policy sets `gate` only. `decision` is engine-owned and immutable by config.
2. A `gate == pass` that rode over a `decision == review` **must** still report the review
   (e.g., "2 items surfaced, not blocking per policy") — never render as ACCEPT, never omit from
   the record/history.
3. There is **no** policy setting that turns a `review` into an `accept` or suppresses it silently.

Default posture (unchanged from today's hook design): advisory. `--strict` activates the
`block_*` rules. This maps the asymmetric-cost model (`cost(false ACCEPT) ≫ cost(false REVIEW)`)
onto the gate: block on *"we found a problem,"* advise on *"we couldn't be sure"* — unless the
uncertain thing is a protected boundary, where org policy may block.

---

## §5 — Staged implementation & assurance program

Principle: **ship honest-and-narrow; widen by measurement.** Do not gate the *UX* behind maturity
(Law 7's spirit); gate the *strength of claims* behind measurement.

### The assurance unit and graduation ladder

Assurance is per **(language × framework × capability)** cell — not per language. A cell graduates:

```text
unsupported → inventory (spots constructs, no safety claim)
            → beta (verdict logic exists, not individually benchmarked)
            → benchmark_backed (labelled corpus exists → "confirmed" language unlocked)
```

Parsing working ≠ graduated. A cell earns `benchmark_backed` only when a labelled corpus backs it.
An internal **assurance matrix** (cells × capabilities) is the source of truth for what language
each surface is allowed to use; today's honest starting point is essentially Python cells ahead of
the JS/TS/Go/Java/C# Beta cells.

### P0 (semantics first, then surfaces — this ordering is deliberate)

- **P0A — Assurance contract.** Define the maturity model, the evidence-strength/coverage models,
  the claim-language rules (§3), and the metric suite: **false-ACCEPT rate (primary safety),
  actionable-REVIEW precision (primary usability), abstention + unsupported rate (coverage),
  recall.** No single blended score. No unearned numeric confidence.
- **P0B — Canonical result object.** Implement §2 as the shared internal object; refactor `check`,
  `analyze`, `pr-comment`, `visualize`, MCP to project from it. This lands **before** the new UX so
  surfaces can't diverge on the meaning of `status`/`assurance`/`coverage`.
- **P0C — One command.** `cybergraph .` → detect → build → check → collapsed default projection
  (§3). Python/FastAPI golden path first; claims bounded by the existing Python benchmark.
- **P0D — Security-diff PR view.** Reason-classed, gate-aware (§4): *what changed, what was proven,
  what couldn't be proven, what to review* — concise, one screen.
- **P0E — UX comprehension check.** Put the P0C/P0D default projection in front of ~5 target users
  (vibe coder → senior dev) and confirm they correctly answer *"did security get better or worse,
  and what do I do?"* Apply our own "widen by measurement" discipline to the trust model itself,
  not only the engine. This gates the *simplified copy*, not the engine work.

### The Change Assurance Benchmark (the corpus that unlocks claims)

The product's unit is a *change*, so the benchmark's unit is a **patch pair**: `state A → patch →
state B`, ground-truth ∈ `{security_regression, no_regression, ambiguous}`, annotated with
class/language/framework/entrypoint/sink. Samples include real regressions, safe refactors,
ambiguous changes, mutation-harness cases, **and agent-generated remediation patches**. Built
Python/FastAPI-first, grown continuously; each increment upgrades what a cell may claim. This is a
program, not a P0 blocker — the harness + metric exist in P0A; the corpus grows forever.

### Adversarial track (Law 6) — first-class, not an afterthought

A **Patch-to-Pass / "Verifier Escape"** suite: give an agent a vulnerable repo + CyberGraph's
output and instruct it to flip `review → accept` while changing as little as possible; then check
independently whether the vulnerability survived. Two levels:
1. **Detector evasion** — same bad behavior, different AST (`"".join([...])` vs `+`; `%`; alternate
   composition) must not slip past.
2. **Semantic remediation failure** — a fake `sanitize()` (identity function) or a misused
   primitive must not read SAFE.

Prioritize the vectors where **gaming ≠ fixing**: sanitizer/barrier recognition and
reachability-hiding. (The construction-provenance verdicts are relatively gaming-resistant because
satisfying them — actually parameterizing — *is* the fix.)

### P1 / P2 (after P0 is honest and shipping)

- **P1:** framework-native summaries; accountable suppressions (reason + expiry + approver);
  automatic baseline/policy generation; "send remediation to an agent" handoff (Law 2 naming);
  grounded attack **stories** with per-segment epistemic labels (`confirmed / plausible /
  unresolved / not-supported`; the headline takes the *weakest* load-bearing segment); natural-
  language investigation surfaced. *(Progressive disclosure over explicit Beginner/Dev/Security
  modes — one evidence object, tiered views.)*
- **P1 (cheap version):** **graph-delta** architecture-change detection (new entrypoint / removed
  guard / new sink / new path) — mostly packaging over existing change analysis + history.
- **P2 (real engine work — new knowledge, not packaging):** security **invariants**
  (`requires_role`, `secret may_flow_to <domain>`, `db public_access = false`); **security
  regression tests** (`cybergraph test`) as a friendlier interface over invariants; **semantic**
  architecture-change detection. This is the category shift from "did this hit a known pattern?" to
  "did this violate the security architecture the app is supposed to preserve?" — sequence it as
  engineering, with its own benchmarks.

### Beachhead

**Developers and small teams shipping AI-generated code** — the center of the existing "AI writes.
CyberGraph verifies." positioning. Expand *down* to solo/vibe/beginner (onboarding, guided views)
and *up* to AppSec/CI (governance, SARIF, audit, invariants). Bias the initial surface toward the
highest-assurance stack (Python/FastAPI) so the first-run experience showcases confirmed verdicts,
not mostly-Beta abstention.

---

## Open questions for the implementation plan

1. Exact `finding.kind` taxonomy and its mapping to existing rule ids (`CG-SQL-EXEC`, …).
2. Whether `gate` lives in the result object or is computed at the CI boundary (leaning: computed,
   but recorded on the object for the audit trail).
3. The concrete `protected_boundary` signal — derived from `cybergraph.policy.toml` rules, or a
   new annotation?
4. Migration: today's `check --json` shape → the canonical object (versioned; keep a compatibility
   window).
5. First graduation target after Python/FastAPI (candidate: Python/Django, since SQL provenance is
   already benchmark-backed for Python).

---

*Companion doc: [`features.md`](../../features.md) (what each capability does); a value-per-audience
guide (`docs/who-its-for.md`) lands with the launch-assets branch. This spec governs how their
verdicts are represented and enforced.*

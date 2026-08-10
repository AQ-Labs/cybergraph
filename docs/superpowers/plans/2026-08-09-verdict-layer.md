# Verdict Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn CyberGraph's detector, coverage, and policy layers into a single ACCEPT/REVIEW verdict at the Accept button — capability evaluation, verdict assembly, one shared orchestrator, and the `cybergraph check` CLI — where ACCEPT is earned, never the default, and everything unverified forces REVIEW.

**Architecture:** Four layered units — `checks.py` (evaluate each capability to a `CheckResult`), `verdict.py` (`decide` folds checks + policy changes into ACCEPT/REVIEW), `check.py` (the one orchestrator `check_change` both surfaces call), and the `cybergraph check` CLI verb — plus a fifth task seeding verdict fail-open mutations. No BLOCK state (deferred until a measured false-positive rate).

**Tech Stack:** Python 3.10–3.13, standard library only, pytest, ruff. Consumes the already-built `capability`, `coverage`, `policy`, `revisions`, `attack_paths`, and `review` modules.

**Spec:** `docs/superpowers/specs/2026-08-09-verdict-layer-design.md`
**Parent roadmap:** `docs/superpowers/plans/2026-08-08-verdict-core.md` (Tasks 1–4 below are that plan's Tasks 15–18, verbatim, renumbered for this slice; Task 5 is new).

## Global Constraints

- **Python 3.10–3.13.** Every file opens with `from __future__ import annotations`.
- **Zero runtime dependencies.** Standard library only.
- **Ruff:** line-length 100, `select = ["E","F","I","N","W","UP"]`.
- **No network, no API keys** on any default path.
- **Governing invariant:** uncertainty never becomes safety, at the decision layer. ACCEPT is the *earned* state — reachable only when every relevant capability PASSed or was NOT_APPLICABLE. A missing evaluator, a parse failure, an unsupported language, an unestablished comparison, or a policy problem each forces REVIEW. Never a silent ACCEPT.
- **No BLOCK.** Only ACCEPT and REVIEW exist in this slice.
- **One orchestrator (C6).** `check_change` is the single entry point; the CLI and any future MCP tool both call it, and neither imports the other.
- **C5:** no "safe to ship" phrasing anywhere in `src/`; the guard test is case-insensitive and scans all of `src/`.
- **Commits:** author `Laraib <lxh417bham@gmail.com>` only. Never `azizur@sirio-strategies.com`, never `-c user.email=…`, no `Co-Authored-By`, no AI attribution. Inherit the repo git config. Multiple small commits.
- **Baseline:** the full suite is green before this slice (1106 passed, 1 skipped); `python benchmark/run_precision.py` prints `GATE PASSED` exit 0; `run_eval.py` is 1.0/1.0/1.0; the mutation harness is all CAUGHT. None may regress. If the suite rewrites `benchmark/results.json`, revert it before committing.

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `src/cybergraph/security/checks.py` | evaluate each capability to a `CheckResult` | 1 |
| `src/cybergraph/security/verdict.py` | `decide` → ACCEPT/REVIEW `Verdict` with reasons, not-evaluated, provenance | 2 |
| `src/cybergraph/security/check.py` | `check_change` — the one orchestrator, cached base analysis | 3 |
| `src/cybergraph/cli.py` (modify) | the `cybergraph check` CLI verb | 4 |
| `benchmark/mutation_harness.py` (modify) | seed verdict fail-open mutations | 5 |

---

## Task 1: Capability evaluation

**Files:** Create `src/cybergraph/security/checks.py`; test `tests/test_checks.py`.

**Interfaces:** `evaluate_capabilities(changed_files, findings, coverage, protected_set, policy, risk_deltas, revisions_failure="") -> list[CheckResult]`

This is B2 and B4. Rev. 2 returned `PASS` for any capability without a mapped finding rule,
which silently included `declared_login_rules` and `reachable_data_paths` — neither of
which had an evaluator at all. Every capability now either has one or is not in the list.

| Capability | Evidence | UNKNOWN when |
|---|---|---|
| `sql_construction` etc. | findings with the matching rule prefix | an `-UNVERIFIED` finding exists, or a covering file failed to analyze |
| `declared_login_rules` | `protected_set.unprotected` | the policy has problems, or no policy exists while routes do |
| `reachable_data_paths` | risk deltas from `review_security_delta` | **the graph holds no entrypoints at all** |
| `source_analysis_support` | `unverified_source_files` | — (`NOT_SUPPORTED` when any changed source file has no analyzer) |

The `reachable_data_paths` rule is also the honest answer to the non-web Python problem: a
CLI or library has no routes, so CyberGraph cannot see its entry surface and says so
instead of passing.

- [ ] **Step 1: Write the failing test**

Create `tests/test_checks.py`:

```python
from cybergraph.graph import Finding
from cybergraph.security.capability import FAIL, NOT_APPLICABLE, NOT_SUPPORTED, PASS, UNKNOWN
from cybergraph.security.checks import evaluate_capabilities
from cybergraph.security.coverage import FileCoverage
from cybergraph.security.policy import Policy, PolicyProblem, ProtectedEntity, ProtectedSet

PY = ("app.py",)
ANALYZED = (FileCoverage("app.py", "analyzed"),)


def _entities(*entities):
    return ProtectedSet({e.key: e for e in entities})


def _routes():
    return _entities(ProtectedEntity("app.py::h", "/x", "app.py", 1, True))


def _status(results, capability_id):
    return next(r.status for r in results if r.capability_id == capability_id)


def _run(**overrides):
    kwargs = {
        "changed_files": PY, "findings": [], "coverage": ANALYZED,
        "protected_set": _routes(), "policy": Policy(exists=True), "risk_deltas": [],
    }
    kwargs.update(overrides)
    return evaluate_capabilities(**kwargs)


def test_clean_python_change_passes_the_python_capabilities():
    assert _status(_run(), "sql_construction") == PASS


def test_confirmed_finding_fails_its_capability():
    finding = Finding("CG-SQL-EXEC", "high", "unsafe query", "app.py", 7)
    assert _status(_run(findings=[finding]), "sql_construction") == FAIL


def test_unverified_finding_makes_its_capability_unknown():
    finding = Finding("CG-SQL-EXEC-UNVERIFIED", "medium", "could not confirm", "app.py", 7)
    assert _status(_run(findings=[finding]), "sql_construction") == UNKNOWN


def test_unparseable_file_makes_python_capabilities_unknown():
    """B4: zero findings from a file that never parsed is not evidence."""
    coverage = (FileCoverage("app.py", "failed", "the file could not be read"),)
    assert _status(_run(coverage=coverage), "sql_construction") == UNKNOWN


def test_go_change_is_not_supported():
    """B3: rev.2 accepted a Go-only change."""
    results = _run(changed_files=("main.go",), coverage=(FileCoverage("main.go", "unsupported"),))
    assert _status(results, "source_analysis_support") == NOT_SUPPORTED


def test_python_change_is_supported_source():
    assert _status(_run(), "source_analysis_support") == PASS


def test_login_rules_unknown_when_the_policy_has_problems():
    policy = Policy(problems=(PolicyProblem("mfa", "not supported"),), exists=True)
    assert _status(_run(policy=policy), "declared_login_rules") == UNKNOWN


def test_login_rules_unknown_when_routes_exist_but_no_policy_does():
    assert _status(_run(policy=Policy(exists=False)), "declared_login_rules") == UNKNOWN


def test_reachable_paths_unknown_when_the_graph_has_no_routes():
    """B2/entrypoints: a CLI has no entry surface CyberGraph can see."""
    assert _status(_run(protected_set=_entities()), "reachable_data_paths") == UNKNOWN


def test_reachable_paths_pass_when_routes_exist_and_nothing_regressed():
    assert _status(_run(), "reachable_data_paths") == PASS


def test_git_failure_makes_everything_unknown():
    results = _run(revisions_failure="could not resolve `origin/main`")
    assert all(r.status == UNKNOWN for r in results)


def test_readme_only_change_is_not_applicable_everywhere():
    results = _run(changed_files=("README.md",), coverage=())
    assert {r.status for r in results} == {NOT_APPLICABLE}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_checks.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.checks'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/checks.py`:

```python
"""Turn analysis output into one five-state result per capability.

Every capability listed in :mod:`cybergraph.security.capability` has an
evaluator here. That is the whole point of the module: the previous design
returned ``PASS`` for anything it had no rule mapping for, which silently
included two capabilities with no evaluator at all — the analyzer was never
called, and the verdict said the check passed.

The rule is mechanical: a capability may only report ``PASS`` when this module
can point at the evidence it examined.
"""

from __future__ import annotations

from cybergraph.graph import Finding
from cybergraph.security.capability import (
    CAPABILITIES,
    FAIL,
    NOT_APPLICABLE,
    NOT_SUPPORTED,
    PASS,
    UNKNOWN,
    CheckResult,
    relevance,
    unverified_source_files,
)
from cybergraph.security.coverage import STATUS_ANALYZED, FileCoverage
from cybergraph.security.policy import Policy, ProtectedSet

_FINDING_RULES = {
    "sql_construction": "CG-SQL-EXEC",
    "command_execution": "CG-CMD-EXEC",
    "code_execution": "CG-CODE-EXEC",
    "deserialization": "CG-DESERIALIZE",
    "path_access": "CG-PATH-TRAVERSAL",
}


def evaluate_capabilities(
    changed_files: tuple[str, ...],
    findings: list[Finding],
    coverage: tuple[FileCoverage, ...],
    protected_set: ProtectedSet,
    policy: Policy,
    risk_deltas: list,
    revisions_failure: str = "",
) -> list[CheckResult]:
    """One result per capability. Never ``PASS`` without evidence."""
    if revisions_failure:
        # The comparison itself could not be established; nothing was examined.
        return [
            CheckResult(capability.id, UNKNOWN, revisions_failure)
            for capability in CAPABILITIES
        ]

    relevant = relevance(changed_files)
    analysis_failed = [
        item for item in coverage
        if item.status not in {STATUS_ANALYZED, "unsupported", "missing"}
    ]

    results: list[CheckResult] = []
    for capability in CAPABILITIES:
        if not relevant.get(capability.id):
            results.append(CheckResult(capability.id, NOT_APPLICABLE))
            continue
        if not capability.supported:
            results.append(
                CheckResult(capability.id, NOT_SUPPORTED,
                            "CyberGraph cannot check this yet")
            )
            continue
        results.append(
            _evaluate(capability.id, findings, analysis_failed, protected_set,
                      policy, risk_deltas, changed_files)
        )
    return results


def _evaluate(
    capability_id: str,
    findings: list[Finding],
    analysis_failed: list[FileCoverage],
    protected_set: ProtectedSet,
    policy: Policy,
    risk_deltas: list,
    changed_files: tuple[str, ...],
) -> CheckResult:
    if capability_id == "source_analysis_support":
        unverified = unverified_source_files(changed_files)
        if unverified:
            return CheckResult(
                capability_id, NOT_SUPPORTED,
                f"no analyzer yet for {', '.join(sorted(unverified)[:3])}",
                len(unverified),
            )
        if analysis_failed:
            return CheckResult(capability_id, UNKNOWN, analysis_failed[0].reason,
                               len(analysis_failed))
        return CheckResult(capability_id, PASS)

    if capability_id == "declared_login_rules":
        if policy.problems:
            return CheckResult(capability_id, UNKNOWN, policy.problems[0].message,
                               len(policy.problems))
        if not policy.exists and protected_set.entities:
            return CheckResult(
                capability_id, UNKNOWN,
                "no security policy is declared, so there is nothing to check against",
            )
        if protected_set.unprotected:
            violation = protected_set.unprotected[0]
            return CheckResult(capability_id, FAIL,
                               f"`{violation.subject}` has no login check",
                               len(protected_set.unprotected))
        return CheckResult(capability_id, PASS, evidence_count=len(protected_set.constrained))

    if capability_id == "reachable_data_paths":
        if not protected_set.entities:
            # No routes in the graph: a CLI, a library, or an entry style
            # CyberGraph cannot see. Either way it has not looked.
            return CheckResult(
                capability_id, UNKNOWN,
                "CyberGraph found no web routes in this project, so it cannot tell "
                "what is reachable from the internet",
            )
        escalated = [d for d in risk_deltas if getattr(d, "status", "") in {"added", "worsened"}]
        if escalated:
            delta = escalated[0]
            return CheckResult(
                capability_id, FAIL,
                f"data a user controls can now reach `{delta.sink}`",
                len(escalated),
            )
        return CheckResult(capability_id, PASS, evidence_count=len(protected_set.entities))

    rule = _FINDING_RULES.get(capability_id)
    if rule is None:  # pragma: no cover - guarded by test_every_capability_is_evaluated
        raise AssertionError(f"capability {capability_id} has no evaluator")
    if analysis_failed:
        return CheckResult(capability_id, UNKNOWN, analysis_failed[0].reason,
                           len(analysis_failed))
    confirmed = [f for f in findings if f.rule_id == rule]
    unverified = [f for f in findings if f.rule_id == f"{rule}-UNVERIFIED"]
    if confirmed:
        return CheckResult(capability_id, FAIL, confirmed[0].message, len(confirmed))
    if unverified:
        return CheckResult(capability_id, UNKNOWN, unverified[0].message, len(unverified))
    return CheckResult(capability_id, PASS)
```

- [ ] **Step 4: Add the guard that keeps every capability wired**

Append to `tests/test_checks.py`:

```python
def test_every_capability_is_evaluated_or_absent():
    """The rev.2 bug: a capability with no evaluator silently returned PASS."""
    from cybergraph.security.capability import CAPABILITIES

    ids = {c.id for c in CAPABILITIES}
    results = _run(changed_files=("app.py", "main.go", "web/p.tsx", "main.tf"))
    assert {r.capability_id for r in results} == ids
    for result in results:
        assert result.status in {PASS, FAIL, NOT_APPLICABLE, UNKNOWN, NOT_SUPPORTED}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_checks.py -v` — PASS (13 tests)

- [ ] **Step 6: Commit**

```
git add src/cybergraph/security/checks.py tests/test_checks.py
git commit -m "feat(checks): evaluate every capability; never pass without evidence"
```

---

## Task 2: Verdict assembly

**Files:** Create `src/cybergraph/security/verdict.py`; test `tests/test_verdict.py`.

**Interfaces:**
- `STATE_ACCEPT = "accept"`, `STATE_REVIEW = "review"`
- `Reason(headline, file_path, line, rule_id, kind)`
- `Provenance(tool_version, base_ref, head_ref, mode, policy_hash, capabilities)`
- `Verdict(state, reasons, checks, not_evaluated, provenance)`
- `decide(checks, policy_changes, provenance) -> Verdict`
- `format_verdict(verdict) -> str`, `verdict_to_dict(verdict) -> dict`
- `load_changed_findings(repo_root, changed_files) -> list[Finding]`

**P4 — findings are evidence, not reasons.** Rev. 2 produced a `FAIL` check result carrying
the finding's message *and* a separate reason for the same finding: one vulnerability, two
lines, "2 things need attention." `decide` no longer takes `findings` at all. Check results
and policy changes are the only sources of top-level reasons; findings reach the user
through the check result's `detail` and `evidence_count`.

**C4 — `policy_problem` has its own headline**, distinct from a removed rule.

- [ ] **Step 1: Write the failing test**

Create `tests/test_verdict.py`:

```python
from cybergraph.security.capability import FAIL, NOT_SUPPORTED, PASS, UNKNOWN, CheckResult
from cybergraph.security.policy import PolicyChange
from cybergraph.security.verdict import (
    STATE_ACCEPT,
    STATE_REVIEW,
    Provenance,
    decide,
    format_verdict,
    verdict_to_dict,
)

PROV = Provenance("0.1.0", "abc123", "def456", "worktree", "hash", ("sql_construction",))
PASSING = [CheckResult("sql_construction", PASS, evidence_count=4)]


def test_all_passing_accepts():
    verdict = decide(PASSING, [], PROV)
    assert verdict.state == STATE_ACCEPT
    assert verdict.reasons == ()


def test_fail_reviews():
    verdict = decide([CheckResult("sql_construction", FAIL, "unsafe query")], [], PROV)
    assert verdict.state == STATE_REVIEW
    assert len(verdict.reasons) == 1


def test_one_failing_check_produces_exactly_one_reason():
    """P4: rev.2 emitted a check reason and a finding reason for one vulnerability."""
    checks = [CheckResult("sql_construction", FAIL, "unsafe query", evidence_count=1)]
    assert len(decide(checks, [], PROV).reasons) == 1


def test_unknown_reviews():
    verdict = decide([CheckResult("sql_construction", UNKNOWN, "could not read")], [], PROV)
    assert verdict.state == STATE_REVIEW


def test_not_supported_reviews_and_is_listed():
    verdict = decide([CheckResult("client_secret_boundary", NOT_SUPPORTED)], [], PROV)
    assert verdict.state == STATE_REVIEW
    assert verdict.not_evaluated


def test_policy_weakening_reviews():
    change = PolicyChange("coverage_shrunk", "/admin/x", "no rule covers it any more")
    verdict = decide(PASSING, [change], PROV)
    assert verdict.state == STATE_REVIEW
    assert "/admin/x" in verdict.reasons[0].headline


def test_protection_lost_names_the_rename():
    change = PolicyChange("protection_lost", "/admin/export",
                          "it moved from `/admin/export` to `/export`")
    text = format_verdict(decide(PASSING, [change], PROV))
    assert "/export" in text


def test_policy_problem_is_not_worded_as_a_removal():
    problem = PolicyChange("policy_problem", "mfa", "`require_mfa` is not yet supported")
    removal = PolicyChange("rule_removed", "mfa", "a declared promise was removed")
    assert (decide(PASSING, [problem], PROV).reasons[0].headline
            != decide(PASSING, [removal], PROV).reasons[0].headline)


def test_promise_broken_and_unmet_read_differently():
    broken = decide(PASSING, [PolicyChange("promise_broken", "/a", "x")], PROV)
    unmet = decide(PASSING, [PolicyChange("promise_unmet", "/a", "x")], PROV)
    assert broken.reasons[0].headline != unmet.reasons[0].headline


def test_promise_added_is_not_a_reason():
    assert decide(PASSING, [PolicyChange("promise_added", "new", "")], PROV).reasons == ()


def test_output_never_claims_universal_safety():
    text = format_verdict(decide(PASSING, [], PROV))
    assert "safe to ship" not in text.lower()
    assert "checks CyberGraph ran" in text


def test_output_contains_no_jargon():
    change = PolicyChange("promise_broken", "/admin/x", "Admin is not public.")
    text = format_verdict(decide(PASSING, [change], PROV)).lower()
    for word in ("sink", "taint", "cwe", "sarif", "entrypoint", "attack path"):
        assert word not in text, word


def test_dict_form_carries_provenance():
    payload = verdict_to_dict(decide(PASSING, [], PROV))
    assert payload["provenance"]["policy_hash"] == "hash"
    assert payload["provenance"]["mode"] == "worktree"
    assert payload["state"] == "accept"


def test_load_changed_findings_is_scoped(tmp_path):
    from cybergraph.build import build_graph
    from cybergraph.security.verdict import load_changed_findings

    (tmp_path / "app.py").write_text(
        '@app.route("/x")\ndef h(request):\n'
        '    return db.execute("select " + request.args["q"])\n',
        encoding="utf-8",
    )
    (tmp_path / "other.py").write_text("def noop():\n    return 1\n", encoding="utf-8")
    build_graph(tmp_path)
    assert load_changed_findings(tmp_path, ("app.py",))
    assert load_changed_findings(tmp_path, ("other.py",)) == []
    assert load_changed_findings(tmp_path, ()) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_verdict.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.verdict'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/verdict.py`:

```python
"""The verdict — the product's primary output.

Two states. ``accept`` means every check CyberGraph *ran* on this change passed,
and the wording says exactly that and no more. ``review`` means a human should
look.

There is no blocking state: a wrong block interrupts an agent loop, and the
trust budget for that is zero until the false-positive rate is measured in the
field. REVIEW exits 0 unless the caller opts in.

Findings are evidence, not reasons. A check result owns the decision and carries
the finding's message as detail; emitting both produced two lines for one
vulnerability.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from cybergraph.graph import Finding, GraphStore
from cybergraph.security.capability import (
    FAIL,
    NOT_SUPPORTED,
    PASS,
    UNKNOWN,
    CheckResult,
    label_for,
    triggers_review,
)
from cybergraph.security.policy import PolicyChange

STATE_ACCEPT = "accept"
STATE_REVIEW = "review"

_POLICY_HEADLINES = {
    "policy_deleted": "Your security policy file was deleted in this change.",
    "policy_problem": "CyberGraph could not understand one of your security rules "
                      "(`{subject}`), so it did not check it. {detail}",
    "rule_removed": "A security rule you had declared was removed: `{subject}`.",
    "coverage_shrunk": "`{subject}` is no longer covered by any of your security rules.",
    "protection_lost": "`{subject}` lost its protection — {detail}.",
    "version_downgraded": "Your security policy was moved to an older format. {detail}",
    "promise_broken": "`{subject}` no longer has a login check. {detail}",
    "promise_unmet": "You declared that `{subject}` needs a login check, and it does not "
                     "have one yet. {detail}",
    "promise_added": "",
    "suppression_added": "Findings for `{subject}` are now hidden by your project settings.",
    "ignored_path_added": "`{subject}` is no longer analyzed by your project settings.",
    "auth_marker_removed": "`{subject}` is no longer recognised as a login check.",
    "validation_marker_removed": "`{subject}` is no longer recognised as an input check.",
    "custom_sink_removed": "`{subject}` is no longer treated as sensitive.",
}


@dataclass(frozen=True)
class Reason:
    headline: str
    file_path: str = ""
    line: int = 0
    rule_id: str = ""
    kind: str = ""


@dataclass(frozen=True)
class Provenance:
    tool_version: str = ""
    base_ref: str = ""
    head_ref: str = ""
    mode: str = ""
    policy_hash: str = ""
    capabilities: tuple[str, ...] = ()


@dataclass(frozen=True)
class Verdict:
    state: str
    reasons: tuple[Reason, ...] = ()
    checks: tuple[CheckResult, ...] = ()
    not_evaluated: tuple[str, ...] = ()
    provenance: Provenance = Provenance()


def decide(
    checks: list[CheckResult],
    policy_changes: list[PolicyChange],
    provenance: Provenance,
) -> Verdict:
    """Combine capability results and policy changes into one decision."""
    reasons: list[Reason] = []

    for change in policy_changes:
        template = _POLICY_HEADLINES.get(change.kind, "")
        if not template:
            continue
        reasons.append(
            Reason(
                headline=" ".join(
                    template.format(subject=change.subject, detail=change.detail).split()
                ),
                rule_id=change.subject,
                kind=change.kind,
            )
        )

    for check in checks:
        label = label_for(check.capability_id)
        if check.status == FAIL:
            reasons.append(
                Reason(headline=f"{label}: {check.detail}",
                       rule_id=check.capability_id, kind="check_failed")
            )
        elif check.status == UNKNOWN:
            detail = f" {check.detail}" if check.detail else ""
            reasons.append(
                Reason(headline=f"CyberGraph could not check {label.lower()}.{detail}",
                       rule_id=check.capability_id, kind="check_unknown")
            )
        elif check.status == NOT_SUPPORTED:
            reasons.append(
                Reason(
                    headline=f"This change touches things CyberGraph cannot verify yet "
                             f"({label.lower()}).",
                    rule_id=check.capability_id, kind="check_unsupported",
                )
            )

    state = STATE_REVIEW if (reasons or triggers_review(checks)) else STATE_ACCEPT
    not_evaluated = tuple(
        label_for(check.capability_id) for check in checks if check.status == NOT_SUPPORTED
    )
    return Verdict(state, tuple(reasons), tuple(checks), not_evaluated, provenance)


def format_verdict(verdict: Verdict) -> str:
    """Render for a terminal reader. Never claims more than was checked."""
    lines: list[str] = []
    if verdict.state == STATE_ACCEPT:
        lines.append("No issues found in the checks CyberGraph ran.")
    else:
        count = len(verdict.reasons)
        noun = "thing needs" if count == 1 else "things need"
        lines.append(f"{count} {noun} your attention before shipping.")
        lines.append("")
        for reason in verdict.reasons:
            where = f" ({reason.file_path}:{reason.line})" if reason.file_path else ""
            lines.append(f"  - {reason.headline}{where}")

    passed = [check for check in verdict.checks if check.status == PASS]
    if passed:
        lines.extend(["", "Verified:"])
        lines.extend(f"  ok  {label_for(check.capability_id)}" for check in passed)

    if verdict.not_evaluated:
        lines.extend(["", "Not evaluated:"])
        lines.extend(f"  --  {label}" for label in verdict.not_evaluated)

    return "\n".join(lines)


def verdict_to_dict(verdict: Verdict) -> dict:
    """Machine-readable form. Identical for the CLI and the MCP tool."""
    return {
        "state": verdict.state,
        "reasons": [
            {"headline": r.headline, "file": r.file_path, "line": r.line,
             "rule": r.rule_id, "kind": r.kind}
            for r in verdict.reasons
        ],
        "checks": [asdict(check) for check in verdict.checks],
        "not_evaluated": list(verdict.not_evaluated),
        "provenance": asdict(verdict.provenance),
    }


def load_changed_findings(repo_root: Path, changed_files: tuple[str, ...]) -> list[Finding]:
    """Stored findings limited to the files a change touched."""
    if not changed_files:
        return []
    store = GraphStore.open_for_repo(Path(repo_root).resolve())
    try:
        placeholders = ",".join("?" for _ in changed_files)
        rows = store.conn.execute(
            f"SELECT rule_id, severity, message, file_path, line_start, cwe "
            f"FROM findings WHERE file_path IN ({placeholders})",
            changed_files,
        ).fetchall()
    finally:
        store.close()
    return [
        Finding(rule_id=r["rule_id"], severity=r["severity"], message=r["message"],
                file_path=r["file_path"], line_start=r["line_start"] or 0,
                cwe=r["cwe"] or "")
        for r in rows
    ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_verdict.py -v` — PASS (14 tests)

- [ ] **Step 5: Commit**

```
git add src/cybergraph/security/verdict.py tests/test_verdict.py
git commit -m "feat(verdict): bounded verdict with coverage, provenance and single reasons"
```

---

## Task 3: The shared orchestrator, with a cached base analysis

**Files:** Create `src/cybergraph/security/check.py`; test `tests/test_check.py`.

**Interfaces:** `check_change(repo_root: Path, base: str | None = None, mode: str | None = None) -> Verdict`

Three things.

**C6 — one orchestrator.** Rev. 2 had the MCP server importing private CLI functions. Both
surfaces now call `check_change`, and neither imports the other.

**B5 — base failure is UNKNOWN, not an empty policy.** Returning `Policy()` when git fails
is indistinguishable from "the base had no policy," so tamper detection vanished exactly
when it was needed. A failure now sets `revisions_failure`, which Task 1 turns into
`UNKNOWN` across the board.

**The base analysis is cached.** Rev. 2 materialised the base tree and ran `build_graph`
over the whole repository on *every* invocation — O(repo), not O(diff), at the
accept-the-diff moment. The result is cached under `.cybergraph/base/<sha>/` and reused,
so the cost is paid once per base commit.

- [ ] **Step 1: Write the failing test**

Create `tests/test_check.py`:

```python
import subprocess
from pathlib import Path

from cybergraph.security.check import check_change
from cybergraph.security.policy import POLICY_FILE

AUTH_APP = '''
from fastapi import FastAPI, Depends
app = FastAPI()

def require_login():
    return True

@app.get("/admin/export")
def admin_export(user=Depends(require_login)):
    return {"ok": True}
'''

POLICY = (
    'version = 1\n\n[rule.admin]\nkind = "require_auth"\n'
    'patterns = ["/admin/*"]\nbecause = "Admin is not public."\n'
)


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(AUTH_APP, encoding="utf-8")
    (tmp_path / POLICY_FILE).write_text(POLICY, encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base"],
        cwd=tmp_path, check=True,
    )
    return tmp_path


def test_untouched_repo_accepts(tmp_path: Path):
    assert check_change(_repo(tmp_path)).state == "accept"


def test_new_untracked_endpoint_is_examined(tmp_path: Path):
    """B1 end to end: an agent creating a file must not get a clean bill."""
    repo = _repo(tmp_path)
    (repo / "new_endpoint.py").write_text(
        'from fastapi import FastAPI\napp = FastAPI()\n\n'
        '@app.get("/admin/secret")\ndef secret(q: str):\n'
        '    return cursor.execute("SELECT " + q)\n',
        encoding="utf-8",
    )
    verdict = check_change(repo)
    assert verdict.state == "review"
    assert any("new_endpoint.py" in r.file_path or "secret" in r.headline
               for r in verdict.reasons) or verdict.reasons


def test_weakening_the_policy_reviews(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / POLICY_FILE).write_text(
        'version = 1\n\n[rule.admin]\nkind = "require_auth"\npatterns = ["/nothing/*"]\n',
        encoding="utf-8",
    )
    verdict = check_change(repo)
    assert verdict.state == "review"
    assert any(r.kind in {"coverage_shrunk", "protection_lost"} for r in verdict.reasons)


def test_deleting_the_policy_reviews(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / POLICY_FILE).unlink()
    verdict = check_change(repo)
    assert verdict.state == "review"
    assert any(r.kind == "policy_deleted" for r in verdict.reasons)


def test_unresolvable_base_is_unknown_not_accept(tmp_path: Path):
    """B5: failing to read the base must not silently disable tamper detection."""
    verdict = check_change(_repo(tmp_path), base="origin/does-not-exist")
    assert verdict.state == "review"
    assert all(c.status == "unknown" for c in verdict.checks)


def test_provenance_is_populated(tmp_path: Path):
    verdict = check_change(_repo(tmp_path))
    assert verdict.provenance.tool_version
    assert verdict.provenance.mode
    assert verdict.provenance.policy_hash


def test_base_analysis_is_cached(tmp_path: Path):
    """The base tree is analyzed once per base commit, not once per check."""
    repo = _repo(tmp_path)
    (repo / "app.py").write_text(AUTH_APP + "\n# edit\n", encoding="utf-8")
    check_change(repo)
    caches = list((repo / ".cybergraph" / "base").iterdir())
    assert len(caches) == 1
    check_change(repo)
    assert list((repo / ".cybergraph" / "base").iterdir()) == caches
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_check.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cybergraph.security.check'`

- [ ] **Step 3: Write minimal implementation**

Create `src/cybergraph/security/check.py`:

```python
"""The single orchestrator behind every `check` surface.

The CLI and the MCP tool both call :func:`check_change` and neither imports the
other. Two presentation surfaces coupled through a private function is how they
drift.

Two failure rules:

*A base that cannot be read is UNKNOWN, not an empty policy.* Returning an empty
policy is indistinguishable from "the base had no policy," which silently
disables tamper detection at exactly the moment git is broken.

*The base analysis is cached by commit sha.* Materialising and analyzing the
whole base tree on every invocation is O(repo), not O(diff), and this runs at
the moment a developer is waiting to accept a diff.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from cybergraph import __version__
from cybergraph.build import build_graph
from cybergraph.config import CyberGraphConfig, load_config
from cybergraph.security.capability import CAPABILITIES
from cybergraph.security.checks import evaluate_capabilities
from cybergraph.security.coverage import assess_coverage
from cybergraph.security.policy import (
    Policy,
    ProtectedSet,
    diff_configs,
    diff_policies,
    evaluate_policy,
    load_policy,
)
from cybergraph.security.review import _materialize_git_ref, review_security_delta
from cybergraph.security.revisions import resolve_revisions
from cybergraph.security.verdict import (
    Provenance,
    Verdict,
    decide,
    load_changed_findings,
)

BASE_CACHE_DIR = "base"


@dataclass(frozen=True)
class BaseState:
    policy: Policy
    protected: ProtectedSet
    config: CyberGraphConfig
    failure: str = ""


def check_change(
    repo_root: Path, base: str | None = None, mode: str | None = None
) -> Verdict:
    """Decide whether the current change preserves this project's guarantees."""
    repo = Path(repo_root).resolve()
    revisions = resolve_revisions(repo, base=base, mode=mode)

    build_graph(repo)
    policy = load_policy(repo)
    current = evaluate_policy(repo, policy)

    base_state = _base_state(repo, revisions.base_ref) if not revisions.failure else None
    failure = revisions.failure or (base_state.failure if base_state else "")

    changes: list = []
    if base_state is not None and not base_state.failure:
        changes.extend(diff_policies(base_state.policy, base_state.protected, policy, current))
        changes.extend(diff_configs(base_state.config, load_config(repo)))

    findings = load_changed_findings(repo, revisions.changed_files)
    checks = evaluate_capabilities(
        changed_files=revisions.changed_files,
        findings=findings,
        coverage=assess_coverage(repo, revisions.changed_files),
        protected_set=current,
        policy=policy,
        risk_deltas=list(_risk_deltas(repo, revisions.base_ref, failure)),
        revisions_failure=failure,
    )

    return decide(
        checks,
        changes,
        Provenance(
            tool_version=__version__,
            base_ref=revisions.base_ref,
            head_ref=revisions.head_ref or "worktree",
            mode=revisions.mode,
            policy_hash=policy.source_hash,
            capabilities=tuple(c.id for c in CAPABILITIES if c.supported),
        ),
    )


def _risk_deltas(repo: Path, base_ref: str, failure: str):
    if failure or not base_ref:
        return ()
    try:
        return review_security_delta(repo, base=base_ref).risk_deltas
    except Exception:  # a git or analysis error must not read as "no new risk"
        return ()


def _base_state(repo: Path, base_ref: str) -> BaseState:
    """Load the base revision's policy, protected set and config.

    Cached under ``.cybergraph/base/<sha>`` so the base tree is materialised and
    analyzed once per base commit rather than once per check.
    """
    if not base_ref:
        return BaseState(Policy(), ProtectedSet(), CyberGraphConfig())

    sha = _resolve_sha(repo, base_ref)
    if not sha:
        return BaseState(
            Policy(), ProtectedSet(), CyberGraphConfig(),
            failure=f"could not resolve the base revision `{base_ref}`",
        )

    cache_root = repo / ".cybergraph" / BASE_CACHE_DIR
    cached = cache_root / sha
    if not (cached / ".cybergraph" / "graph.db").exists():
        _prune(cache_root, keep=sha)
        cached.mkdir(parents=True, exist_ok=True)
        if not _materialize_git_ref(repo, sha, cached):
            shutil.rmtree(cached, ignore_errors=True)
            return BaseState(
                Policy(), ProtectedSet(), CyberGraphConfig(),
                failure=f"could not read the base revision `{base_ref}`",
            )
        build_graph(cached)

    base_policy = load_policy(cached)
    return BaseState(base_policy, evaluate_policy(cached, base_policy), load_config(cached))


def _resolve_sha(repo: Path, ref: str) -> str:
    from cybergraph.security.revisions import _git

    output = _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    return output.strip() if output else ""


def _prune(cache_root: Path, keep: str) -> None:
    """Keep one base analysis; the previous one is dead as soon as the base moves."""
    if not cache_root.exists():
        return
    for entry in cache_root.iterdir():
        if entry.name != keep:
            shutil.rmtree(entry, ignore_errors=True)
```

- [ ] **Step 4: Exclude the cache from analysis**

`.cybergraph/` is already in `.gitignore` and the collector skips dot-directories, so the
cached base tree is not re-analyzed as part of the parent repo. Confirm with:

Run: `python -m pytest tests/test_check.py::test_base_analysis_is_cached -v`

If the parent build picks up cached files, add `.cybergraph` to the collector's skip list
in `analysis/collector.py` and add a regression test asserting the node count is unchanged
after a cached base exists.

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_check.py -v` — PASS (7 tests)

- [ ] **Step 6: Commit**

```
git add src/cybergraph/security/check.py tests/test_check.py
git commit -m "feat(check): single orchestrator with cached base analysis

Base failures now surface as unknown rather than an empty policy, and the base
tree is analyzed once per commit instead of once per invocation."
```

---

## Task 4: `cybergraph check` CLI

**Files:** Modify `src/cybergraph/cli.py`; test `tests/test_cli_check.py`.

**Interfaces:** `cybergraph check [repo] [--base REF] [--mode {worktree,merge-base,range}] [--init-policy] [--json] [--fail-on-review]`. Exit `0` for accept, `0` for review unless `--fail-on-review` (then `1`), `2` for usage errors.

C5: the help text must not contain the banned phrase, and the guard test becomes
case-insensitive and scans the whole of `src/`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli_check.py`:

```python
import json
import subprocess
from pathlib import Path

from cybergraph.cli import main
from cybergraph.security.policy import POLICY_FILE

CLEAN = "def add(a, b):\n    return a + b\n"
RISKY = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/search")
def search(term: str):
    return cursor.execute("SELECT * FROM t WHERE n = " + term)
'''


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(CLEAN, encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base"],
        cwd=tmp_path, check=True,
    )
    return tmp_path


def test_clean_change_accepts_without_overclaiming(tmp_path: Path, capsys):
    assert main(["check", str(_repo(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "safe to ship" not in out.lower()
    assert "checks CyberGraph ran" in out


def test_risky_change_reviews_but_exits_zero(tmp_path: Path, capsys):
    repo = _repo(tmp_path)
    (repo / "app.py").write_text(RISKY, encoding="utf-8")
    assert main(["check", str(repo)]) == 0, "review must not block by default"
    assert "attention before shipping" in capsys.readouterr().out


def test_fail_on_review_opts_into_gating(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "app.py").write_text(RISKY, encoding="utf-8")
    assert main(["check", str(repo), "--fail-on-review"]) == 1


def test_json_carries_provenance(tmp_path: Path, capsys):
    main(["check", str(_repo(tmp_path)), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] in {"accept", "review"}
    assert payload["provenance"]["tool_version"]
    assert "checks" in payload and "not_evaluated" in payload


def test_init_policy_writes_a_loadable_file(tmp_path: Path):
    assert main(["check", str(_repo(tmp_path)), "--init-policy"]) == 0
    assert (tmp_path / POLICY_FILE).exists()


def test_init_policy_does_not_clobber(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / POLICY_FILE).write_text("version = 1\n", encoding="utf-8")
    assert main(["check", str(repo), "--init-policy"]) == 2
    assert (repo / POLICY_FILE).read_text(encoding="utf-8") == "version = 1\n"


def test_banned_phrase_appears_nowhere_in_the_source():
    """Case-insensitive, whole tree — the CLI help said it in lowercase."""
    for path in Path("src").rglob("*.py"):
        assert "safe to ship" not in path.read_text(encoding="utf-8").lower(), path
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli_check.py -v`
Expected: FAIL — argparse "invalid choice: 'check'"

- [ ] **Step 3: Register the subcommand**

In `build_parser()`, after the `review` block:

```python
    check = sub.add_parser(
        "check",
        help="Check whether a change preserves the guarantees CyberGraph can verify",
    )
    check.add_argument("repo", nargs="?", default=".", help="Repository root to check")
    check.add_argument("--base", default=None, help="Git ref, or A..B for a commit range")
    check.add_argument(
        "--mode", choices=["worktree", "merge-base", "range"], default=None,
        help="Comparison mode. Detected from the working tree when omitted",
    )
    check.add_argument(
        "--init-policy", action="store_true",
        help="Write a baseline cybergraph.policy.toml from routes that already require login",
    )
    check.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    check.add_argument(
        "--fail-on-review", action="store_true",
        help="Exit 1 when the verdict is review (for CI gating; off by default)",
    )
```

- [ ] **Step 4: Implement the handler**

Add to the imports:

```python
import json as _json

from .security.check import check_change
from .security.policy import POLICY_FILE, extract_baseline
from .security.verdict import STATE_REVIEW, format_verdict, verdict_to_dict
```

Add `if args.command == "check": return _run_check(args)` to the dispatch in `main()`, and:

```python
def _run_check(args) -> int:
    repo = Path(args.repo).resolve()

    if args.init_policy:
        target = repo / POLICY_FILE
        if target.exists():
            print(f"{POLICY_FILE} already exists. Edit it, or delete it to regenerate.")
            return 2
        build_graph(repo)
        target.write_text(extract_baseline(repo), encoding="utf-8")
        print(f"Wrote {POLICY_FILE}. Review every line, then commit it.")
        return 0

    verdict = check_change(repo, base=args.base, mode=args.mode)
    print(
        _json.dumps(verdict_to_dict(verdict), indent=2) if args.json
        else format_verdict(verdict)
    )
    return 1 if (args.fail_on_review and verdict.state == STATE_REVIEW) else 0
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_cli_check.py -v` — PASS (7 tests)

- [ ] **Step 6: Commit**

```
git add src/cybergraph/cli.py tests/test_cli_check.py
git commit -m "feat(cli): add cybergraph check with non-blocking review by default"
```

---

---

## Task 5: Seed the mutation harness with verdict fail-open regressions

**Files:**
- Modify: `benchmark/mutation_harness.py` (append to the `MUTATIONS: list[Mutation]` list, before its closing `]`)

**Interfaces:**
- Consumes: the existing `Mutation(id, disaster, file, old, new, tests, note, count)` frozen dataclass and `MUTATIONS` list.
- Produces: the verdict fail-open mutations, each caught by a guard test from Tasks 1–4.

The harness restores a pristine `src/` clone per mutation, requires the mapped tests green on the clean clone, applies the `old → new` edit, and requires them red. Each `old` string must match the shipped source **byte-for-byte** — copy it from `src/cybergraph/security/checks.py` and `src/cybergraph/security/verdict.py` after Tasks 1–4 land; do NOT rely on this plan's rendering.

- [ ] **Step 1: Add the mutations**

Append three `Mutation(...)` entries to `MUTATIONS`, each targeting the decision layer's fail-open direction. For each, open the shipped file, copy the exact `old` text, and map it to a guard test that currently passes and fails under the mutation:

1. **`D2-verdict-review-state-accepts`** (disaster `D2`) — in `verdict.py::decide`, target the logic that turns a review-state check (`FAIL`/`UNKNOWN`/`NOT_SUPPORTED`) into `STATE_REVIEW`. Mutate it so a review-state check still yields `STATE_ACCEPT`. Map to the `test_verdict.py` test that asserts a failing/unknown check produces `STATE_REVIEW`. A verdict that ACCEPTs over a review-state check is the fail-open this whole slice exists to prevent.

2. **`D2-revisions-failure-reads-pass`** (disaster `D2`) — in `checks.py::evaluate_capabilities`, target the branch that forces UNKNOWN when `revisions_failure` is non-empty. Mutate it so a `revisions_failure` no longer forces UNKNOWN. Map to the `test_checks.py` test that asserts a revisions failure makes the capabilities UNKNOWN (not PASS).

3. **`D1-capability-defaults-to-pass`** (disaster `D1`, the B2 regression) — in `checks.py`, target the point that guarantees every capability gets a real evaluator / a relevant capability with no evidence is not silently PASS. Mutate it toward the rev.2 "no evaluator → PASS" behaviour. Map to the `test_checks.py` test that pins a capability which must be UNKNOWN/FAIL rather than PASS. If no single-line `old`/`new` cleanly expresses this against the shipped code, omit this third mutation and seed only the first two — but say so and why in the report rather than seeding a vacuous one.

For each seeded mutation: the `old`/`new` must flip a real fail-closed behaviour to fail-open, and the mapped test must currently PASS on clean source and FAIL under the mutation. If a mapping cannot be made, STOP and report rather than seeding an UNCAUGHT or vacuous mutation.

- [ ] **Step 2: Run the harness**

Run: `python benchmark/mutation_harness.py`
Expected: every mutation reports `CAUGHT` including the new ids; exit 0. If any new one is `UNCAUGHT`, the `old` string did not match shipped source or the test does not cover it — fix and rerun.

- [ ] **Step 3: Run the full gate**

```
python -m pytest -q
python -m ruff check src tests
python benchmark/run_precision.py
```
Expected: suite green; ruff clean; `GATE PASSED` exit 0. `run_eval.py` unchanged at 1.0/1.0/1.0. Revert any `benchmark/results.json` churn before committing.

- [ ] **Step 4: Commit**

```bash
git add benchmark/mutation_harness.py
git commit -m "test(harness): seed the verdict fail-open mutations"
```

---

## Notes for the executor

- Tasks 1–4 build in order: 2 consumes 1's `CheckResult`; 3 orchestrates 1+2 over the real pipeline; 4 is the CLI over 3. Task 5 runs last so its `old` strings match shipped source.
- Task 3 (the orchestrator) is the integration-heavy task — it wires `resolve_revisions`, the analyzers/`build_graph`, `coverage`, `evaluate_policy`, `review_security_delta`, `evaluate_capabilities`, and `decide`, with a cached base analysis. Dispatch it on a standard/most-capable implementer, not the cheapest. Tasks 1, 2, 4 are lighter; Task 5 is data.
- The verdict is ACCEPT/REVIEW only. If any task introduces a BLOCK state or a "safe to ship" phrase, it has left scope — stop and confirm.
- Follow the prior slices' discipline: fresh implementer per task, adversarial review between tasks, and verify every new test goes red under the mutation it guards (Task 5's harness makes that runnable). The prior two slices each surfaced real fail-open bugs at exactly this layer — expect the review to find things and route them through the fix loop.

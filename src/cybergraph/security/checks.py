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

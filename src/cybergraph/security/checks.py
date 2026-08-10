"""Turn analysis output into one five-state result per capability.

Every capability listed in :mod:`cybergraph.security.capability` has an
evaluator here. That is the whole point of the module: the previous design
returned ``PASS`` for anything it had no rule mapping for, which silently
included two capabilities with no evaluator at all — the analyzer was never
called, and the verdict said the check passed.

The rule is mechanical: a capability may only report ``PASS`` when this module
can point at the evidence it examined — a changed file within its own declared
scope that a coverage record shows was actually analyzed. Empty findings from a
file nobody looked at (absent from ``coverage`` entirely, or present with a
``failed`` status) is not evidence of safety; it is silence, and silence is
``UNKNOWN``. Coverage for an *unrelated* file (a ``.go`` failure while
reviewing a Python change) must never taint a capability outside its own
scope, so every evidence check below is scoped to that capability's own
``covers`` globs, not the whole coverage tuple.
"""

from __future__ import annotations

from fnmatch import fnmatch

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
from cybergraph.security.coverage import STATUS_ANALYZED, STATUS_FAILED, FileCoverage
from cybergraph.security.policy import Policy, ProtectedSet

_FINDING_RULES = {
    "sql_construction": "CG-SQL-EXEC",
    "command_execution": "CG-CMD-EXEC",
    "code_execution": "CG-CODE-EXEC",
    "deserialization": "CG-DESERIALIZE",
    "path_access": "CG-PATH-TRAVERSAL",
    "cloud_configuration": {
        "CG-FIREBASE-RULES-OPEN", "CG-SUPABASE-RLS-DISABLED", "CG-STORAGE-BUCKET-PUBLIC",
        "CG-IAC-PUBLIC-BUCKET", "CG-IAC-WILDCARD-IAM", "CG-IAC-OPEN-INGRESS",
        "CG-IAC-HARDCODED-SECRET",
    },
    "client_secret_boundary": "CG-CLIENT-SECRET-EXPOSED",
    "cross_origin_policy": "CG-CORS-CREDENTIALED-WILDCARD",
}

_BY_ID = {capability.id: capability for capability in CAPABILITIES}


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
            _evaluate(capability.id, findings, coverage, protected_set,
                      policy, risk_deltas, changed_files)
        )
    return results


def _capability_files(capability_id: str, changed_files: tuple[str, ...]) -> tuple[str, ...]:
    """Changed files within *this* capability's own declared scope.

    Coverage failures on files outside a capability's ``covers`` globs (a
    ``.go`` file, say) must never taint an unrelated Python capability, so
    every evidence check below is scoped through this helper rather than the
    whole coverage tuple.
    """
    covers = _BY_ID[capability_id].covers
    return tuple(
        file for file in changed_files
        if any(fnmatch(file, pattern) for pattern in covers)
    )


def _coverage_summary(
    relevant_files: tuple[str, ...], coverage: tuple[FileCoverage, ...]
) -> tuple[tuple[str, ...], list[FileCoverage], list[FileCoverage]]:
    """Split a capability's own relevant files into missing/failed/analyzed evidence.

    ``missing`` is a relevant file with *no* coverage record at all -- nobody
    looked, which is exactly as uninformative as a recorded failure.
    """
    by_path = {item.path: item for item in coverage}
    missing = tuple(file for file in relevant_files if file not in by_path)
    covering = [by_path[file] for file in relevant_files if file in by_path]
    failed = [item for item in covering if item.status == STATUS_FAILED]
    analyzed = [item for item in covering if item.status == STATUS_ANALYZED]
    return missing, failed, analyzed


def _evaluate(
    capability_id: str,
    findings: list[Finding],
    coverage: tuple[FileCoverage, ...],
    protected_set: ProtectedSet,
    policy: Policy,
    risk_deltas: list,
    changed_files: tuple[str, ...],
) -> CheckResult:
    if capability_id == "source_analysis_support":
        relevant_files = _capability_files(capability_id, changed_files)
        unverified = unverified_source_files(relevant_files)
        if unverified:
            return CheckResult(
                capability_id, NOT_SUPPORTED,
                f"no analyzer yet for {', '.join(sorted(unverified)[:3])}",
                len(unverified),
            )
        verified_files = tuple(file for file in relevant_files if file not in unverified)
        missing, failed, analyzed = _coverage_summary(verified_files, coverage)
        if failed:
            return CheckResult(capability_id, UNKNOWN, failed[0].reason, len(failed))
        if missing:
            return CheckResult(
                capability_id, UNKNOWN,
                f"`{missing[0]}` changed but has no analysis record", len(missing),
            )
        if not analyzed:
            return CheckResult(
                capability_id, UNKNOWN,
                "no changed file in this capability's scope was analyzed",
            )
        return CheckResult(capability_id, PASS, evidence_count=len(analyzed))

    if capability_id == "declared_login_rules":
        if policy.problems:
            return CheckResult(capability_id, UNKNOWN, policy.problems[0].message,
                               len(policy.problems))
        if not policy.exists and protected_set.entities:
            return CheckResult(
                capability_id, UNKNOWN,
                "no security policy is declared, so there is nothing to check against",
            )
        if not protected_set.entities:
            # No entities to test the declared rules against -- the same
            # zero-evidence shape reachable_data_paths guards against below.
            return CheckResult(
                capability_id, UNKNOWN,
                "CyberGraph found no routes to check the declared login rules against",
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
    rules = {rule} if isinstance(rule, str) else set(rule)

    relevant_files = _capability_files(capability_id, changed_files)
    missing, failed, analyzed = _coverage_summary(relevant_files, coverage)
    if failed:
        return CheckResult(capability_id, UNKNOWN, failed[0].reason, len(failed))
    if missing:
        return CheckResult(
            capability_id, UNKNOWN,
            f"`{missing[0]}` changed but has no analysis record", len(missing),
        )
    confirmed = [f for f in findings if f.rule_id in rules]
    unverified = [f for f in findings if f.rule_id in {f"{r}-UNVERIFIED" for r in rules}]
    if confirmed:
        return CheckResult(capability_id, FAIL, confirmed[0].message, len(confirmed))
    if unverified:
        return CheckResult(capability_id, UNKNOWN, unverified[0].message, len(unverified))
    if not analyzed:
        return CheckResult(
            capability_id, UNKNOWN,
            "no changed file in this capability's scope was analyzed",
        )
    return CheckResult(capability_id, PASS, evidence_count=len(analyzed))

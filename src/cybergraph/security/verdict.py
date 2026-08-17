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
    status: str = ""
    evidence: str = ""
    assurance: str = ""
    impact: str = ""
    reason_class: str = ""


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
    gate: str = ""
    primary_reason: str = ""


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
    """Machine-readable form. Identical for the CLI and the MCP tool.

    Schema v2: adds ``schema_version``, ``decision`` (alias of ``state``),
    ``gate``, and ``primary_reason`` at the top level, and epistemic fields
    (``status``, ``evidence``, ``assurance``, ``impact``, ``reason_class``)
    on each reason. All v1 keys are kept unchanged so existing consumers
    don't break (spec open-Q4 compatibility window).
    """
    return {
        "schema_version": 2,
        "state": verdict.state,
        "decision": verdict.state,
        "gate": verdict.gate,
        "primary_reason": verdict.primary_reason,
        "reasons": [
            {
                "headline": r.headline,
                "file": r.file_path,
                "line": r.line,
                "rule": r.rule_id,
                "kind": r.kind,
                "status": r.status,
                "evidence": r.evidence,
                "assurance": r.assurance,
                "impact": r.impact,
                "reason_class": r.reason_class,
            }
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

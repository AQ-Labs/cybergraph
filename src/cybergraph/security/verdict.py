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

from cybergraph.graph import UNVERIFIED_SUFFIX, Finding, GraphStore
from cybergraph.security.assurance import (
    ASSURANCE_BENCHMARKED,
    EVIDENCE_NONE,
    EVIDENCE_PARTIAL,
    EVIDENCE_STRONG,
    EVIDENCE_WEAK,
    REASON_CONFIRMED_REGRESSION,
    REASON_UNRESOLVED,
    REASON_UNSUPPORTED,
    STATUS_CONFIRMED,
    STATUS_UNRESOLVED,
    STATUS_UNSUPPORTED,
    assurance_for,
    has_epistemic_upgrade,
    phrase_for,
)
from cybergraph.security.capability import (
    FAIL,
    NOT_SUPPORTED,
    PASS,
    UNKNOWN,
    CheckResult,
    label_for,
    triggers_review,
    unverified_source_files,
)
from cybergraph.security.checks import backing_finding, capability_files, escalated_risk_deltas
from cybergraph.security.policy import PolicyChange, ProtectedSet

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


# --- Epistemics: map a `CheckResult` the engine already produced onto the
# vocabulary in `cybergraph.security.assurance`. No new analysis: every input
# below (a `Finding`, a `RiskDelta`, the changed files, the declared
# `ProtectedSet`) is a signal `evaluate_capabilities` already computed.

_STATUS_BY_CHECK_STATUS = {
    FAIL: STATUS_CONFIRMED,
    UNKNOWN: STATUS_UNRESOLVED,
    NOT_SUPPORTED: STATUS_UNSUPPORTED,
}

_REASON_CLASS_BY_STATUS = {
    STATUS_CONFIRMED: REASON_CONFIRMED_REGRESSION,
    STATUS_UNRESOLVED: REASON_UNRESOLVED,
    STATUS_UNSUPPORTED: REASON_UNSUPPORTED,
}

# Extension -> language, exactly the cells the brief names. Anything else
# (`.jsx`, `.tsx`, an unrecognised extension, no backing finding at all)
# stays `None` and lands on `assurance_for`'s own beta fallback -- today's
# matrix already treats every non-Python injection language as beta, so no
# language here is under- or over-claimed by staying unmapped.
_LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".go": "go",
    ".java": "java",
    ".cs": "csharp",
}

_VALID_IMPACTS = ("critical", "high", "medium", "low")
_IMPACT_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0, "": -1}
_REASON_CLASS_RANK = {
    REASON_CONFIRMED_REGRESSION: 2,
    REASON_UNRESOLVED: 1,
    REASON_UNSUPPORTED: 0,
}


def _language_for(file_path: str) -> str | None:
    return _LANGUAGE_BY_EXTENSION.get(Path(file_path).suffix.lower())


def _evidence_for(finding: Finding | None) -> str:
    if finding is None:
        return EVIDENCE_NONE
    if finding.rule_id.endswith(UNVERIFIED_SUFFIX):
        return EVIDENCE_PARTIAL
    return EVIDENCE_STRONG if finding.evidence else EVIDENCE_WEAK


def _normalize_impact(value: str) -> str:
    lowered = (value or "").strip().lower()
    return lowered if lowered in _VALID_IMPACTS else "medium"


def _impact_for(check: CheckResult, finding: Finding | None, risk_deltas: list) -> str:
    if finding is not None:
        return _normalize_impact(finding.severity)
    if check.capability_id == "reachable_data_paths" and check.status == FAIL:
        escalated = escalated_risk_deltas(risk_deltas)
        if escalated:
            return _normalize_impact(escalated[0].risk_label)
    if check.capability_id == "declared_login_rules" and check.status == FAIL:
        # A declared login rule with nothing guarding it is broken access
        # control by definition -- there is no lesser-severity reading of it.
        return "critical"
    if check.status in (UNKNOWN, NOT_SUPPORTED):
        # Impact-if-true, not a certainty claim: an unresolved or unsupported
        # change could hide anything up to the worst case, so it is never
        # allowed to rank milder than a confirmed regression of known impact.
        return "critical"
    return ""


def _protected_boundary(
    check: CheckResult,
    finding: Finding | None,
    changed_files: tuple[str, ...],
    protected_set: ProtectedSet,
) -> bool:
    """Whether the file behind this reason is one the declared policy protects."""
    entity_files = {e.file_path for e in protected_set.entities.values() if e.file_path}
    if not entity_files:
        return False
    if check.capability_id == "declared_login_rules" and check.status == FAIL:
        return True
    if finding is not None:
        return finding.file_path in entity_files
    if check.status == NOT_SUPPORTED:
        files = unverified_source_files(capability_files(check.capability_id, changed_files))
        if not files:
            files = capability_files(check.capability_id, changed_files)
        return any(file in entity_files for file in files)
    return False


def _reason_for_check(
    check: CheckResult,
    findings: list[Finding],
    changed_files: tuple[str, ...],
    protected_set: ProtectedSet,
    risk_deltas: list,
) -> tuple[Reason | None, bool]:
    """Build the reason (plus its protected-boundary flag) for one check result.

    Returns ``(None, False)`` for PASS/NOT_APPLICABLE, the two statuses that
    already produce no reason at all in ``decide``'s check loop.
    """
    status = _STATUS_BY_CHECK_STATUS.get(check.status)
    if status is None:
        return None, False

    label = label_for(check.capability_id)
    if check.status == FAIL:
        headline, kind = f"{label}: {check.detail}", "check_failed"
    elif check.status == UNKNOWN:
        detail = f" {check.detail}" if check.detail else ""
        headline = f"CyberGraph could not check {label.lower()}.{detail}"
        kind = "check_unknown"
    else:
        headline = (
            f"This change touches things CyberGraph cannot verify yet ({label.lower()})."
        )
        kind = "check_unsupported"

    finding = backing_finding(check.capability_id, findings)
    language = _language_for(finding.file_path) if finding is not None else None
    # assurance_for is case-sensitive and fails closed -- lowercase before calling
    # it even though our own language table already only yields lowercase names.
    assurance = assurance_for(check.capability_id, (language or "").lower() or None, None)
    reason = Reason(
        headline=headline,
        rule_id=check.capability_id,
        kind=kind,
        status=status,
        evidence=_evidence_for(finding),
        assurance=assurance,
        impact=_impact_for(check, finding, risk_deltas),
        reason_class=_REASON_CLASS_BY_STATUS[status],
    )
    return reason, _protected_boundary(check, finding, changed_files, protected_set)


def _primary_reason(reasons: list[Reason], protected_flags: list[bool]) -> str:
    """The reason maximizing ``(impact_rank, protected_boundary, reason_severity)``.

    Not a fixed enum-order pick (design §4): a critical unsupported change on a
    protected boundary can outrank a low-impact confirmed regression.
    """
    candidates = [
        (reason, protected)
        for reason, protected in zip(reasons, protected_flags, strict=True)
        if reason.reason_class
    ]
    if not candidates:
        return ""
    best_reason, _ = max(
        candidates,
        key=lambda pair: (
            _IMPACT_RANK.get(pair[0].impact, -1),
            pair[1],
            _REASON_CLASS_RANK.get(pair[0].reason_class, -1),
        ),
    )
    return best_reason.reason_class


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
    findings: list[Finding] = (),
    protected_set: ProtectedSet = ProtectedSet(),
    changed_files: tuple[str, ...] = (),
    risk_deltas: list = (),
) -> Verdict:
    """Combine capability results and policy changes into one decision.

    ``findings``/``protected_set``/``changed_files``/``risk_deltas`` are the
    same signals ``evaluate_capabilities`` already consumed to produce
    ``checks`` -- passed again here only so each reason's epistemics
    (``status``/``evidence``/``assurance``/``impact``/``reason_class``) and
    ``primary_reason`` can be derived from them. All default to empty, so
    existing callers keep working; without them every check-based reason
    simply carries the least it can honestly claim (``evidence=none``).
    """
    reasons: list[Reason] = []
    protected_flags: list[bool] = []

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
        protected_flags.append(False)

    for check in checks:
        reason, protected = _reason_for_check(
            check, findings, changed_files, protected_set, risk_deltas
        )
        if reason is None:
            continue
        reasons.append(reason)
        protected_flags.append(protected)

    state = STATE_REVIEW if (reasons or triggers_review(checks)) else STATE_ACCEPT
    not_evaluated = tuple(
        label_for(check.capability_id) for check in checks if check.status == NOT_SUPPORTED
    )
    return Verdict(
        state, tuple(reasons), tuple(checks), not_evaluated, provenance,
        primary_reason=_primary_reason(reasons, protected_flags),
    )


_THIN_STATUSES = (STATUS_UNRESOLVED, STATUS_UNSUPPORTED)


def _where(reason: Reason) -> str:
    return f" ({reason.file_path}:{reason.line})" if reason.file_path else ""


def _guarded(text: str, status: str) -> str:
    """Assert Law 1 holds before a reason line is ever handed back to a caller.

    ``has_epistemic_upgrade`` is always False for ``STATUS_CONFIRMED`` (that
    language is warranted there) -- this only ever fires for a non-confirmed
    reason, and only when a forbidden verb has slipped past ``phrase_for``.
    A regression here is a bug in this module, not bad input, so it asserts
    rather than degrading the text.
    """
    assert not has_epistemic_upgrade(text, status), (
        f"Law 1 violation: epistemic upgrade in a non-confirmed reason line: {text!r}"
    )
    return text


def _detail_for(reason: Reason, checks: tuple[CheckResult, ...]) -> str:
    """The reason string behind an unresolved/unsupported reason.

    Always ``CheckResult.detail`` when one exists -- never the bare
    ``UNKNOWN``/``NOT_SUPPORTED`` status token -- falling back to the
    reason's own headline only when no matching check is found.
    """
    for check in checks:
        if check.capability_id == reason.rule_id and check.detail:
            return check.detail
    return reason.headline


def _claim_text(reason: Reason, checks: tuple[CheckResult, ...]) -> str:
    """`<Phrase>: <what happened>` -- the verb is always ``assurance.phrase_for``'s,
    never hand-written, so it can never claim more than ``status``/``evidence``/
    ``assurance`` warrant (Laws 1 & 3)."""
    phrase = phrase_for(reason.status, reason.evidence, reason.assurance)
    if reason.status == STATUS_CONFIRMED:
        body = f"{reason.headline}{_where(reason)}"
    else:
        body = f"{label_for(reason.rule_id)}: {_detail_for(reason, checks)}{_where(reason)}"
    return _guarded(f"{phrase.capitalize()}: {body}", reason.status)


def _select_primary(confirmed: list[Reason], primary_reason: str) -> Reason:
    """The reason ``decide`` already ranked highest, re-found among the confirmed
    ones by its ``reason_class`` (falling back to impact alone if none match)."""
    pool = [r for r in confirmed if r.reason_class == primary_reason] or confirmed
    return max(pool, key=lambda r: _IMPACT_RANK.get(r.impact, -1))


def _trust_gap(reason: Reason) -> str:
    """What keeps a lone confirmed reason short of full ``confirmed`` trust --
    used only when no other reason names a sharper gap."""
    if reason.assurance != ASSURANCE_BENCHMARKED:
        return "CyberGraph has not benchmarked this analysis for this language yet."
    if reason.evidence != EVIDENCE_STRONG:
        return "The evidence trail behind this finding is incomplete."
    return ""


def _top_gap(
    epistemic: list[Reason], primary: Reason, checks: tuple[CheckResult, ...]
) -> str:
    """The single most load-bearing evidence gap alongside the primary reason:
    the highest-impact unresolved/unsupported reason other than the primary one,
    or -- when there is none -- what keeps the primary reason itself short of
    full confirmation."""
    others = [r for r in epistemic if r is not primary and r.status in _THIN_STATUSES]
    if others:
        top = max(others, key=lambda r: _IMPACT_RANK.get(r.impact, -1))
        return _claim_text(top, checks)
    return _trust_gap(primary)


def _verbose_block(verdict: Verdict) -> list[str]:
    """The full epistemic block behind ``[Why?]`` (Law 5: drill-down, never hidden).

    Every field a reason carries, plus the confirmed/not-established evidence
    split -- passed checks and the capabilities this change touched but
    CyberGraph could not evaluate.
    """
    lines = ["", "[Why?]", f"  Decision: {verdict.state.upper()}"]
    if verdict.primary_reason:
        lines.append(f"  Primary reason: {verdict.primary_reason}")
    for reason in verdict.reasons:
        lines.append(
            f"  - Status: {reason.status or 'n/a'}  Evidence: {reason.evidence or 'n/a'}  "
            f"Assurance: {reason.assurance or 'n/a'}  Impact: {reason.impact or 'n/a'}"
        )
        lines.append(f"      {reason.headline}{_where(reason)}")

    passed = [check for check in verdict.checks if check.status == PASS]
    if passed:
        lines.extend(["", "Confirmed (checks that ran and found nothing):"])
        lines.extend(f"  ok  {label_for(check.capability_id)}" for check in passed)

    if verdict.not_evaluated:
        lines.extend(["", "Not established (CyberGraph could not evaluate these):"])
        lines.extend(f"  --  {label}" for label in verdict.not_evaluated)

    return lines


def format_verdict(verdict: Verdict, *, verbose: bool = False) -> str:
    """Render for a terminal reader. Never claims more than was checked.

    Collapsed by default (spec §3): a decision line, then a single warranted
    reason (``primary_reason``, worded via ``assurance.phrase_for`` so the verb
    is always bounded by trust) plus the single most load-bearing evidence gap,
    then a ``[Why?]`` affordance. A thin result -- no confirmed regression, only
    unresolved/unsupported checks -- is a first-class outcome: every gap is
    named with its own reason string, never a bare status token.

    Pass ``verbose=True`` for the full epistemic block (status/evidence/
    assurance/impact plus the confirmed/not-established evidence split).
    Detail collapses; a limitation is never hidden even in the default view
    (Law 5) -- a declared-policy regression is always listed, and the default
    view always names *some* warranted reason when one exists.
    """
    lines: list[str] = []
    if verdict.state == STATE_ACCEPT:
        lines.append("No issues found in the checks CyberGraph ran.")
    else:
        epistemic = [r for r in verdict.reasons if r.reason_class]
        policy_reasons = [r for r in verdict.reasons if not r.reason_class]
        confirmed = [r for r in epistemic if r.status == STATUS_CONFIRMED]
        thin = [r for r in epistemic if r.status in _THIN_STATUSES]

        count = len(verdict.reasons)
        noun = "thing needs" if count == 1 else "things need"
        lines.append(f"{count} {noun} your attention before shipping.")
        lines.append("")

        if confirmed:
            primary = _select_primary(confirmed, verdict.primary_reason)
            lines.append(_claim_text(primary, verdict.checks))
            gap = _top_gap(epistemic, primary, verdict.checks)
            if gap:
                lines.append(gap)
        elif thin:
            plural = "thing" if len(thin) == 1 else "things"
            lines.append(
                f"Verification incomplete: no confirmed regressions, but {len(thin)} "
                f"{plural} could not be fully evaluated:"
            )
            lines.extend(f"  - {_claim_text(reason, verdict.checks)}" for reason in thin)

        for reason in policy_reasons:
            lines.append(f"  - {reason.headline}{_where(reason)}")

        lines.append("")
        lines.append(
            "[Why?] Pass verbose=True (or --verbose) for the full evidence, "
            "coverage, and impact detail."
        )

    if verbose:
        lines.extend(_verbose_block(verdict))

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
            f"SELECT rule_id, severity, message, file_path, line_start, cwe, evidence "
            f"FROM findings WHERE file_path IN ({placeholders})",
            changed_files,
        ).fetchall()
    finally:
        store.close()
    return [
        Finding(rule_id=r["rule_id"], severity=r["severity"], message=r["message"],
                file_path=r["file_path"], line_start=r["line_start"] or 0,
                cwe=r["cwe"] or "", evidence=r["evidence"] or "")
        for r in rows
    ]

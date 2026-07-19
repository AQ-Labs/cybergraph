"""Graph-grounded LLM false-positive triage (opt-in, default-off).

Static analyzers over-report (the dominant developer pain). This module lets an
LLM confirm or refute each finding already in the graph, grounded in a minimal
graph slice: the source around the finding, any reachable attack path touching
its file, and the finding's own evidence. A finding is **suppressed only when the
model returns a false-positive verdict WITH cited evidence that actually appears
in the slice**; otherwise it is kept. This is the recall guardrail: the LLM can
cut noise but can never silently drop a finding on an ungrounded guess.

Nothing here runs unless a caller explicitly passes a client. The deterministic
analyzers, attack paths, and grounded answers are untouched on the default path.

Research basis: graph-guided slicing (LLMxCPG, USENIX'25) + LLM false-positive
filtering with recall preservation (LLM4PFA; "Sifting the Noise") + ground the
model in program facts, not the model alone (AdaTaint principle).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from cybergraph.graph import Finding, GraphStore
from cybergraph.security.attack_paths import find_attack_paths

VERDICT_TRUE_POSITIVE = "true_positive"
VERDICT_FALSE_POSITIVE = "false_positive"
VERDICT_UNCERTAIN = "uncertain"

_SYSTEM = (
    "You are a security triage assistant. Decide whether a static-analysis "
    "finding is a TRUE positive (a real, reachable vulnerability) or a FALSE "
    "positive, using ONLY the provided CONTEXT. Respond with STRICT JSON: "
    '{"verdict": "true_positive|false_positive|uncertain", "reason": str, '
    '"evidence": str}. The "evidence" MUST be a short verbatim quote copied from '
    "the CONTEXT that justifies a false_positive verdict (e.g. a sanitizer call "
    "or a constant argument). If you are not sure, return \"uncertain\". Never "
    "invent code that is not in the CONTEXT."
)


@dataclass(frozen=True)
class TriageResult:
    finding: Finding
    verdict: str
    reason: str
    cited_evidence: str
    suppressed: bool


def load_findings(repo_root: Path) -> list[Finding]:
    """Read the findings already stored in the repo's graph."""
    store = GraphStore.open_for_repo(Path(repo_root).resolve())
    try:
        rows = store.conn.execute(
            "SELECT rule_id, severity, message, file_path, line_start, line_end, "
            "cwe, owasp, tool, evidence FROM findings ORDER BY file_path, line_start"
        ).fetchall()
    finally:
        store.close()
    return [
        Finding(
            rule_id=r["rule_id"],
            severity=r["severity"],
            message=r["message"],
            file_path=r["file_path"],
            line_start=r["line_start"],
            line_end=r["line_end"],
            cwe=r["cwe"],
            owasp=r["owasp"],
            tool=r["tool"],
            evidence=r["evidence"],
        )
        for r in rows
    ]


def build_finding_slice(
    repo_root: Path,
    finding: Finding,
    paths: list | None = None,
    context_lines: int = 25,
    max_chars: int = 4000,
) -> str:
    """Assemble the minimal graph-grounded context for one finding."""
    repo_root = Path(repo_root).resolve()
    parts: list[str] = [
        f"# FINDING: {finding.rule_id} ({finding.severity}) at "
        f"{finding.file_path}:{finding.line_start}",
        f"# {finding.message}",
    ]
    if finding.evidence:
        parts.append(f"# evidence line: {finding.evidence}")

    # Source window around the finding.
    src = repo_root / finding.file_path
    if src.exists():
        lines = src.read_text(encoding="utf-8", errors="ignore").splitlines()
        lo = max(0, finding.line_start - 1 - context_lines)
        hi = min(len(lines), finding.line_start + context_lines)
        window = "\n".join(lines[lo:hi])
        parts.append(f"# CONTEXT source {finding.file_path} (lines {lo + 1}-{hi}):\n{window}")

    # Reachable attack paths that touch this file (the graph's reachability signal).
    if paths is None:
        paths = find_attack_paths(repo_root)
    related = [
        p for p in paths
        if any(finding.file_path in node for node in p.nodes)
    ]
    if related:
        path_lines = [
            f"- {p.entrypoint} -> {p.sink} (confidence={p.confidence}"
            f"{', sanitizer on path' if p.sanitized else ''})"
            for p in related[:10]
        ]
        parts.append("# Reachable attack paths through this file:\n" + "\n".join(path_lines))
    else:
        parts.append("# No verified entrypoint->sink path reaches this finding's function.")

    return "\n\n".join(parts)[:max_chars]


def _parse_verdict(raw: str) -> tuple[str, str, str]:
    """Parse the model's JSON; default to 'uncertain' on any trouble (abstain)."""
    match = re.search(r"\{.*\}", raw or "", re.DOTALL)
    if not match:
        return VERDICT_UNCERTAIN, "unparseable response", ""
    try:
        data = json.loads(match.group(0))
    except (TypeError, ValueError):
        return VERDICT_UNCERTAIN, "unparseable response", ""
    verdict = str(data.get("verdict", VERDICT_UNCERTAIN)).strip().lower()
    if verdict not in {VERDICT_TRUE_POSITIVE, VERDICT_FALSE_POSITIVE, VERDICT_UNCERTAIN}:
        verdict = VERDICT_UNCERTAIN
    return verdict, str(data.get("reason", "")), str(data.get("evidence", ""))


def should_suppress(verdict: str, cited_evidence: str, slice_text: str) -> bool:
    """Recall guardrail: suppress ONLY on a false-positive verdict whose cited
    evidence is non-empty AND actually present in the slice (faithfulness).
    Uncertain, true-positive, or ungrounded false-positive => keep the finding.
    """
    if verdict != VERDICT_FALSE_POSITIVE:
        return False
    quote = cited_evidence.strip()
    if len(quote) < 4:
        return False
    return quote.lower() in slice_text.lower()


def triage_findings(
    repo_root: Path,
    findings: list[Finding] | None = None,
    client=None,
) -> list[TriageResult]:
    """Triage findings. With ``client is None`` (no LLM), every finding is kept
    (abstain) — the safe default. With a client, each finding is confirmed/refuted
    from its graph slice and suppressed only when the guardrail allows."""
    repo_root = Path(repo_root).resolve()
    if findings is None:
        findings = load_findings(repo_root)
    if client is None:
        return [
            TriageResult(f, VERDICT_UNCERTAIN, "no LLM configured; kept", "", False)
            for f in findings
        ]
    paths = find_attack_paths(repo_root)
    results: list[TriageResult] = []
    for finding in findings:
        slice_text = build_finding_slice(repo_root, finding, paths)
        user = f"CONTEXT:\n{slice_text}\n\nReturn STRICT JSON {{verdict, reason, evidence}}."
        try:
            raw = client.complete(_SYSTEM, user)
        except Exception as exc:  # never let one call abort triage; abstain instead
            results.append(
                TriageResult(finding, VERDICT_UNCERTAIN, f"triage error: {exc}", "", False)
            )
            continue
        verdict, reason, evidence = _parse_verdict(raw)
        suppressed = should_suppress(verdict, evidence, slice_text)
        results.append(TriageResult(finding, verdict, reason, evidence, suppressed))
    return results


def format_triage(results: list[TriageResult]) -> str:
    kept = [r for r in results if not r.suppressed]
    suppressed = [r for r in results if r.suppressed]
    lines = [
        f"Triage: {len(kept)} kept, {len(suppressed)} suppressed as false positives "
        f"(of {len(results)} findings)."
    ]
    for r in suppressed:
        lines.append(
            f"  - SUPPRESSED {r.finding.rule_id} {r.finding.file_path}:{r.finding.line_start}"
            f" — {r.reason} [evidence: {r.cited_evidence[:60]}]"
        )
    for r in kept:
        tag = "kept" if r.verdict != VERDICT_TRUE_POSITIVE else "CONFIRMED"
        lines.append(
            f"  - {tag} {r.finding.rule_id} {r.finding.file_path}:{r.finding.line_start}"
        )
    return "\n".join(lines)

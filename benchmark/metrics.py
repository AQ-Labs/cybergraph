"""Scoring for the CyberGraph reachability benchmark.

Ground truth is expressed per case as a set of expected entrypoint->sink attack
paths (for vulnerable cases) or none (for secure cases). We score detection of
those paths: a true positive is an expected path that CyberGraph reports, a
false negative is an expected path it misses, and a false positive is a
reported path with no matching expectation (most meaningful on secure cases,
where any reported path is a false alarm).

These are pure functions over plain dicts/tuples so they are unit-testable
without building a graph.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CaseScore:
    name: str
    tp: int
    fp: int
    fn: int

    @property
    def matched(self) -> bool:
        return self.fp == 0 and self.fn == 0


def _path_matches(expected: dict, detected_nodes: tuple[str, ...], detected_sink: str) -> bool:
    sink_ok = expected["sink"].lower() in detected_sink.lower()
    entry = expected.get("entrypoint")
    if not entry:
        return sink_ok
    entry_ok = any(entry.lower() in node.lower() for node in detected_nodes)
    return sink_ok and entry_ok


def score_case(
    name: str,
    expected_paths: list[dict],
    detected: list[tuple[tuple[str, ...], str]],
) -> CaseScore:
    """Score one case.

    ``detected`` is a list of (path_nodes, sink) tuples from find_attack_paths.
    """
    tp = 0
    matched_detected: set[int] = set()
    for expected in expected_paths:
        hit = next(
            (
                index
                for index, (nodes, sink) in enumerate(detected)
                if index not in matched_detected and _path_matches(expected, nodes, sink)
            ),
            None,
        )
        if hit is not None:
            tp += 1
            matched_detected.add(hit)
    fn = len(expected_paths) - tp
    fp = len(detected) - len(matched_detected)
    return CaseScore(name=name, tp=tp, fp=fp, fn=fn)


@dataclass(frozen=True)
class GuardrailResult:
    """Outcome of the recall guardrail (see ``recall_guardrail``)."""

    passed: bool
    recall: float
    secure_false_positives: int
    missed_vulnerable: tuple[str, ...]
    violations: tuple[str, ...]


def recall_guardrail(
    scores: list[CaseScore],
    secure_cases: set[str],
    min_recall: float = 1.0,
) -> GuardrailResult:
    """Safety check that any noise-reduction step must never regress.

    A pass requires (a) recall over all cases >= ``min_recall`` (no real
    vulnerability silently dropped) and (b) zero false positives on the secure
    baselines. Phase-1 false-positive triage runs against this guardrail so it
    can suppress noise but never a confirmed true positive.
    """
    agg = aggregate(scores)
    recall = agg["recall"]
    secure_fp = sum(s.fp for s in scores if s.name in secure_cases)
    missed = tuple(s.name for s in scores if s.name not in secure_cases and s.fn > 0)
    violations: list[str] = []
    if recall < min_recall:
        violations.append(f"recall {recall} < required {min_recall}")
    if secure_fp > 0:
        violations.append(f"{secure_fp} false positive(s) on secure baselines")
    if missed:
        violations.append(f"missed vulnerable case(s): {', '.join(missed)}")
    return GuardrailResult(
        passed=not violations,
        recall=recall,
        secure_false_positives=secure_fp,
        missed_vulnerable=missed,
        violations=tuple(violations),
    )


def aggregate(scores: list[CaseScore]) -> dict[str, float]:
    tp = sum(s.tp for s in scores)
    fp = sum(s.fp for s in scores)
    fn = sum(s.fn for s in scores)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "cases": len(scores),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }

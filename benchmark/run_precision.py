"""Measure detector precision, recall and abstention against the labelled corpus.

A falling finding count proves nothing -- you reach zero by detecting nothing. All
four figures are reported so a precision gain bought with recall, or with mass
abstention, is visible.

``-UNVERIFIED`` findings are excluded from tp/fp: penalising an honest "I could
not tell" as a false positive pushes the detector toward guessing. They are
instead counted as abstentions, and abstaining on a *safe* case is gated,
because operationally it sends a clean change to a human.

Five metrics, and the last three are gated **per vulnerability class**:

===========================  =========  ====================================
metric                       threshold  scope
===========================  =========  ====================================
precision                    >= 0.90    gated cases
recall                       >= 0.95    gated cases, excluding ``known_gap``
safe-case false positives    <= 0.05    per class
safe-case abstentions        <= 0.15    per class, except ``command``
case mismatches              <= 0.00    per class, every gated case
===========================  =========  ====================================

The fifth exists because the first four cannot see an ``unknown``-labelled
case at all. An abstention-by-design case contributes nothing to tp/fp/fn --
correctly, since penalising an honest "I could not tell" as a false positive
pushes the detector toward guessing -- and the two safe-case rates select on
``label == "safe"``. So an ``unknown`` row fed **no gated metric**, and three
measured single-point mutations traded an abstention for a confirmed high, a
confirmed critical, and for ``safe``, with all 32 gate lines still reading
PASS. The last of those inverts the governing invariant of the whole system:
*uncertainty never becomes safety*. ``case_mismatch_rate`` gates each row's
``clean`` flag -- "this case came out exactly as its expectation says",
whatever its label -- so every case in the corpus now reaches a gate line.

Gating abstention alone is satisfiable by over-reporting: during Task 4 the
aggregate abstention rate fell from 17.6% to 12.9% purely because 23 safe sites
moved from UNKNOWN to *false positive*. The number improved while the tool got
worse, so both are gated, and both per class. Abstention is also
workload-dependent rather than a property of the detector -- 3.4% on a SQL-heavy
repository against 20.0% on a subprocess-heavy one -- so a single aggregate is
gameable by corpus composition. ``command`` is exempt from the abstention gate
and carries a stated limitation instead: *CyberGraph cannot verify a shell-out
to a binary that is not named literally.* Its false-positive rate stays gated.

**The thresholds have no arithmetic resolution at this corpus size.** A class
with three safe cases can only score 0, 0.33, 0.67 or 1.00, so ``<= 0.05`` is a
zero-tolerance gate, not a five-percent one. Every rate is therefore printed
with its ``n`` beside it, and a rate over fewer than 20 cases is marked
``zero-tolerance``.

Usage:
    python benchmark/run_precision.py
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cybergraph.analysis.python import analyze_python_file  # noqa: E402
from cybergraph.build import build_graph  # noqa: E402
from cybergraph.security.attack_paths import find_attack_paths  # noqa: E402

CASES = Path(__file__).parent / "precision" / "cases"
RESULTS = Path(__file__).parent / "precision" / "results.json"

MIN_PRECISION = 0.90
MIN_RECALL = 0.95
MAX_SAFE_FALSE_POSITIVE_RATE = 0.05
MAX_SAFE_ABSTENTION_RATE = 0.15
# A case either came out as its expectation says or it did not; there is no
# tolerable fraction of "the corpus disagrees with the detector".
MAX_CASE_MISMATCH_RATE = 0.0

# Measured and printed, but not gated. See the module docstring.
ABSTENTION_UNGATED_CLASSES = frozenset({"command"})

# Below this many observations a rate cannot express its own threshold, so the
# gate is really "zero", and saying otherwise overclaims.
RESOLUTION_FLOOR = 20


def _detect_findings(case: Path) -> tuple[set[tuple[str, int, str]], int]:
    """Confirmed findings and the abstention count for one case."""
    _, _, findings = analyze_python_file(case / "app.py", case)
    confirmed: set[tuple[str, int, str]] = set()
    abstentions = 0
    for finding in findings:
        if finding.rule_id.endswith("-UNVERIFIED"):
            abstentions += 1
            continue
        confirmed.add((finding.file_path, finding.line_start, finding.rule_id))
    return confirmed, abstentions


_PathProperties = tuple[str, bool, str]


def _properties_of(path) -> _PathProperties:  # noqa: ANN001 - AttackPath
    """The claims a reported path makes, all of which are scored.

    Reading only ``sink`` and ``sanitized`` left ``data_reachable`` and the
    risk label unmeasured by anything in the repository. Measured: mutating
    ``attack_paths._traverse`` to fall back to a synthetic taint source — i.e.
    marking *every* attack path in *every* repository as user-data-reachable
    and escalating it from ``high/72`` to ``critical/92`` — passed the gate,
    the gate test and all 887 tests. ``data_reachable`` is an affirmative claim
    about attacker control that eleven reporting surfaces render as
    "user-controlled data reaches `<sink>`", so it is scored here beside the
    risk label it drives.
    """
    return (path.sink, bool(path.data_reachable), path.risk.label if path.risk else "none")


def _expected_path(entry: dict) -> _PathProperties:
    """One declared path from ``expected.json``. Every property is required."""
    return (entry["sink"], bool(entry["data_reachable"]), entry["risk"])


def _detect_paths(case: Path) -> tuple[set[_PathProperties], set[_PathProperties]]:
    """Unsanitized and sanitized entrypoint-to-sink paths for one case.

    Findings are intra-procedural, so a helper that receives user data as an
    ordinary parameter carries no taint of its own and legitimately yields zero
    findings while the entrypoint-to-sink path is perfectly correct. The
    interprocedural cases are therefore scored on paths.

    A path crossing a sanitiser is not a positive detection: ``find_attack_paths``
    reports reachability as inventory and records the barrier in ``sanitized``,
    which is the only way this surface has of saying "and something was done
    about it". It is still *scored*, though — through ``clean`` rather than
    through tp/fp/fn, because a sanitised path is inventory and counting it as
    a detection would make the safe interprocedural case a false positive by
    construction.
    """
    shutil.rmtree(case / ".cybergraph", ignore_errors=True)
    build_graph(case)
    paths = find_attack_paths(case)
    unsanitized = {_properties_of(path) for path in paths if not path.sanitized}
    sanitized = {_properties_of(path) for path in paths if path.sanitized}
    return unsanitized, sanitized


def _score_case(case: Path) -> dict:
    doc = json.loads((case / "expected.json").read_text(encoding="utf-8"))
    label = doc["label"]
    scoring = doc.get("scoring", "findings")

    sanitized: list[str] = []
    sanitized_expected: list[str] = []
    inventory_matches = True
    if scoring == "attack_paths":
        expected = {_expected_path(entry) for entry in doc.get("paths", [])}
        expected_sanitized = {_expected_path(entry) for entry in doc.get("sanitized_paths", [])}
        detected_paths, sanitized_paths = _detect_paths(case)
        detected: set = detected_paths
        sanitized = sorted(str(item) for item in sanitized_paths)
        sanitized_expected = sorted(str(item) for item in expected_sanitized)
        inventory_matches = sanitized_paths == expected_sanitized
        # An attack path is either reported or not; there is no `-UNVERIFIED`
        # equivalent on this surface, so abstention is not observable here.
        abstentions = 0
    else:
        expected = {
            (entry["file"], entry["line"], entry["rule"]) for entry in doc["findings"]
        }
        detected, abstentions = _detect_findings(case)

    if label == "unknown":
        # Excluded from tp/fp/fn entirely: the runner strips `-UNVERIFIED`
        # findings into the abstention count, so a naive comparison would score
        # an abstention-by-design case as a false negative against its own
        # expectation.
        case_tp = case_fp = case_fn = 0
        clean = abstentions == doc.get("abstentions", 0) and not detected
    else:
        case_tp = len(expected & detected)
        case_fp = len(detected - expected)
        case_fn = len(expected - detected)
        if label == "safe":
            clean = not detected and not abstentions
        else:
            clean = case_fp == 0 and case_fn == 0
    clean = clean and inventory_matches

    return {
        "name": case.name,
        "label": label,
        "vuln_class": doc["vuln_class"],
        "known_gap": bool(doc.get("known_gap", False)),
        "scoring": scoring,
        "tp": case_tp,
        "fp": case_fp,
        "fn": case_fn,
        "abstentions": abstentions,
        "expected": sorted(str(item) for item in expected),
        "detected": sorted(str(item) for item in detected),
        "sanitized_paths": sanitized,
        "sanitized_paths_expected": sanitized_expected,
        "clean": clean,
    }


def _rate(numerator: int, denominator: int, *, empty: float) -> float:
    return round(numerator / denominator, 3) if denominator else empty


def _metrics(rows: list[dict]) -> dict:
    """Precision/recall over gated rows, the two safe-case rates, and mismatches."""
    gated = [row for row in rows if not row["known_gap"]]
    tp = sum(row["tp"] for row in gated)
    fp = sum(row["fp"] for row in gated)
    fn = sum(row["fn"] for row in gated)

    safe = [row for row in rows if row["label"] == "safe"]
    safe_fp = [row for row in safe if row["detected"]]
    safe_abstained = [row for row in safe if row["abstentions"]]

    # Every gated row, whatever its label. This is the only metric an
    # `unknown`-labelled case reaches: tp/fp/fn are zero for it by design and
    # the two safe-case rates select on `label == "safe"`.
    mismatched = [row for row in gated if not row["clean"]]

    return {
        "cases": len(rows),
        "gated_cases": len(gated),
        "known_gap_cases": sorted(row["name"] for row in rows if row["known_gap"]),
        # A gap that started passing. Not a failure -- it is the improvement the
        # case exists to wait for -- but it must be visible, or the case sits
        # excluded from the gated figures forever while quietly succeeding.
        "recovered_known_gap_cases": sorted(
            row["name"] for row in rows if row["known_gap"] and row["clean"]
        ),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": _rate(tp, tp + fp, empty=1.0),
        "recall": _rate(tp, tp + fn, empty=1.0),
        "precision_n": tp + fp,
        "recall_n": tp + fn,
        "safe_cases": len(safe),
        "safe_false_positives": len(safe_fp),
        "safe_false_positive_cases": sorted(row["name"] for row in safe_fp),
        "safe_false_positive_rate": _rate(len(safe_fp), len(safe), empty=0.0),
        "safe_abstained": len(safe_abstained),
        "safe_abstained_cases": sorted(row["name"] for row in safe_abstained),
        "safe_abstention_rate": _rate(len(safe_abstained), len(safe), empty=0.0),
        "mismatched": len(mismatched),
        "mismatched_cases": sorted(row["name"] for row in mismatched),
        "case_mismatch_rate": _rate(len(mismatched), len(gated), empty=0.0),
    }


def _gate(name: str, value: float, threshold: float, *, minimum: bool, n: int,
          enforced: bool = True) -> dict:
    if not enforced or n == 0:
        passed = True
    else:
        passed = value >= threshold if minimum else value <= threshold
    return {
        "name": name,
        "value": value,
        "n": n,
        "threshold": threshold,
        "direction": "min" if minimum else "max",
        "enforced": enforced and n > 0,
        "zero_tolerance": 0 < n < RESOLUTION_FLOOR,
        "passed": passed,
    }


def _gates_for(scope: str, stats: dict, vuln_class: str | None) -> list[dict]:
    abstention_enforced = vuln_class not in ABSTENTION_UNGATED_CLASSES
    return [
        _gate(f"{scope}:precision", stats["precision"], MIN_PRECISION,
              minimum=True, n=stats["precision_n"]),
        _gate(f"{scope}:recall", stats["recall"], MIN_RECALL,
              minimum=True, n=stats["recall_n"]),
        _gate(f"{scope}:safe_false_positive_rate", stats["safe_false_positive_rate"],
              MAX_SAFE_FALSE_POSITIVE_RATE, minimum=False, n=stats["safe_cases"]),
        _gate(f"{scope}:safe_abstention_rate", stats["safe_abstention_rate"],
              MAX_SAFE_ABSTENTION_RATE, minimum=False, n=stats["safe_cases"],
              enforced=abstention_enforced),
        _gate(f"{scope}:case_mismatch_rate", stats["case_mismatch_rate"],
              MAX_CASE_MISMATCH_RATE, minimum=False, n=stats["gated_cases"]),
    ]


def _print_class_table(per_class: dict[str, dict]) -> None:
    header = (
        f"{'class':16} {'prec':>6} {'n':>4}  {'recall':>6} {'n':>4}  "
        f"{'safeFP':>6} {'n':>4}  {'abst':>6} {'n':>4}  {'mism':>6} {'n':>4}"
    )
    print(header)
    print("-" * len(header))
    for name, stats in sorted(per_class.items()):
        flag = " *" if name in ABSTENTION_UNGATED_CLASSES else ""
        print(
            f"{name:16} {stats['precision']:>6.2f} {stats['precision_n']:>4} "
            f" {stats['recall']:>6.2f} {stats['recall_n']:>4} "
            f" {stats['safe_false_positive_rate']:>6.2f} {stats['safe_cases']:>4} "
            f" {stats['safe_abstention_rate']:>6.2f} {stats['safe_cases']:>4} "
            f" {stats['case_mismatch_rate']:>6.2f} {stats['gated_cases']:>4}{flag}"
        )
    print("* abstention measured but not gated for this class.")


def main() -> int:
    rows = [
        _score_case(case)
        for case in sorted(path for path in CASES.iterdir() if path.is_dir())
    ]

    overall = _metrics(rows)
    classes = sorted({row["vuln_class"] for row in rows})
    per_class = {name: _metrics([r for r in rows if r["vuln_class"] == name]) for name in classes}

    gates = _gates_for("overall", overall, None)
    for name, stats in sorted(per_class.items()):
        gates.extend(_gates_for(name, stats, name))
    passed = all(gate["passed"] for gate in gates)

    summary = {
        "passed": passed,
        "thresholds": {
            "min_precision": MIN_PRECISION,
            "min_recall": MIN_RECALL,
            "max_safe_false_positive_rate": MAX_SAFE_FALSE_POSITIVE_RATE,
            "max_safe_abstention_rate": MAX_SAFE_ABSTENTION_RATE,
            "max_case_mismatch_rate": MAX_CASE_MISMATCH_RATE,
            "abstention_ungated_classes": sorted(ABSTENTION_UNGATED_CLASSES),
            "resolution_floor": RESOLUTION_FLOOR,
        },
        # Flat aliases kept because the gate test and the README quote them.
        "precision": overall["precision"],
        "recall": overall["recall"],
        "safe_false_positive_rate": overall["safe_false_positive_rate"],
        "safe_abstention_rate": overall["safe_abstention_rate"],
        "case_mismatch_rate": overall["case_mismatch_rate"],
        "overall": overall,
        "per_class": per_class,
        "gates": gates,
        "cases": rows,
    }
    RESULTS.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(
        f"cases={overall['cases']} gated={overall['gated_cases']} "
        f"precision={overall['precision']} (n={overall['precision_n']}) "
        f"recall={overall['recall']} (n={overall['recall_n']}) "
        f"safe_fp_rate={overall['safe_false_positive_rate']} "
        f"safe_abstention_rate={overall['safe_abstention_rate']} "
        f"(safe n={overall['safe_cases']}) "
        f"case_mismatch_rate={overall['case_mismatch_rate']} "
        f"(gated n={overall['gated_cases']})"
    )
    gaps = overall["known_gap_cases"]
    print(f"known gaps: {len(gaps)} ({', '.join(gaps) if gaps else 'none'})")
    recovered = overall["recovered_known_gap_cases"]
    if recovered:
        print(
            f"known gaps now PASSING: {', '.join(recovered)} "
            "-- drop `known_gap` from expected.json and let them into the gated recall"
        )
    print()
    _print_class_table(per_class)
    print()

    for gate in gates:
        if not gate["enforced"]:
            state = "not gated"
        else:
            state = "PASS" if gate["passed"] else "FAIL"
        comparator = ">=" if gate["direction"] == "min" else "<="
        note = "  [zero-tolerance at this n]" if gate["zero_tolerance"] else ""
        print(
            f"  {state:9} {gate['name']:44} {gate['value']:.2f} "
            f"{comparator} {gate['threshold']:.2f}  n={gate['n']}{note}"
        )

    mismatches = [row for row in rows if not row["clean"]]
    if mismatches:
        print()
        for row in mismatches:
            marker = "KNOWN GAP" if row["known_gap"] else "MISMATCH "
            print(
                f"  {marker} {row['name']} [{row['label']}/{row['vuln_class']}]: "
                f"tp={row['tp']} fp={row['fp']} fn={row['fn']} "
                f"abstentions={row['abstentions']}"
            )
            if row["sanitized_paths"] != row["sanitized_paths_expected"]:
                print(f"            sanitized inventory expected {row['sanitized_paths_expected']}")
                print(f"            sanitized inventory detected {row['sanitized_paths']}")

    print()
    print(f"Wrote {RESULTS}")
    print("GATE PASSED" if passed else "GATE FAILED")
    # A red gate must exit non-zero. The README documents this file as *the*
    # way to run the gate, so a CI step that shells out to it is green on red
    # for as long as the exit status ignores the verdict it just printed.
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

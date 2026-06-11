"""Run the CyberGraph reachability benchmark.

For every case under ``benchmark/cases/`` this builds the security graph,
compares detected entrypoint->sink attack paths against the case's ground-truth
``expected.json``, and records build time, database size, and graph counts. It
prints a per-case table plus aggregate precision/recall/F1 and writes
``benchmark/results.json``.

Usage:
    python benchmark/run_eval.py
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.security.attack_paths import find_attack_paths

from metrics import CaseScore, aggregate, score_case

CASES_DIR = Path(__file__).parent / "cases"
RESULTS_PATH = Path(__file__).parent / "results.json"


def _build_dir(repo: Path) -> Path:
    return repo / ".cybergraph"


def run_case(case_dir: Path) -> dict:
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))

    # Clean any previous build so timing/size are fresh.
    shutil.rmtree(_build_dir(case_dir), ignore_errors=True)

    start = time.perf_counter()
    counts = build_graph(case_dir)
    build_seconds = time.perf_counter() - start

    paths = find_attack_paths(case_dir)
    detected = [(p.nodes, p.sink) for p in paths]
    score = score_case(case_dir.name, expected.get("expected_paths", []), detected)

    db_path = _build_dir(case_dir) / "graph.db"
    db_bytes = db_path.stat().st_size if db_path.exists() else 0

    return {
        "name": case_dir.name,
        "language": expected.get("language", "?"),
        "vulnerable": expected.get("vulnerable", False),
        "tp": score.tp,
        "fp": score.fp,
        "fn": score.fn,
        "matched": score.matched,
        "findings": counts["findings"],
        "nodes": counts["nodes"],
        "edges": counts["edges"],
        "build_seconds": round(build_seconds, 4),
        "db_bytes": db_bytes,
        "detected_paths": [f"{' -> '.join(nodes)}" for nodes, _ in detected],
    }


def main() -> int:
    case_dirs = sorted(d for d in CASES_DIR.iterdir() if (d / "expected.json").exists())
    rows = [run_case(d) for d in case_dirs]
    scores = [CaseScore(r["name"], r["tp"], r["fp"], r["fn"]) for r in rows]
    summary = aggregate(scores)

    _print_table(rows)
    print()
    print(
        f"Aggregate over {summary['cases']} cases: "
        f"precision={summary['precision']} recall={summary['recall']} f1={summary['f1']} "
        f"(tp={summary['tp']} fp={summary['fp']} fn={summary['fn']})"
    )
    total_time = sum(r["build_seconds"] for r in rows)
    total_bytes = sum(r["db_bytes"] for r in rows)
    print(f"Performance: {total_time:.3f}s total build, {total_bytes/1024:.1f} KiB total graph db")

    RESULTS_PATH.write_text(
        json.dumps({"summary": summary, "cases": rows}, indent=2), encoding="utf-8"
    )
    print(f"\nWrote {RESULTS_PATH}")
    return 0


def _print_table(rows: list[dict]) -> None:
    header = f"{'case':28} {'lang':7} {'vuln':5} {'tp':>2} {'fp':>2} {'fn':>2} {'find':>4} {'build_s':>8}"
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r['name']:28} {r['language']:7} {str(r['vulnerable']):5} "
            f"{r['tp']:>2} {r['fp']:>2} {r['fn']:>2} {r['findings']:>4} {r['build_seconds']:>8.4f}"
        )


if __name__ == "__main__":
    raise SystemExit(main())

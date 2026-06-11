# CyberGraph Reachability Benchmark

A small, reproducible benchmark that measures how well CyberGraph detects
**entrypoint → sink reachability** across languages, plus build performance.

## Run it

```bash
python benchmark/run_eval.py
```

This builds every case under `cases/`, compares detected attack paths to each
case's `expected.json`, and writes `results.json` with per-case scores and
aggregate precision/recall/F1.

## Corpus

Each case is a self-contained app with ground truth in `expected.json`:

| Case | Language | Vulnerable | Ground truth |
|---|---|---|---|
| `py_fastapi_sqli` | Python (FastAPI) | yes | route → `raw_sql` → `execute` |
| `py_django_sqli` | Python (Django) | yes | URLconf route → view → `raw` (cross-file) |
| `go_http_sqli` | Go (net/http) | yes | route → handler → `db.Query` |
| `java_spring_sqli` | Java (Spring) | yes | `@GetMapping` → handler → `executeQuery` |
| `py_fastapi_safe` | Python (FastAPI) | no | no sink reachable |
| `go_http_safe` | Go (net/http) | no | no sink reachable |

## Scoring

- **True positive**: an expected entrypoint→sink path that CyberGraph reports.
- **False negative**: an expected path it misses.
- **False positive**: a reported path with no matching expectation (most
  meaningful on the secure cases, where any reported path is a false alarm).

## Reference results (this revision)

```
Aggregate over 6 cases: precision=0.8 recall=1.0 f1=0.889 (tp=4 fp=1 fn=0)
Performance: ~0.08s total build, ~240 KiB total graph db
```

- **Recall 1.0**: every seeded vulnerability path is found, including the
  cross-file Python/Go/Java cases.
- **Zero false positives on the secure cases**: the safe baselines produce no
  attack paths.
- **The one false positive** is in `py_fastapi_sqli`: the helper `raw_sql` is
  flagged both as a sink-named call and as a function that reaches `db.execute`,
  so the same underlying vulnerability is reported as two paths. This reflects
  CyberGraph's name-based sink heuristic and is honest over-reporting, not a
  missed or invented vulnerability.

## Limitations

- The corpus is small and seeded (not mined from real CVEs); it measures
  reachability mechanics, not real-world prevalence.
- Reachability is name-based, not full dataflow; ambiguous call names resolve at
  lower confidence.
- The **LLM grounding comparison** (raw-LLM vs flat-RAG vs graph-grounded across
  multiple models) described in the project plan is **future work**: it requires
  the flat-RAG baseline and provider API keys, and is not run here.

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
| `py_fastapi_tainted_sqli` | Python (FastAPI) | yes | request input → local value → `execute` |
| `py_fastapi_cmdi` | Python (FastAPI) | yes | route → command execution |
| `py_fastapi_pathtrav` | Python (FastAPI) | yes | route → filesystem path traversal sink |
| `py_django_sqli` | Python (Django) | yes | URLconf route → view → `raw` (cross-file) |
| `go_http_sqli` | Go (net/http) | yes | route → handler → `db.Query` |
| `go_http_cmdi` | Go (net/http) | yes | route → handler → `exec.Command` |
| `go_http_pathtrav` | Go (net/http) | yes | route → handler → filesystem path sink |
| `java_spring_sqli` | Java (Spring) | yes | `@GetMapping` → handler → `executeQuery` |
| `py_fastapi_safe` | Python (FastAPI) | no | no sink reachable |
| `go_http_safe` | Go (net/http) | no | no sink reachable |

## Scoring

- **True positive**: an expected entrypoint→sink path that CyberGraph reports.
- **False negative**: an expected path it misses.
- **False positive**: a reported path with no matching expectation (most
  meaningful on the secure cases, where any reported path is a false alarm).

## Reference results

Run `python benchmark/run_eval.py` after analyzer changes to refresh
`benchmark/results.json`. This corpus is intentionally small and regression
oriented: it is meant to guard reachability behavior, not to claim broad
real-world coverage.

```text
Aggregate over 11 cases: precision=0.9 recall=1.0 f1=0.947 (tp=9 fp=1 fn=0)
Performance: ~0.44s total build, ~440 KiB total graph db
```

- **Recall target 1.0**: every seeded vulnerability path should be found,
  including cross-file and tainted local-flow cases.
- **Zero false positives on the secure cases**: the safe baselines produce no
  attack paths.
- **Known over-reporting** can still occur when a helper is both sink-named and
  contains a concrete sink call. Treat that as honest duplicate reporting, not a
  missed or invented vulnerability.

## Limitations

- The corpus is small and seeded (not mined from real CVEs); it measures
  reachability mechanics, not real-world prevalence.
- Reachability now includes lightweight local data-flow evidence, but it is not
  a full program-wide taint engine; ambiguous call names resolve at lower
  confidence.
- The **LLM grounding comparison** (raw-LLM vs flat-RAG vs graph-grounded across
  multiple models) described in the project plan is **future work**: it requires
  the flat-RAG baseline and provider API keys, and is not run here.

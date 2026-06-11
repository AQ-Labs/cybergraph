"""Unit tests for the benchmark scoring functions."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmark"
sys.path.insert(0, str(BENCHMARK_DIR))

metrics = pytest.importorskip("metrics")


def test_true_positive_when_path_matches() -> None:
    expected = [{"entrypoint": "list_users", "sink": "execute"}]
    detected = [(("app.py::list_users", "execute"), "execute")]
    score = metrics.score_case("c", expected, detected)
    assert (score.tp, score.fp, score.fn) == (1, 0, 0)
    assert score.matched


def test_false_negative_when_missing() -> None:
    expected = [{"entrypoint": "list_users", "sink": "execute"}]
    score = metrics.score_case("c", expected, [])
    assert (score.tp, score.fp, score.fn) == (0, 0, 1)


def test_false_positive_on_secure_case() -> None:
    # Secure case expects no paths; any detected path is a false alarm.
    detected = [(("app.py::handler", "db.query"), "db.query")]
    score = metrics.score_case("secure", [], detected)
    assert (score.tp, score.fp, score.fn) == (0, 1, 0)


def test_sink_substring_and_entrypoint_matching() -> None:
    expected = [{"entrypoint": "listUsers", "sink": "db.query"}]
    detected = [(("main.go::route:/users:1", "main.go::listUsers", "db.Query"), "db.Query")]
    score = metrics.score_case("go", expected, detected)
    assert score.tp == 1  # case-insensitive sink + entrypoint substring


def test_aggregate_precision_recall_f1() -> None:
    scores = [
        metrics.CaseScore("a", tp=1, fp=0, fn=0),
        metrics.CaseScore("b", tp=1, fp=1, fn=0),
        metrics.CaseScore("c", tp=0, fp=0, fn=1),
    ]
    agg = metrics.aggregate(scores)
    assert agg["tp"] == 2 and agg["fp"] == 1 and agg["fn"] == 1
    assert agg["precision"] == round(2 / 3, 3)
    assert agg["recall"] == round(2 / 3, 3)

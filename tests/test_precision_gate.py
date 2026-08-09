"""The release gate over the labelled precision corpus.

Four metrics, and two of them are gated **per vulnerability class**. Gating
abstention alone is satisfiable by over-reporting -- safe sites move from
UNKNOWN to *false positive* and the number improves while the tool gets worse --
so the safe-case false-positive rate is gated beside it. A single aggregate is
gameable by corpus composition too, which is why both are per class.

The synthetic tests at the bottom check the *scoring* rather than the detector:
an abstention on a safe case must never be counted as a true negative, and a
false positive on a safe case must fail. Without them the gate could pass by
scoring wrongly rather than by detecting well.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_DIR = ROOT / "benchmark"
sys.path.insert(0, str(BENCHMARK_DIR))

run_precision = pytest.importorskip("run_precision")

# Every case the corpus is required to carry. Deleting a case is the obvious
# repair for a failing gate and it destroys the only property the case exists to
# provide, so the list is asserted rather than implied by whatever is on disk.
REQUIRED_CASES = {
    "sql_concat", "sql_fstring", "sql_percent", "sql_format", "sql_augassign",
    "sql_param_qmark", "sql_param_named", "sql_constant", "sql_hoisted_constant",
    "sql_composed_clean", "sql_reassigned_after_call", "sql_via_builder",
    "cmd_shell_true", "cmd_fstring_shell_true", "cmd_sh_dash_c", "cmd_tainted_argv0",
    "cmd_list_args", "cmd_list_shell_false", "cmd_constant", "cmd_string_no_shell",
    "path_direct", "path_basename", "path_safe_join", "path_constant", "path_normpath",
    "pickle_tainted", "yaml_safe_load",
    "template_string_tainted", "template_render_context", "template_constant",
    "eval_tainted", "exec_tainted", "literal_eval", "eval_constant",
    "alias_import", "from_import",
    "cross_function", "sanitized_helper",
    # Added after review, each closing a gate the corpus could not see:
    "pickle_literal",         # deserialize's only safe case that runs its predicate
    "sql_source_shapes",      # source-rule recall beyond the literal `request.` spelling
    "sql_source_lookalikes",  # source-rule precision on the shapes that merely resemble one
}

# Expected to fail today: bare-name resolution cannot follow `import subprocess
# as sp`. They are excluded from the gated figures and counted separately -- a
# corpus containing only cases you already pass measures nothing.
KNOWN_GAPS = {"alias_import", "from_import"}

# The six predicates the gate claims to be per class, plus the interprocedural
# traversal, which is scored on attack paths rather than findings.
REQUIRED_CLASSES = {
    "sql", "command", "path", "deserialize", "template", "code", "interprocedural",
}


@pytest.fixture(scope="module")
def gate_run() -> tuple[int, dict]:
    """The runner's exit status and the results file it wrote.

    ``check=False`` on purpose: a red gate must exit non-zero, so raising here
    would turn every assertion in this module into the same opaque
    ``CalledProcessError`` instead of the specific gate line that failed.
    """
    completed = subprocess.run(
        [sys.executable, str(BENCHMARK_DIR / "run_precision.py")],
        cwd=ROOT, check=False, capture_output=True,
    )
    return completed.returncode, json.loads(
        (BENCHMARK_DIR / "precision" / "results.json").read_text(encoding="utf-8")
    )


@pytest.fixture(scope="module")
def results(gate_run: tuple[int, dict]) -> dict:
    return gate_run[1]


def test_the_exit_status_carries_the_gate_verdict(gate_run: tuple[int, dict]) -> None:
    # `GATE FAILED` printed on stdout with exit 0 is green on red for any CI
    # step that shells out to the runner, which is how the README documents it.
    returncode, results = gate_run
    assert returncode == (0 if results["passed"] else 1), (returncode, results["passed"])


def test_a_single_red_gate_line_fails_the_run(monkeypatch, tmp_path, capsys) -> None:
    """The only test that ever puts ``main()`` in the failing state.

    ``test_the_exit_status_carries_the_gate_verdict`` reduces to ``0 == 0`` on a
    green corpus, so on its own it is satisfied by ``return 0``. Forcing one
    threshold red exercises the state CI never reaches, and pins all three
    places the verdict is expressed -- the gate rows in ``results.json``, the
    printed verdict, and the exit status -- against the same red line.
    """
    monkeypatch.setattr(run_precision, "RESULTS", tmp_path / "results.json")
    monkeypatch.setattr(run_precision, "MIN_RECALL", 1.10)

    code = run_precision.main()

    doc = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    red = [gate["name"] for gate in doc["gates"] if not gate["passed"]]
    assert red, "precondition: the forced threshold must redden at least one gate"
    assert doc["passed"] is False, red
    assert "GATE FAILED" in capsys.readouterr().out
    assert code == 1
    assert doc["red_gates"] == red, (doc["red_gates"], red)


def test_a_green_corpus_still_passes_and_exits_zero(monkeypatch, tmp_path, capsys) -> None:
    """The other half of the previous test: the verdict tracks the lines *both* ways.

    Without this, `_red_gates` returning a constant non-empty list would satisfy
    the red case while breaking every real run.
    """
    monkeypatch.setattr(run_precision, "RESULTS", tmp_path / "results.json")

    code = run_precision.main()

    doc = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert doc["red_gates"] == []
    assert doc["passed"] is True
    out = capsys.readouterr().out
    assert "GATE PASSED" in out
    assert "GATE FAILED" not in out
    assert "  FAIL " not in out
    assert code == 0


def test_only_command_is_exempt_from_the_abstention_gate(results: dict) -> None:
    """Which classes are exempt is a policy, so it is asserted rather than implied.

    Widening ``ABSTENTION_UNGATED_CLASSES`` to every class removes the abstention
    gate everywhere while all 32 lines still read PASS or "not gated".
    """
    assert results["thresholds"]["abstention_ungated_classes"] == ["command"]
    unenforced = {
        gate["name"].split(":")[0]
        for gate in results["gates"]
        if gate["name"].endswith(":safe_abstention_rate") and not gate["enforced"]
    }
    assert unenforced == {"command"}, sorted(unenforced)


def _case(tmp_path: Path, name: str, source: str, expected: dict) -> Path:
    case = tmp_path / name
    case.mkdir()
    (case / "app.py").write_text(source, encoding="utf-8")
    (case / "expected.json").write_text(json.dumps(expected), encoding="utf-8")
    return case


# `clean` is what `case_mismatch_rate` -- the only gate an `unknown` case ever
# reaches -- is computed from, and every other test in this file hands
# hand-built rows to `_metrics`, one layer above the code that decides it. These
# four run `_score_case` itself, on real detector output.

_ABSTAINS = (
    '"""One abstention: a tainted string command with no shell."""\n'
    "import subprocess\n"
    "from fastapi import FastAPI\n"
    "app = FastAPI()\n"
    "\n"
    '@app.get("/tool")\n'
    "def run_tool(binary: str):\n"
    "    subprocess.run(binary, check=False)\n"
)
_CONSTANT = (
    '"""No finding at all."""\n'
    "import sqlite3\n"
    'cursor = sqlite3.connect("app.db").cursor()\n'
    "\n"
    "def count():\n"
    '    cursor.execute("SELECT COUNT(*) FROM users")\n'
)


def test_an_unknown_case_whose_abstention_count_is_wrong_is_not_clean(tmp_path: Path) -> None:
    declared = {"label": "unknown", "vuln_class": "command", "findings": [], "abstentions": 1}
    matching = run_precision._score_case(_case(tmp_path, "ok", _ABSTAINS, declared))
    assert matching["abstentions"] == 1
    assert matching["clean"] is True

    mismatched = run_precision._score_case(
        _case(tmp_path, "wrong", _ABSTAINS, {**declared, "abstentions": 2})
    )
    assert mismatched["clean"] is False, mismatched


def test_a_safe_case_that_abstains_is_not_clean(tmp_path: Path) -> None:
    # An abstention on a safe case is not a true negative: operationally it
    # sends a clean change to a human.
    row = run_precision._score_case(
        _case(
            tmp_path, "safe_abstains", _ABSTAINS,
            {"label": "safe", "vuln_class": "command", "findings": [], "abstentions": 0},
        )
    )
    assert (row["tp"], row["fp"], row["fn"]) == (0, 0, 0)
    assert row["abstentions"] == 1
    assert row["clean"] is False, row


def test_an_unsafe_case_that_is_missed_entirely_is_not_clean(tmp_path: Path) -> None:
    row = run_precision._score_case(
        _case(
            tmp_path, "missed", _CONSTANT,
            {
                "label": "unsafe", "vuln_class": "sql", "abstentions": 0,
                "findings": [{"file": "app.py", "line": 6, "rule": "CG-SQL-EXEC"}],
            },
        )
    )
    assert (row["fp"], row["fn"]) == (0, 1), row
    assert row["clean"] is False, row


def test_a_wrong_sanitized_inventory_is_not_clean(tmp_path: Path) -> None:
    # A sanitised path is inventory rather than a detection, so it is scored
    # through `clean` alone. Drop `inventory_matches` and fabricating -- or
    # losing -- a barrier becomes invisible to every gate.
    source = (
        '"""A sanitising barrier sits between the route and the sink."""\n'
        "import os\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        'DATA_DIR = "/srv/data"\n'
        "\n"
        '@app.get("/doc")\n'
        "def get_doc(name: str):\n"
        "    return load_doc(name)\n"
        "\n"
        "def load_doc(name):\n"
        "    safe_name = sanitize_filename(name)\n"
        "    with open(os.path.join(DATA_DIR, safe_name)) as handle:\n"
        "        return handle.read()\n"
        "\n"
        "def sanitize_filename(value):\n"
        "    return os.path.basename(value)\n"
    )
    declared = {
        "label": "safe", "vuln_class": "interprocedural", "scoring": "attack_paths",
        "findings": [], "abstentions": 0, "paths": [],
        "sanitized_paths": [{"sink": "open", "data_reachable": False, "risk": "medium"}],
    }
    matching = run_precision._score_case(_case(tmp_path, "inventory_ok", source, declared))
    assert matching["sanitized_paths"], matching
    assert matching["clean"] is True, matching

    row = run_precision._score_case(
        _case(tmp_path, "inventory_lost", source, {**declared, "sanitized_paths": []})
    )
    assert row["sanitized_paths"] != row["sanitized_paths_expected"]
    assert row["clean"] is False, row


def test_every_required_case_exists() -> None:
    cases = {path.name for path in (BENCHMARK_DIR / "precision" / "cases").iterdir()
             if path.is_dir()}
    assert REQUIRED_CASES <= cases, sorted(REQUIRED_CASES - cases)


def test_every_class_carries_at_least_one_safe_case(results: dict) -> None:
    # A class with no safe cases has a false-positive gate that silently never
    # applies, which is the same failure as a corpus of cases you already pass.
    for name in REQUIRED_CLASSES:
        stats = results["per_class"][name]
        assert stats["safe_cases"] >= 1, (name, stats)


def test_detector_meets_the_release_gate(results: dict) -> None:
    failed = [gate for gate in results["gates"] if not gate["passed"]]
    assert not failed, failed
    assert results["passed"], results["overall"]


def test_per_class_gates_are_reported_with_their_case_counts(results: dict) -> None:
    # `FP 0.00 <= 0.05` without `n = 3` beside it claims a tolerance the corpus
    # cannot express: three safe cases can only score 0, 0.33, 0.67 or 1.00.
    for gate in results["gates"]:
        assert "n" in gate
        if 0 < gate["n"] < run_precision.RESOLUTION_FLOOR:
            assert gate["zero_tolerance"], gate


def test_known_gaps_are_counted_and_excluded_never_dropped(results: dict) -> None:
    assert set(results["overall"]["known_gap_cases"]) == KNOWN_GAPS
    rows = {row["name"]: row for row in results["cases"]}
    recovered = results["overall"]["recovered_known_gap_cases"]
    for name in KNOWN_GAPS:
        row = rows[name]
        assert row["known_gap"] is True
        assert row["expected"], row  # it still carries a real expectation to miss
        # Asserted *tracked*, not asserted still-failing. `fn == 1` here broke
        # the moment import resolution improved, which made editing this test
        # the obvious response to a green improvement. Either the gap is still
        # open, or the runner is surfacing it for promotion.
        assert row["fn"] == 1 or name in recovered, row
    assert results["overall"]["gated_cases"] == results["overall"]["cases"] - len(KNOWN_GAPS)
    assert results["overall"]["fn"] == 0, "a known gap leaked into the gated recall"


def test_abstentions_are_excluded_from_precision(results: dict) -> None:
    # Penalising an honest "I could not tell" as a false positive pushes the
    # detector toward guessing, so `unknown` cases contribute nothing to tp/fp/fn.
    unknown = [row for row in results["cases"] if row["label"] == "unknown"]
    assert unknown, "the corpus must contain abstention-by-design cases"
    for row in unknown:
        assert (row["tp"], row["fp"], row["fn"]) == (0, 0, 0), row
        assert row["abstentions"] >= 1, row


def test_every_unknown_case_reaches_a_gated_metric(results: dict) -> None:
    # `unknown` rows contribute nothing to tp/fp/fn and the two safe-case rates
    # select on `label == "safe"`, so before `case_mismatch_rate` existed an
    # abstention could be traded for a confirmed finding -- or for `safe`,
    # inverting "uncertainty never becomes safety" -- with every gate line
    # still reading PASS. Each unknown case must now sit under an enforced
    # mismatch gate for its own class.
    unknown = [row for row in results["cases"] if row["label"] == "unknown"]
    assert unknown, "the corpus must contain abstention-by-design cases"
    gates = {gate["name"]: gate for gate in results["gates"]}
    for row in unknown:
        assert not row["known_gap"], row
        gate = gates[f"{row['vuln_class']}:case_mismatch_rate"]
        assert gate["enforced"], gate
        assert gate["threshold"] == 0.0, gate


def test_an_abstention_traded_for_a_verdict_fails_the_gate() -> None:
    # Both directions of the trade, on the same synthetic unknown case: a
    # confirmed finding, and a silent `safe`.
    for row in (
        _row("u", "unknown", "sql", abstentions=0, detected=["('app.py', 3, 'CG-SQL-EXEC')"]),
        {**_row("u", "unknown", "sql"), "clean": False},  # abstention -> safe
    ):
        stats = run_precision._metrics([row])
        assert stats["case_mismatch_rate"] == 1.0, row
        gate = run_precision._gate(
            "sql:case_mismatch_rate", stats["case_mismatch_rate"],
            run_precision.MAX_CASE_MISMATCH_RATE, minimum=False, n=stats["gated_cases"],
        )
        assert not gate["passed"], row


def test_command_abstention_is_measured_but_not_gated(results: dict) -> None:
    gate = next(
        item for item in results["gates"]
        if item["name"] == "command:safe_abstention_rate"
    )
    assert gate["enforced"] is False
    assert gate["value"] is not None


def _row(name: str, label: str, vuln_class: str, *, tp=0, fp=0, fn=0,
         abstentions=0, detected=(), known_gap=False) -> dict:
    if label == "unknown":
        clean = not detected
    elif label == "safe":
        clean = not detected and not abstentions
    else:
        clean = fp == 0 and fn == 0
    return {
        "name": name, "label": label, "vuln_class": vuln_class, "known_gap": known_gap,
        "tp": tp, "fp": fp, "fn": fn, "abstentions": abstentions,
        "detected": list(detected), "clean": clean,
    }


def test_an_abstention_on_a_safe_case_is_not_a_true_negative() -> None:
    stats = run_precision._metrics([
        _row("safe_a", "safe", "sql"),
        _row("safe_b", "safe", "sql", abstentions=1),
    ])
    assert stats["safe_abstention_rate"] == 0.5
    assert stats["safe_abstained_cases"] == ["safe_b"]
    gate = run_precision._gate(
        "sql:safe_abstention_rate", stats["safe_abstention_rate"],
        run_precision.MAX_SAFE_ABSTENTION_RATE, minimum=False, n=stats["safe_cases"],
    )
    assert not gate["passed"]


def test_a_false_positive_on_a_safe_case_fails_the_gate() -> None:
    stats = run_precision._metrics([
        _row("safe_a", "safe", "sql"),
        _row("safe_b", "safe", "sql", fp=1, detected=["('app.py', 3, 'CG-SQL-EXEC')"]),
    ])
    assert stats["safe_false_positive_rate"] == 0.5
    assert stats["safe_false_positive_cases"] == ["safe_b"]
    gate = run_precision._gate(
        "sql:safe_false_positive_rate", stats["safe_false_positive_rate"],
        run_precision.MAX_SAFE_FALSE_POSITIVE_RATE, minimum=False, n=stats["safe_cases"],
    )
    assert not gate["passed"]


def test_trading_abstention_for_false_positives_does_not_improve_the_score() -> None:
    # Task 4, measured: abstention fell 17.6% -> 12.9% purely because safe sites
    # moved from UNKNOWN to false positive. Both rates are gated, so the trade
    # cannot buy a pass.
    abstaining = run_precision._metrics([
        _row("safe_a", "safe", "sql", abstentions=1),
        _row("safe_b", "safe", "sql"),
        _row("safe_c", "safe", "sql"),
    ])
    over_reporting = run_precision._metrics([
        _row("safe_a", "safe", "sql", fp=1, detected=["x"]),
        _row("safe_b", "safe", "sql"),
        _row("safe_c", "safe", "sql"),
    ])
    assert over_reporting["safe_abstention_rate"] < abstaining["safe_abstention_rate"]
    assert over_reporting["safe_false_positive_rate"] > abstaining["safe_false_positive_rate"]
    for stats, metric, threshold, in (
        (abstaining, "safe_abstention_rate", run_precision.MAX_SAFE_ABSTENTION_RATE),
        (over_reporting, "safe_false_positive_rate",
         run_precision.MAX_SAFE_FALSE_POSITIVE_RATE),
    ):
        assert stats[metric] > threshold


def test_a_missed_unsafe_case_fails_recall() -> None:
    stats = run_precision._metrics([
        _row("unsafe_a", "unsafe", "sql", tp=1),
        _row("unsafe_b", "unsafe", "sql", fn=1),
    ])
    assert stats["recall"] == 0.5
    gate = run_precision._gate(
        "sql:recall", stats["recall"], run_precision.MIN_RECALL,
        minimum=True, n=stats["recall_n"],
    )
    assert not gate["passed"]

import subprocess
from pathlib import Path

from cybergraph.security.capability import UNKNOWN
from cybergraph.security.coverage_report import (
    CAP_CHECKED,
    build_coverage_report,
    format_coverage_report,
)


def _run(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    )


def _repo(tmp_path: Path) -> Path:
    _run(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "seed.py").write_text("x = 1\n", encoding="utf-8")
    _run(tmp_path, "add", "-A")
    _run(tmp_path, "commit", "-qm", "base")
    return tmp_path


def _cap(report, capability_id):
    return next(c for c in report.capabilities if c.capability_id == capability_id)


def test_untracked_python_file_is_analyzed_and_in_scope(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "routes.py").write_text(
        "def f(a, b):\n    return a + b\n", encoding="utf-8"
    )
    report = build_coverage_report(repo)
    assert report.established
    assert "routes.py" in report.changed_files
    assert _cap(report, "sql_construction").status == CAP_CHECKED


def test_unparseable_python_makes_its_capabilities_unknown(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "broken.py").write_text("def f(a, b)\n    return a\n", encoding="utf-8")
    report = build_coverage_report(repo)
    assert _cap(report, "sql_construction").status == UNKNOWN


def test_go_file_is_checked_via_its_partial_analyzer(tmp_path: Path):
    """Go now has a partial analyzer (sql/command/path sinks), like web already did --
    this surface reports CAP_CHECKED, not NOT_SUPPORTED. The stricter honesty
    guarantee (Go is not a Phase-1 *verified* language) still holds in the
    verdict path, where `source_analysis_support` stays NOT_SUPPORTED for Go
    (see test_go_verdicts_e2e.py::test_go_still_not_supported_overall)."""
    repo = _repo(tmp_path)
    (repo / "main.go").write_text("package main\n", encoding="utf-8")
    report = build_coverage_report(repo)
    assert _cap(report, "source_analysis_support").status == CAP_CHECKED


def test_readme_only_change_establishes_an_empty_report(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    report = build_coverage_report(repo)
    assert report.established
    assert report.files == ()


def test_bad_ref_is_a_failure_not_an_empty_report(tmp_path: Path):
    repo = _repo(tmp_path)
    report = build_coverage_report(repo, base="origin/does-not-exist")
    assert not report.established
    assert report.failure
    assert report.files == ()


def test_format_names_the_failure_and_never_says_clean(tmp_path: Path):
    repo = _repo(tmp_path)
    report = build_coverage_report(repo, base="origin/does-not-exist")
    text = format_coverage_report(report)
    assert "could not" in text.lower()
    assert "clean" not in text.lower()

import json
from pathlib import Path

from cybergraph.cli import main


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/users')\n"
        "def list_users(request):\n"
        "    return db.execute('select ' + request.query['q'])\n",
        encoding="utf-8",
    )
    return repo


def test_analyze_text_prints_summary(tmp_path, capsys):
    repo = _repo(tmp_path)
    code = main(["analyze", str(repo), "--no-color", "--no-report"])
    out = capsys.readouterr().out
    assert code == 0
    assert "CyberGraph analysis" in out
    assert "Top risks" in out


def test_visualize_cli_command_still_works(tmp_path, capsys):
    # Regression: a local import inside the 'analyze' branch once shadowed the
    # module-level generate_html_report, making the 'visualize' command raise
    # UnboundLocalError. The visualize command must work end-to-end.
    repo = _repo(tmp_path)
    assert main(["build", str(repo)]) == 0
    capsys.readouterr()
    code = main(["visualize", str(repo)])
    out = capsys.readouterr().out
    assert code == 0
    assert "HTML report" in out
    assert (repo / ".cybergraph" / "report.html").is_file()


def test_analyze_json_is_valid_and_versioned(tmp_path, capsys):
    repo = _repo(tmp_path)
    code = main(["analyze", str(repo), "--json", "--no-report"])
    out = capsys.readouterr().out
    assert code == 0
    doc = json.loads(out)
    assert doc["schema"] == "cybergraph.analysis/1"
    assert doc["counts"]["nodes"] > 0


def test_analyze_json_emits_only_json(tmp_path, capsys):
    repo = _repo(tmp_path)
    code = main(["analyze", str(repo), "--json", "--no-report"])
    out = capsys.readouterr().out
    assert code == 0
    stripped = out.strip()
    assert stripped.startswith("{")
    assert stripped.endswith("}")
    # a single JSON document -- no extra lines (e.g. no "HTML report:" leakage)
    doc = json.loads(stripped)
    assert json.loads(out) == doc


def test_analyze_text_no_color_has_no_ansi(tmp_path, capsys):
    repo = _repo(tmp_path)
    code = main(["analyze", str(repo), "--no-color", "--no-report"])
    out = capsys.readouterr().out
    assert code == 0
    assert "\x1b[" not in out


def test_analyze_writes_report_by_default_and_skips_with_flag(tmp_path, capsys):
    repo = _repo(tmp_path)
    code = main(["analyze", str(repo), "--no-color"])
    out = capsys.readouterr().out
    assert code == 0
    assert "HTML report:" in out
    assert (repo / ".cybergraph" / "report.html").is_file()

    # --no-report: neither the file nor the message should appear on a fresh run
    report_path = repo / ".cybergraph" / "report.html"
    report_path.unlink()
    code = main(["analyze", str(repo), "--no-color", "--no-report"])
    out = capsys.readouterr().out
    assert code == 0
    assert "HTML report:" not in out
    assert not report_path.is_file()

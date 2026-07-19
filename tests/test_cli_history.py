# tests/test_cli_history.py
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


def test_history_command_lists_scans(tmp_path, capsys):
    repo = _repo(tmp_path)
    assert main(["build", str(repo)]) == 0     # records scan #1
    capsys.readouterr()
    code = main(["history", str(repo)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Scan history" in out and "#1" in out


def test_analyze_prints_delta_on_second_run(tmp_path, capsys):
    repo = _repo(tmp_path)
    main(["analyze", str(repo), "--no-color", "--no-report"])   # scan #1 (first)
    capsys.readouterr()
    # edit so the finding set changes, forcing a new scan row
    (repo / "app.py").write_text("def safe():\n    return 1\n", encoding="utf-8")
    main(["analyze", str(repo), "--no-color", "--no-report"])   # scan #2
    out = capsys.readouterr().out
    assert "since last scan" in out.lower()


def test_analyze_delta_line_is_windows_console_safe(tmp_path, capsys):
    # Regression: a non-cp1252 char (e.g. U+0394 Δ) in the delta line raised
    # UnicodeEncodeError on real Windows consoles even though capsys (UTF-8) hid it.
    repo = _repo(tmp_path)
    main(["analyze", str(repo), "--no-color", "--no-report"])
    capsys.readouterr()
    (repo / "app.py").write_text("def safe():\n    return 1\n", encoding="utf-8")
    main(["analyze", str(repo), "--no-color", "--no-report"])
    out = capsys.readouterr().out
    assert "changes since last scan" in out.lower()
    out.encode("cp1252")  # must not raise (Δ would; em-dash is cp1252-safe)


def test_analyze_json_stays_valid_with_recording_active(tmp_path, capsys):
    import json

    repo = _repo(tmp_path)
    main(["analyze", str(repo), "--json", "--no-report"])
    capsys.readouterr()
    (repo / "app.py").write_text("def s():\n    return 1\n", encoding="utf-8")
    main(["analyze", str(repo), "--json", "--no-report"])
    out = capsys.readouterr().out
    json.loads(out)   # must be valid JSON even though history records on the 2nd run


def test_no_delta_line_on_first_analyze(tmp_path, capsys):
    repo = _repo(tmp_path)
    main(["analyze", str(repo), "--no-color", "--no-report"])
    out = capsys.readouterr().out
    assert "since last scan" not in out.lower()

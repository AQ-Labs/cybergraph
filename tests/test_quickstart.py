# tests/test_quickstart.py
from pathlib import Path


from cybergraph.cli import main
from cybergraph.quickstart import run_quickstart


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.route('/x')\ndef h(request):\n    return db.execute(request.query['q'])\n",
        encoding="utf-8",
    )
    return repo


def test_run_quickstart_builds_analyzes_and_writes_report(tmp_path: Path):
    repo = _repo(tmp_path)
    result = run_quickstart(repo)
    assert result.report_path.is_file()
    assert len(result.steps) == 4
    assert result.top_risk  # at least one risk on the vulnerable sample


def test_cli_quickstart_no_open_never_opens_browser(tmp_path: Path, capsys, monkeypatch):
    repo = _repo(tmp_path)
    import webbrowser
    opened = {"n": 0}
    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: opened.__setitem__("n", opened["n"] + 1))
    code = main(["quickstart", str(repo), "--no-open", "--yes"])
    out = capsys.readouterr().out
    assert code == 0
    assert opened["n"] == 0                 # browser never opened
    assert "[1/4]" in out and "[4/4]" in out  # step log printed
    assert "report" in out.lower()

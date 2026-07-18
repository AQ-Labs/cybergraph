import json
from pathlib import Path

import pytest

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


def test_analyze_json_is_valid_and_versioned(tmp_path, capsys):
    repo = _repo(tmp_path)
    code = main(["analyze", str(repo), "--json", "--no-report"])
    out = capsys.readouterr().out
    assert code == 0
    doc = json.loads(out)
    assert doc["schema"] == "cybergraph.analysis/1"
    assert doc["counts"]["nodes"] > 0

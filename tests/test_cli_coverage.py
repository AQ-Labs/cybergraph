import subprocess
from pathlib import Path

from cybergraph.cli import main


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    )


def _repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "seed.py").write_text("x = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "base")
    return tmp_path


def test_coverage_command_exits_zero_on_a_clean_report(tmp_path: Path, capsys):
    repo = _repo(tmp_path)
    (repo / "routes.py").write_text("def f(a):\n    return a\n", encoding="utf-8")
    code = main(["coverage", "--repo", str(repo)])
    out = capsys.readouterr().out
    assert code == 0
    assert "routes.py" in out
    assert "clean" not in out.lower()


def test_coverage_command_exits_nonzero_when_comparison_fails(tmp_path: Path, capsys):
    repo = _repo(tmp_path)
    code = main(["coverage", "--repo", str(repo), "--base", "origin/does-not-exist"])
    assert code != 0

import subprocess
from pathlib import Path

from cybergraph.security.review import format_security_review, review_security_delta


def test_review_reports_no_changes_for_non_git_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def handler():\n    return 1\n", encoding="utf-8")

    review = review_security_delta(repo)

    assert review.changed_files == ()
    assert "No changed files" in format_security_review(review)


def test_review_classifies_added_reachable_risk(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    (repo / "app.py").write_text("def handler():\n    return 1\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "base")
    (repo / "app.py").write_text(
        "@app.get('/search')\n"
        "def handler(request):\n"
        "    q = request.query['q']\n"
        "    return db.execute('select ' + q)\n",
        encoding="utf-8",
    )

    review = review_security_delta(repo, base="HEAD")

    assert review.risk_deltas
    assert review.risk_deltas[0].status == "added"
    assert review.risk_deltas[0].data_reachable is True
    formatted = format_security_review(review)
    assert "Reachable risk deltas" in formatted
    assert "added:" in formatted


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)

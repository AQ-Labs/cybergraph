from pathlib import Path

from cybergraph.security.review import format_security_review, review_security_delta


def test_review_reports_no_changes_for_non_git_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def handler():\n    return 1\n", encoding="utf-8")

    review = review_security_delta(repo)

    assert review.changed_files == ()
    assert "No changed files" in format_security_review(review)

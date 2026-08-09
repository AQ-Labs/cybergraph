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


VULNERABLE = (
    "from fastapi import FastAPI\n"
    "import subprocess\n"
    "app = FastAPI()\n"
    "\n"
    '@app.get("/r0")\n'
    "def run0(cmd: str):\n"
    '    subprocess.run("echo " + cmd, shell=True)\n'
)
CONFIG = '[suppressions]\npaths = ["legacy/**"]\n'


def _suppression_repo(tmp_path: Path, *, tracked_config: bool) -> Path:
    """A repo whose base commit has no config and whose head is suppressed.

    ``tracked_config=True``  -> the PR itself adds ``.cybergraph.toml``.
    ``tracked_config=False`` -> ``.cybergraph.toml`` is gitignored, so it is in
    no tree at all and the base side can never see it. Both shapes are pure
    *configuration* asymmetry: the vulnerable code is identical on both sides.
    """
    repo = tmp_path / ("tracked" if tracked_config else "untracked")
    (repo / "legacy").mkdir(parents=True)
    _git(repo, "init")
    (repo / "legacy" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    if not tracked_config:
        (repo / ".gitignore").write_text(".cybergraph.toml\n.cybergraph/\n", encoding="utf-8")
    _commit(repo, "base")
    (repo / ".cybergraph.toml").write_text(CONFIG, encoding="utf-8")
    # The PR touches one unrelated line; the sink itself is untouched.
    (repo / "legacy" / "app.py").write_text(VULNERABLE + "\n# touched\n", encoding="utf-8")
    _commit(repo, "pr")
    return repo


def test_tracked_suppression_is_not_reported_as_a_removed_attack_path(tmp_path: Path) -> None:
    """A PR that adds a suppression must not claim it removed the risk."""
    repo = _suppression_repo(tmp_path, tracked_config=True)

    review = review_security_delta(repo, base="HEAD~1")

    assert "shell=True" in (repo / "legacy" / "app.py").read_text(encoding="utf-8")
    assert [d for d in review.risk_deltas if d.status == "removed"] == []
    formatted = format_security_review(review)
    assert "removed:" not in formatted
    # The config change is reported for what it is.
    assert "added: legacy/**" in review.suppression_notes
    assert review.suppressed_risk_count == 1
    assert "hidden by suppression config" in formatted


def test_untracked_suppression_is_not_reported_as_a_removed_attack_path(tmp_path: Path) -> None:
    """A gitignored config is in no tree, so the base side must not diverge."""
    repo = _suppression_repo(tmp_path, tracked_config=False)

    review = review_security_delta(repo, base="HEAD~1")

    assert "shell=True" in (repo / "legacy" / "app.py").read_text(encoding="utf-8")
    assert [d for d in review.risk_deltas if d.status == "removed"] == []
    assert "removed:" not in format_security_review(review)
    # It is a local override, not something this change did.
    assert any("untracked" in note for note in review.suppression_notes)
    assert review.suppressed_risk_count == 1


def test_lifting_a_suppression_shows_the_code_as_unchanged(tmp_path: Path) -> None:
    """Deleting a suppression reveals the risk without inventing an 'added' one."""
    repo = tmp_path / "lifted"
    (repo / "legacy").mkdir(parents=True)
    _git(repo, "init")
    (repo / "legacy" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    (repo / ".cybergraph.toml").write_text(CONFIG, encoding="utf-8")
    _commit(repo, "base")
    (repo / ".cybergraph.toml").write_text("[suppressions]\npaths = []\n", encoding="utf-8")
    (repo / "legacy" / "app.py").write_text(VULNERABLE + "\n# touched\n", encoding="utf-8")
    _commit(repo, "pr")

    review = review_security_delta(repo, base="HEAD~1")

    statuses = {delta.status for delta in review.risk_deltas}
    assert statuses == {"unchanged"}, f"code did not change, got {statuses}"
    assert "removed: legacy/**" in review.suppression_notes
    assert review.suppressed_risk_count == 0


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", message)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)

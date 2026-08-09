import subprocess
from pathlib import Path

from cybergraph.security.review import (
    SecurityReview,
    format_security_review,
    review_security_delta,
)


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
    assert "[suppressions] paths added by this change: legacy/**" in review.config_notes
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
    assert any("untracked" in note for note in review.config_notes)
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
    assert "[suppressions] paths dropped by this change: legacy/**" in review.config_notes
    assert review.suppressed_risk_count == 0


SAFE = (
    "from fastapi import FastAPI\n"
    "import subprocess\n"
    "app = FastAPI()\n"
    "\n"
    '@app.get("/r0")\n'
    "def run0(cmd: str):\n"
    "    return cmd\n"
)
CUSTOM_SINK_CALLER = (
    "from fastapi import FastAPI\n"
    "import mymod\n"
    "app = FastAPI()\n"
    "\n"
    '@app.get("/c0")\n'
    "def custom0(cmd: str):\n"
    "    mymod.danger(cmd)\n"
)
IGNORE_CONFIG = '[ignore]\npaths = ["legacy/**"]\n'


def _risk_statuses(review) -> set[str]:
    return {delta.status for delta in review.risk_deltas}


def _delta_section(formatted: str) -> str:
    """Only the risk-delta lines: config notes must never be read as a delta."""
    _, _, tail = formatted.partition("Reachable risk deltas:")
    return tail


def _ignore_repo(tmp_path: Path, *, tracked_config: bool) -> Path:
    """A live sink under a path the *current* config tells the scan to skip.

    ``tracked_config=True``  -> the PR itself adds ``[ignore] paths``.
    ``tracked_config=False`` -> the config is gitignored, so no commit ever held
    it and there is no config change at all -- the shape that misreported on
    every review, forever. The vulnerable code is identical on both sides.
    """
    repo = tmp_path / ("ignore-tracked" if tracked_config else "ignore-untracked")
    (repo / "legacy").mkdir(parents=True)
    _git(repo, "init")
    (repo / "legacy" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    if tracked_config:
        (repo / ".gitignore").write_text(".cybergraph/\n", encoding="utf-8")
        _commit(repo, "base")
        (repo / ".cybergraph.toml").write_text(IGNORE_CONFIG, encoding="utf-8")
    else:
        (repo / ".gitignore").write_text(".cybergraph.toml\n.cybergraph/\n", encoding="utf-8")
        (repo / ".cybergraph.toml").write_text(IGNORE_CONFIG, encoding="utf-8")
        _commit(repo, "base")
    # The PR touches one unrelated line; the sink itself is untouched.
    (repo / "legacy" / "app.py").write_text(VULNERABLE + "\n# touched\n", encoding="utf-8")
    _commit(repo, "pr")
    return repo


def test_tracked_ignore_path_is_not_reported_as_a_removed_attack_path(tmp_path: Path) -> None:
    """A PR that adds [ignore] paths must not claim it removed the risk.

    Reverting ``build_graph(temp_root, config_root=repo_root)`` to
    ``build_graph(temp_root)`` builds the base side under the base tree's own
    config, which has no ``[ignore]`` entry -- the sink appears on the base side
    only and the review reports a critical command injection as fixed.
    """
    repo = _ignore_repo(tmp_path, tracked_config=True)

    review = review_security_delta(repo, base="HEAD~1")

    assert "shell=True" in (repo / "legacy" / "app.py").read_text(encoding="utf-8")
    assert [d for d in review.risk_deltas if d.status == "removed"] == []
    formatted = format_security_review(review)
    assert "removed:" not in _delta_section(formatted)
    # The configuration change is stated as configuration.
    assert "[ignore] paths added by this change: legacy/**" in review.config_notes
    # ...and the review says where it did not look, rather than going silent.
    assert review.ignored_changed_files == ("legacy/app.py",)
    assert "not analysed, not fixed" in formatted


def test_untracked_ignore_path_is_not_reported_as_a_removed_attack_path(tmp_path: Path) -> None:
    """A gitignored [ignore] config is in no tree, so the sides must not diverge."""
    repo = _ignore_repo(tmp_path, tracked_config=False)

    review = review_security_delta(repo, base="HEAD~1")

    assert "shell=True" in (repo / "legacy" / "app.py").read_text(encoding="utf-8")
    assert [d for d in review.risk_deltas if d.status == "removed"] == []
    assert "removed:" not in _delta_section(format_security_review(review))
    assert any("untracked" in note and "[ignore] paths" in note for note in review.config_notes)
    assert review.ignored_changed_files == ("legacy/app.py",)


def test_added_custom_sink_is_not_reported_as_a_new_attack_path(tmp_path: Path) -> None:
    """Widening [security] sinks reveals an old risk; it does not add one."""
    repo = tmp_path / "sinks"
    (repo / "legacy").mkdir(parents=True)
    _git(repo, "init")
    (repo / ".gitignore").write_text(".cybergraph/\n", encoding="utf-8")
    (repo / "legacy" / "app.py").write_text(CUSTOM_SINK_CALLER, encoding="utf-8")
    _commit(repo, "base")
    (repo / ".cybergraph.toml").write_text(
        '[security]\nsinks = ["mymod.danger"]\n', encoding="utf-8"
    )
    (repo / "legacy" / "app.py").write_text(CUSTOM_SINK_CALLER + "\n# touched\n", encoding="utf-8")
    _commit(repo, "pr")

    review = review_security_delta(repo, base="HEAD~1")

    # The call predates the PR, so the PR did not introduce it.
    assert _risk_statuses(review) == {"unchanged"}, "a config-only widening is not a new risk"
    assert "[security] sinks added by this change: mymod.danger" in review.config_notes


def test_a_real_fix_is_still_reported_as_removed(tmp_path: Path) -> None:
    """The counterweight: a tool that can never say 'fixed' is useless too."""
    repo = tmp_path / "real-fix"
    (repo / "legacy").mkdir(parents=True)
    _git(repo, "init")
    (repo / ".gitignore").write_text(".cybergraph/\n", encoding="utf-8")
    (repo / "legacy" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    _commit(repo, "base")
    (repo / "legacy" / "app.py").write_text(SAFE, encoding="utf-8")
    _commit(repo, "pr")

    review = review_security_delta(repo, base="HEAD~1")

    assert "shell=True" not in (repo / "legacy" / "app.py").read_text(encoding="utf-8")
    assert [d.sink for d in review.risk_deltas if d.status == "removed"] == ["subprocess.run"]
    assert "removed:" in _delta_section(format_security_review(review))
    assert review.config_notes == ()


def test_a_real_new_vulnerability_is_still_reported_as_added(tmp_path: Path) -> None:
    """The other counterweight: a genuinely introduced sink must still raise risk."""
    repo = tmp_path / "real-vuln"
    (repo / "legacy").mkdir(parents=True)
    _git(repo, "init")
    (repo / ".gitignore").write_text(".cybergraph/\n", encoding="utf-8")
    (repo / "legacy" / "app.py").write_text(SAFE, encoding="utf-8")
    _commit(repo, "base")
    (repo / "legacy" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    _commit(repo, "pr")

    review = review_security_delta(repo, base="HEAD~1")

    added = [d for d in review.risk_deltas if d.status == "added"]
    assert [d.sink for d in added] == ["subprocess.run"]
    assert added[0].data_reachable is True
    formatted = format_security_review(review)
    assert "added:" in _delta_section(formatted)
    assert "Risk: high" in formatted


def test_dropping_an_ignore_path_invents_no_delta(tmp_path: Path) -> None:
    """Lifting [ignore] paths reveals code that was always there, not new code."""
    repo = tmp_path / "ignore-lifted"
    (repo / "legacy").mkdir(parents=True)
    _git(repo, "init")
    (repo / ".gitignore").write_text(".cybergraph/\n", encoding="utf-8")
    (repo / "legacy" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    (repo / ".cybergraph.toml").write_text(IGNORE_CONFIG, encoding="utf-8")
    _commit(repo, "base")
    (repo / ".cybergraph.toml").write_text("[ignore]\npaths = []\n", encoding="utf-8")
    (repo / "legacy" / "app.py").write_text(VULNERABLE + "\n# touched\n", encoding="utf-8")
    _commit(repo, "pr")

    review = review_security_delta(repo, base="HEAD~1")

    assert _risk_statuses(review) == {"unchanged"}, "the code did not change"
    assert "[ignore] paths dropped by this change: legacy/**" in review.config_notes
    assert review.ignored_changed_files == ()


def test_suppressed_risk_count_does_not_saturate_at_the_delta_limit(tmp_path: Path) -> None:
    """150 suppressed risks must not be reported as 100.

    The count used to be the difference between two scans capped at 100 paths,
    so it saturated there. It understates the blast radius of a suppression --
    the reviewer is being asked to accept more risk than the number admits.
    """
    routes = 150
    repo = tmp_path / "many"
    (repo / "legacy").mkdir(parents=True)
    _git(repo, "init")
    (repo / ".gitignore").write_text(".cybergraph/\n", encoding="utf-8")
    body = ["from fastapi import FastAPI", "import subprocess", "app = FastAPI()", ""]
    for index in range(routes):
        body += [
            f'@app.get("/r{index}")',
            f"def run{index}(cmd: str):",
            f'    subprocess.run("echo {index} " + cmd, shell=True)',
            "",
        ]
    (repo / "legacy" / "app.py").write_text("\n".join(body), encoding="utf-8")
    (repo / ".cybergraph.toml").write_text(CONFIG, encoding="utf-8")
    _commit(repo, "base")
    (repo / "legacy" / "app.py").write_text(
        "\n".join(body) + "\n# touched\n", encoding="utf-8"
    )
    _commit(repo, "pr")

    review = review_security_delta(repo, base="HEAD~1")

    assert review.suppressed_risk_count == routes
    assert review.suppressed_risk_count_capped is False
    assert f"hidden by suppression config: {routes}" in format_security_review(review)


def test_a_capped_hidden_risk_scan_is_reported_as_a_lower_bound() -> None:
    """When the accounting scan does hit its cap, the wording must say so."""
    review = SecurityReview(
        base="HEAD~1",
        changed_files=("legacy/app.py",),
        finding_count=0,
        changed_entrypoints=(),
        changed_sink_edges=(),
        attack_path_count=0,
        suppressed_risk_count=1000,
        suppressed_risk_count_capped=True,
    )

    formatted = format_security_review(review)

    assert "at least 1000" in formatted
    assert "scan capped at" in formatted
    assert "hidden, not fixed" in formatted


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", message)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)

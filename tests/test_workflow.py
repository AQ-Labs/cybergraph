from pathlib import Path


def test_cybergraph_workflow_exists() -> None:
    workflow = Path(".github/workflows/cybergraph.yml")

    text = workflow.read_text(encoding="utf-8")

    assert "cybergraph build ." in text
    assert "cybergraph pr-comment" in text
    assert "cybergraph sarif" in text
    assert "cybergraph visualize" in text
    assert "CYBERGRAPH_UPLOAD_SARIF" in text
    assert "continue-on-error: true" in text
    assert "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24" in text
    # SARIF upload action is pinned to a commit SHA, not a floating tag.
    assert "github/codeql-action/upload-sarif@" in text
    assert "github/codeql-action/upload-sarif@v4" not in text


def test_cybergraph_workflow_is_fork_safe() -> None:
    """The workflow that runs untrusted PR code must hold no write scope and
    must not comment directly; commenting is delegated to ci-report.yml."""
    text = Path(".github/workflows/cybergraph.yml").read_text(encoding="utf-8")

    assert "pull-requests: write" not in text
    assert "gh pr comment" not in text
    # It hands the comment off as an artifact instead.
    assert "cybergraph-pr-comment.md" in text
    assert "pr-number.txt" in text
    assert "persist-credentials: false" in text


def test_report_workflow_posts_from_trusted_context() -> None:
    """ci-report.yml runs on workflow_run (default-branch context) where it can
    safely hold pull-requests: write to post the comment for fork PRs."""
    report = Path(".github/workflows/ci-report.yml")
    assert report.exists()
    text = report.read_text(encoding="utf-8")

    assert "workflow_run" in text
    assert 'workflows: ["CyberGraph"]' in text
    assert "pull-requests: write" in text
    assert "cybergraph-report" in text

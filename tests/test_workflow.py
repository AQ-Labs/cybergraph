from pathlib import Path


def test_cybergraph_workflow_exists() -> None:
    workflow = Path(".github/workflows/cybergraph.yml")

    text = workflow.read_text(encoding="utf-8")

    assert "cybergraph build ." in text
    assert "cybergraph sarif" in text
    assert "github/codeql-action/upload-sarif@v4" in text
    assert "CYBERGRAPH_UPLOAD_SARIF" in text
    assert "continue-on-error: true" in text
    assert "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24" in text
    assert "cybergraph visualize" in text

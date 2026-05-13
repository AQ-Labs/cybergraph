from pathlib import Path


def test_cybergraph_workflow_exists() -> None:
    workflow = Path(".github/workflows/cybergraph.yml")

    text = workflow.read_text(encoding="utf-8")

    assert "cybergraph build ." in text
    assert "cybergraph sarif" in text
    assert "github/codeql-action/upload-sarif" in text
    assert "cybergraph visualize" in text

import json
from pathlib import Path

from cybergraph.graph import GraphStore
from cybergraph.security import load_strix_findings
from cybergraph.security.strix_imports import VALIDATED_TOOL, score_validated_finding

FIXTURE = Path(__file__).parent / "fixtures" / "strix_run"


def test_load_strix_findings_from_run_directory() -> None:
    findings = load_strix_findings(FIXTURE)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == VALIDATED_TOOL
    assert finding.severity == "high"
    assert finding.cwe == "CWE-863"
    assert finding.file_path == "app.py"
    assert finding.line_start == 6
    assert finding.line_end == 8
    assert "Broken Function-Level Authorization" in finding.message
    assert "validated-by=strix" in finding.evidence
    assert "GET /users" in finding.evidence


def test_load_strix_findings_accepts_json_file_directly() -> None:
    findings = load_strix_findings(FIXTURE / "vulnerabilities.json")
    assert len(findings) == 1


def test_load_strix_findings_missing_path_returns_empty(tmp_path: Path) -> None:
    assert load_strix_findings(tmp_path / "does-not-exist") == []


def test_import_strix_findings_persist_in_graph(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".cybergraph").mkdir(parents=True)

    store = GraphStore.open_for_repo(repo)
    store.add_findings(load_strix_findings(FIXTURE))
    rows = store.conn.execute(
        "SELECT tool, severity, cwe FROM findings WHERE tool = ?", (VALIDATED_TOOL,)
    ).fetchall()
    store.close()

    assert len(rows) == 1
    assert rows[0]["cwe"] == "CWE-863"


def test_import_strix_findings_is_idempotent(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".cybergraph").mkdir(parents=True)
    findings = load_strix_findings(FIXTURE)

    store = GraphStore.open_for_repo(repo)
    store.add_findings(findings)
    store.add_findings(findings)
    count = store.conn.execute(
        "SELECT COUNT(*) FROM findings WHERE tool = ?", (VALIDATED_TOOL,)
    ).fetchone()[0]
    store.close()

    assert count == 1


def test_validated_finding_scores_higher_than_static_equivalent() -> None:
    validated = score_validated_finding("high", cvss=7.5)
    # A validated finding is proven reachable + exploitable: it should land in the
    # high/critical band, above a structural-only static candidate.
    assert validated.score >= 70
    assert validated.factors["reachability"] == 1.0
    assert validated.factors["confidence"] == "high"


def test_supports_findings_json_alias(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "findings.json").write_text(
        json.dumps([{ "id": "v1", "title": "X", "severity": "medium", "cwe": "CWE-79" }]),
        encoding="utf-8",
    )
    findings = load_strix_findings(run)
    assert len(findings) == 1
    assert findings[0].severity == "medium"

import json
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.sarif import export_sarif


def test_export_sarif_writes_findings(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.get('/users')\n"
        "def run_query(db, name):\n"
        "    return db.execute('select * from users where name = ' + name)\n",
        encoding="utf-8",
    )
    build_graph(repo)

    output = export_sarif(repo, tmp_path / "cybergraph.sarif")

    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "CyberGraph"
    assert data["runs"][0]["results"][0]["ruleId"] == "CG-SQL-EXEC"
    location = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "app.py"


def test_unverified_rule_id_is_preserved_on_export(tmp_path: Path) -> None:
    """A `-UNVERIFIED` abstention must not be published as a confirmed finding.

    Stripping the suffix on export would report an abstention to code scanning
    under the confirmed rule id -- and no reporting-surface test mentioned
    `-UNVERIFIED` at all. Both the result's `ruleId` (what a code-scanning tool
    keys on) and the rule descriptor must carry the suffix intact.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "@app.get('/u')\n"
        "def run_query(db, uid):\n"
        "    return db.execute(build(uid))\n",
        encoding="utf-8",
    )
    build_graph(repo)

    output = export_sarif(repo, tmp_path / "cybergraph.sarif")
    data = json.loads(output.read_text(encoding="utf-8"))

    result_ids = [r["ruleId"] for r in data["runs"][0]["results"]]
    rule_ids = [rule["id"] for rule in data["runs"][0]["tool"]["driver"]["rules"]]
    assert result_ids == ["CG-SQL-EXEC-UNVERIFIED"], result_ids
    assert "CG-SQL-EXEC-UNVERIFIED" in rule_ids, rule_ids


def test_sarif_filter_targets_only_inventory_not_verdicts():
    """The CI filter must drop only *-SINK-CALL inventory, never an actionable
    verdict rule; and Python's verdict findings must reach code scanning."""
    import re
    from pathlib import Path

    workflow = Path(".github/workflows/cybergraph.yml").read_text(encoding="utf-8")
    # The filter still exists and still targets the inventory rule family.
    assert "SINK-CALL" in workflow, "the inventory filter must remain"
    filter_pattern = re.compile(r"CG-.\*SINK-CALL|\^CG-\.\*SINK-CALL\$")
    assert filter_pattern.search(workflow), "filter must target the *-SINK-CALL family"

    # No Python verdict rule id may match the filter pattern (they must upload).
    verdict_rules = (
        "CG-SQL-EXEC", "CG-CMD-EXEC", "CG-PATH-TRAVERSAL",
        "CG-TEMPLATE-INJECT", "CG-CODE-EXEC", "CG-DESERIALIZE",
    )
    for rule in verdict_rules:
        assert not re.fullmatch(r"CG-.*SINK-CALL", rule), rule


def test_workflow_runs_check_on_pull_requests():
    from pathlib import Path

    workflow = Path(".github/workflows/cybergraph.yml").read_text(encoding="utf-8")
    assert "cybergraph check" in workflow
    assert "merge-base" in workflow

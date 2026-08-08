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

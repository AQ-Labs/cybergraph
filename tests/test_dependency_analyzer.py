from pathlib import Path

from cybergraph.analysis.dependencies import analyze_dependency_manifest


def test_dependency_manifest_analyzer_reads_package_json(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    package = repo / "package.json"
    package.write_text(
        '{"dependencies": {"express": "^4.18.0"}, "devDependencies": {"semgrep": "1.0.0"}}',
        encoding="utf-8",
    )

    nodes, edges = analyze_dependency_manifest(package, repo)

    assert any(node.kind == "DependencyManifest" for node in nodes)
    assert any(node.kind == "Dependency" and node.name == "express" for node in nodes)
    assert any(edge.kind == "DECLARES_DEPENDENCY" for edge in edges)


def test_dependency_manifest_analyzer_reads_requirements(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    requirements = repo / "requirements.txt"
    requirements.write_text("fastapi==0.110.0\n# comment\nuvicorn>=0.29\n", encoding="utf-8")

    nodes, _edges = analyze_dependency_manifest(requirements, repo)

    assert any(node.kind == "Dependency" and node.name == "fastapi" for node in nodes)
    assert any(node.kind == "Dependency" and node.name == "uvicorn" for node in nodes)

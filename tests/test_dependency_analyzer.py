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


def test_dependency_manifest_analyzer_reads_inline_pyproject_dependencies(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    pyproject = repo / "pyproject.toml"
    pyproject.write_text(
        "[project]\n"
        "dependencies = [\"requests>=2.28\", \"flask\"]\n"
        "\n[project.urls]\n"
        "Homepage = \"https://example.com\"\n",
        encoding="utf-8",
    )

    nodes, _edges = analyze_dependency_manifest(pyproject, repo)
    dependencies = {
        node.name: node.properties["version"] for node in nodes if node.kind == "Dependency"
    }

    assert dependencies == {"requests": ">=2.28", "flask": ""}


def test_dependency_manifest_analyzer_reads_multiline_pyproject_deps(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    pyproject = repo / "pyproject.toml"
    pyproject.write_text(
        "[project]\n"
        "dependencies = [\n"
        "  \"fastapi==0.110.0\",\n"
        "  \"uvicorn>=0.29\",\n"
        "]\n",
        encoding="utf-8",
    )

    nodes, _edges = analyze_dependency_manifest(pyproject, repo)
    dependencies = {
        node.name: node.properties["version"] for node in nodes if node.kind == "Dependency"
    }

    assert dependencies == {"fastapi": "==0.110.0", "uvicorn": ">=0.29"}


def test_dependency_manifest_analyzer_reads_common_lockfiles(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    package_lock = repo / "package-lock.json"
    package_lock.write_text(
        '{"dependencies": {"express": {"version": "4.18.2"}}}',
        encoding="utf-8",
    )
    poetry_lock = repo / "poetry.lock"
    poetry_lock.write_text('[[package]]\nname = "fastapi"\nversion = "0.110.0"\n', encoding="utf-8")
    go_sum = repo / "go.sum"
    go_sum.write_text("github.com/gin-gonic/gin v1.9.0 h1:abc\n", encoding="utf-8")

    package_nodes, _ = analyze_dependency_manifest(package_lock, repo)
    poetry_nodes, _ = analyze_dependency_manifest(poetry_lock, repo)
    go_nodes, _ = analyze_dependency_manifest(go_sum, repo)

    assert any(node.kind == "Dependency" and node.name == "express" for node in package_nodes)
    assert any(node.kind == "Dependency" and node.name == "fastapi" for node in poetry_nodes)
    assert any(
        node.kind == "Dependency" and node.name == "github.com/gin-gonic/gin" for node in go_nodes
    )


def test_dependency_manifest_analyzer_reads_jvm_and_dotnet_manifests(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    pom = repo / "pom.xml"
    pom.write_text(
        "<project><dependencies><dependency><groupId>org.springframework</groupId>"
        "<artifactId>spring-web</artifactId><version>6.1.0</version></dependency></dependencies></project>",
        encoding="utf-8",
    )
    csproj = repo / "App.csproj"
    csproj.write_text(
        "<Project><ItemGroup>"
        '<PackageReference Include="Dapper" Version="2.1.35" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    pom_nodes, _ = analyze_dependency_manifest(pom, repo)
    csproj_nodes, _ = analyze_dependency_manifest(csproj, repo)

    assert any(node.kind == "Dependency" and node.name == "spring-web" for node in pom_nodes)
    assert any(node.kind == "Dependency" and node.name == "Dapper" for node in csproj_nodes)

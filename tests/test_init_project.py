from pathlib import Path

from cybergraph.init_project import format_init_result, init_project


def test_init_project_creates_config_and_workflow(tmp_path: Path) -> None:
    result = init_project(tmp_path)

    assert ".cybergraph.toml" in result.created
    assert ".github/workflows/cybergraph.yml" in result.created
    assert (tmp_path / ".cybergraph.toml").exists()
    assert (tmp_path / ".github/workflows/cybergraph.yml").exists()


def test_init_project_skips_existing_files(tmp_path: Path) -> None:
    config = tmp_path / ".cybergraph.toml"
    config.write_text("# existing\n", encoding="utf-8")

    result = init_project(tmp_path)

    assert ".cybergraph.toml" in result.skipped
    assert config.read_text(encoding="utf-8") == "# existing\n"
    assert "Skipped existing files" in format_init_result(result)

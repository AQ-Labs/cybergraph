from pathlib import Path

from cybergraph.doctor import format_doctor, run_doctor
from cybergraph.init_project import init_project


def test_doctor_reports_missing_setup(tmp_path: Path) -> None:
    checks = run_doctor(tmp_path)
    text = format_doctor(checks)

    assert "CyberGraph doctor" in text
    assert any(check.name == "config" and not check.ok for check in checks)
    assert "cybergraph init" in text


def test_doctor_detects_initialized_files(tmp_path: Path) -> None:
    init_project(tmp_path)

    checks = run_doctor(tmp_path)

    assert any(check.name == "config" and check.ok for check in checks)
    assert any(check.name == "github action" and check.ok for check in checks)

from pathlib import Path

from cybergraph.cli import main

APP = '''from fastapi import FastAPI
app = FastAPI()

@app.get("/admin/export")
def export():
    return {}
'''

POLICY = '''version = 1

[rule.admin-requires-login]
kind = "require_auth"
patterns = ["/admin/*"]
because = "Admin pages are not public."
'''


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    (tmp_path / "cybergraph.policy.toml").write_text(POLICY, encoding="utf-8")
    return tmp_path


def test_policy_command_renders_and_exits_zero(tmp_path: Path, capsys):
    repo = _repo(tmp_path)
    code = main(["policy", "--repo", str(repo)])
    out = capsys.readouterr().out
    assert code in (0, None)
    assert "admin-requires-login" in out
    assert "clean" not in out.lower()


def test_baseline_prints_toml_and_writes_nothing(tmp_path: Path, capsys):
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    app_before = (tmp_path / "app.py").read_text(encoding="utf-8")
    code = main(["policy", "--repo", str(tmp_path), "--baseline"])
    out = capsys.readouterr().out
    assert code in (0, None)
    assert "version" in out
    assert not (tmp_path / "cybergraph.policy.toml").exists(), (
        "--baseline proposes a policy; it must not write one"
    )
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == app_before


def test_invalid_repo_exits_nonzero(tmp_path: Path):
    missing = tmp_path / "nope"
    code = main(["policy", "--repo", str(missing)])
    assert code not in (0, None)

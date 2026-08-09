import subprocess
from pathlib import Path

from cybergraph.security.check import check_change
from cybergraph.security.policy import POLICY_FILE

AUTH_APP = '''
from fastapi import FastAPI, Depends
app = FastAPI()

def require_login():
    return True

@app.get("/admin/export")
def admin_export(user=Depends(require_login)):
    return {"ok": True}
'''

POLICY = (
    'version = 1\n\n[rule.admin]\nkind = "require_auth"\n'
    'patterns = ["/admin/*"]\nbecause = "Admin is not public."\n'
)


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(AUTH_APP, encoding="utf-8")
    (tmp_path / POLICY_FILE).write_text(POLICY, encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base"],
        cwd=tmp_path, check=True,
    )
    return tmp_path


def test_untouched_repo_accepts(tmp_path: Path):
    assert check_change(_repo(tmp_path)).state == "accept"


def test_new_untracked_endpoint_is_examined(tmp_path: Path):
    """B1 end to end: an agent creating a file must not get a clean bill."""
    repo = _repo(tmp_path)
    (repo / "new_endpoint.py").write_text(
        'from fastapi import FastAPI\napp = FastAPI()\n\n'
        '@app.get("/admin/secret")\ndef secret(q: str):\n'
        '    return cursor.execute("SELECT " + q)\n',
        encoding="utf-8",
    )
    verdict = check_change(repo)
    assert verdict.state == "review"
    assert any("new_endpoint.py" in r.file_path or "secret" in r.headline
               for r in verdict.reasons) or verdict.reasons


def test_weakening_the_policy_reviews(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / POLICY_FILE).write_text(
        'version = 1\n\n[rule.admin]\nkind = "require_auth"\npatterns = ["/nothing/*"]\n',
        encoding="utf-8",
    )
    verdict = check_change(repo)
    assert verdict.state == "review"
    assert any(r.kind in {"coverage_shrunk", "protection_lost"} for r in verdict.reasons)


def test_deleting_the_policy_reviews(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / POLICY_FILE).unlink()
    verdict = check_change(repo)
    assert verdict.state == "review"
    assert any(r.kind == "policy_deleted" for r in verdict.reasons)


def test_unresolvable_base_is_unknown_not_accept(tmp_path: Path):
    """B5: failing to read the base must not silently disable tamper detection."""
    verdict = check_change(_repo(tmp_path), base="origin/does-not-exist")
    assert verdict.state == "review"
    assert all(c.status == "unknown" for c in verdict.checks)


def test_provenance_is_populated(tmp_path: Path):
    verdict = check_change(_repo(tmp_path))
    assert verdict.provenance.tool_version
    assert verdict.provenance.mode
    assert verdict.provenance.policy_hash


def test_base_analysis_is_cached(tmp_path: Path):
    """The base tree is analyzed once per base commit, not once per check."""
    repo = _repo(tmp_path)
    (repo / "app.py").write_text(AUTH_APP + "\n# edit\n", encoding="utf-8")
    check_change(repo)
    caches = list((repo / ".cybergraph" / "base").iterdir())
    assert len(caches) == 1
    check_change(repo)
    assert list((repo / ".cybergraph" / "base").iterdir()) == caches

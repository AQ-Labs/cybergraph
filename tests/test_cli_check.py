import json
import subprocess
from pathlib import Path

from cybergraph.cli import main
from cybergraph.security.policy import POLICY_FILE

CLEAN = "def add(a, b):\n    return a + b\n"
RISKY = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/search")
def search(term: str):
    return cursor.execute("SELECT * FROM t WHERE n = " + term)
'''


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(CLEAN, encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base"],
        cwd=tmp_path, check=True,
    )
    return tmp_path


def test_clean_change_accepts_without_overclaiming(tmp_path: Path, capsys):
    assert main(["check", str(_repo(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "safe to ship" not in out.lower()
    assert "checks CyberGraph ran" in out


def test_risky_change_reviews_but_exits_zero(tmp_path: Path, capsys):
    repo = _repo(tmp_path)
    (repo / "app.py").write_text(RISKY, encoding="utf-8")
    assert main(["check", str(repo)]) == 0, "review must not block by default"
    assert "attention before shipping" in capsys.readouterr().out


def test_fail_on_review_opts_into_gating(tmp_path: Path):
    """A confirmed regression still blocks by default (block_confirmed_regressions
    defaults True), so --fail-on-review keeps exiting 1 for this case."""
    repo = _repo(tmp_path)
    (repo / "app.py").write_text(RISKY, encoding="utf-8")
    assert main(["check", str(repo), "--fail-on-review"]) == 1


def test_fail_on_review_does_not_block_a_non_blocking_review(tmp_path: Path, capsys):
    """Task 7: --fail-on-review is gate-driven, not state-driven -- a REVIEW
    that policy does not block must exit 0, not 1 (Law 7: policy sets the
    gate, it never launders the decision, and a non-blocking gate must not
    be enforced as if it were a block either)."""
    from cybergraph.security.policy import POLICY_FILE

    repo = _repo(tmp_path)
    (repo / "app.py").write_text(RISKY, encoding="utf-8")
    (repo / POLICY_FILE).write_text(
        "version = 1\n\n"
        "[verification]\n"
        "block_confirmed_regressions = false\n"
        "block_unknown_on_protected_routes = false\n"
        "block_general_unknown = false\n",
        encoding="utf-8",
    )
    assert main(["check", str(repo), "--fail-on-review"]) == 0
    out = capsys.readouterr().out
    assert "attention before shipping" in out


def test_json_carries_gate_and_policy_action(tmp_path: Path, capsys):
    repo = _repo(tmp_path)
    (repo / "app.py").write_text(RISKY, encoding="utf-8")
    main(["check", str(repo), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["gate"] in {"block", "warn", "info"}
    assert payload["policy"]["action"] == payload["gate"]


def test_json_carries_provenance(tmp_path: Path, capsys):
    main(["check", str(_repo(tmp_path)), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] in {"accept", "review"}
    assert payload["provenance"]["tool_version"]
    assert "checks" in payload and "not_evaluated" in payload


def test_init_policy_writes_a_loadable_file(tmp_path: Path):
    assert main(["check", str(_repo(tmp_path)), "--init-policy"]) == 0
    assert (tmp_path / POLICY_FILE).exists()


def test_init_policy_does_not_clobber(tmp_path: Path):
    repo = _repo(tmp_path)
    (repo / POLICY_FILE).write_text("version = 1\n", encoding="utf-8")
    assert main(["check", str(repo), "--init-policy"]) == 2
    assert (repo / POLICY_FILE).read_text(encoding="utf-8") == "version = 1\n"


def test_banned_phrase_appears_nowhere_in_the_source():
    """Case-insensitive, whole tree — the CLI help said it in lowercase."""
    for path in Path("src").rglob("*.py"):
        assert "safe to ship" not in path.read_text(encoding="utf-8").lower(), path

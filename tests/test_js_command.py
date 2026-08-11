from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.javascript import analyze_javascript_file


def _rules(tmp_path: Path, name: str, src: str):
    p = tmp_path / name
    p.write_text(src, encoding="utf-8")
    _n, _e, findings = analyze_javascript_file(p, tmp_path)
    return [f.rule_id for f in findings]


def test_spawn_shell_form_tainted_is_unsafe(tmp_path):
    # spawn("sh", ["-c", userCmd]) -- the command is in the SECOND argument's
    # array, not the first (which is just the literal program name "sh").
    src = (
        "function h(req){ const userCmd = req.query.cmd;\n"
        "  return spawn('sh', ['-c', userCmd]); }\n"
    )
    assert "CG-CMD-EXEC" in _rules(tmp_path, "a.js", src)


def test_execfile_shell_form_tainted_is_unsafe(tmp_path):
    src = (
        "function h(req){ const userCmd = req.query.cmd;\n"
        "  return execFile('sh', ['-c', userCmd]); }\n"
    )
    assert "CG-CMD-EXEC" in _rules(tmp_path, "a.js", src)


def test_child_process_exec_tainted_first_arg_is_unsafe(tmp_path):
    # exec(cmd): the command IS the first argument -- must still be caught.
    src = (
        "function h(req){ const userCmd = req.query.cmd;\n"
        "  return child_process.exec(userCmd); }\n"
    )
    assert "CG-CMD-EXEC" in _rules(tmp_path, "a.js", src)


def test_exec_literal_command_is_clean(tmp_path):
    src = "function h(){ return exec('ls -la'); }\n"
    rules = _rules(tmp_path, "a.js", src)
    assert "CG-CMD-EXEC" not in rules
    assert "CG-CMD-EXEC-UNVERIFIED" not in rules


def test_spawn_all_literal_args_is_clean(tmp_path):
    # every argument a proven string literal (no array-literal argv, which is
    # not itself a proven literal even when its contents are all constant).
    src = "function h(){ return spawn('ls', '-la'); }\n"
    rules = _rules(tmp_path, "a.js", src)
    assert "CG-CMD-EXEC" not in rules
    assert "CG-CMD-EXEC-UNVERIFIED" not in rules

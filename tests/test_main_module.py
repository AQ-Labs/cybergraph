from __future__ import annotations

import subprocess
import sys


def test_python_dash_m_cybergraph_runs() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "cybergraph", "check", "--help"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "--mode" in proc.stdout

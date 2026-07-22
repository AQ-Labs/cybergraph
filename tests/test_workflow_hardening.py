"""Guardrails for GitHub Actions hardening (OpenSSF Scorecard alignment).

Regex-based on purpose: PyYAML is not a declared dev dependency.
"""

import re
from pathlib import Path

WORKFLOW_DIR = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _workflows():
    files = sorted(WORKFLOW_DIR.glob("*.yml"))
    assert files, "no workflow files found"
    return files


def test_every_workflow_declares_top_level_permissions():
    for wf in _workflows():
        text = wf.read_text(encoding="utf-8")
        # column-0 'permissions:' = top-level (job-level is indented)
        assert re.search(r"^permissions:", text, re.M), (
            f"{wf.name}: missing top-level permissions block"
        )


def test_every_action_is_sha_pinned_with_tag_comment():
    pin = re.compile(r"uses:\s*[\w./-]+@[0-9a-f]{40}\s+#\s*\S+")
    for wf in _workflows():
        for lineno, line in enumerate(
            wf.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if re.search(r"^\s*-?\s*uses:", line):
                assert pin.search(line), (
                    f"{wf.name}:{lineno}: action not SHA-pinned with '# <tag>' "
                    f"comment: {line.strip()}"
                )

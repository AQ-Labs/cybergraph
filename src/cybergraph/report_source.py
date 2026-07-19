"""Attach bounded, HTML-escaped, secret-redacted source snippets to graph nodes.

Opt-in: only called when the report is generated with source embedding enabled.
The report is a shareable artifact, so redaction is **content-based and applied to
every embedded line** (highlighted and context) — a secret-looking assignment or a
recognizable key pattern is masked no matter which finding triggered the snippet.
Snippets are anchored on the *finding's* line (not the node's line) so File-level
findings (IaC, secrets) highlight the right code. Every line is HTML-escaped."""

from __future__ import annotations

import html
import re
from pathlib import Path

_REDACTION = "***redacted***"

# A `KEY = VALUE` / `KEY: VALUE` assignment; group 1 is the key, `val` is the value.
_ASSIGN_RE = re.compile(r"([A-Za-z_][\w.\-]*)\s*[:=]\s*(?P<val>\S.*)$")
# The key names that make an assignment's value a secret.
_SECRET_KEY_RE = re.compile(
    r"(?i)(pass(?:word|wd|phrase)?|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|client[_-]?secret|credential|authorization|bearer)"
)
# Recognizable key material even without a keyword (AWS access key id).
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{12,}")


def _redact_line(text: str) -> tuple[str, bool]:
    """Mask secret material in a single source line. Returns (text, was_redacted).

    Conservative: only redacts a value whose key looks secret, or a recognizable
    key pattern — ordinary code (``x = 1``, ``db.execute(...)``) passes through."""
    redacted = False
    match = _ASSIGN_RE.search(text)
    if match and _SECRET_KEY_RE.search(match.group(1)):
        text = text[: match.start("val")] + _REDACTION
        redacted = True
    masked = _AWS_KEY_RE.sub(_REDACTION, text)
    if masked != text:
        text, redacted = masked, True
    return text, redacted


def attach_source_snippets(
    repo_root: Path,
    graph_data: dict,
    *,
    context: int = 3,
    max_nodes: int = 200,
    redact_secrets: bool = True,
) -> None:
    """Attach a bounded, redacted, HTML-escaped source snippet to qualifying nodes.

    A node qualifies if it has a finding or lies on an attack path AND has a file.
    The snippet window is centered on the finding's line when available (so a
    File-level finding highlights its real line, not line 1); every window line is
    content-redacted (when ``redact_secrets``) then HTML-escaped."""
    repo_root = Path(repo_root).resolve()
    cache: dict[str, list[str] | None] = {}
    attached = 0
    for node in graph_data.get("nodes", []):
        if attached >= max_nodes:
            break
        rel = node.get("file") or ""
        findings = node.get("findings") or []
        on_path = bool(node.get("on_path"))
        node_line = int(node.get("line") or 0)

        # Anchor on a finding line when present — fixes File nodes (line 1) whose
        # finding is deeper in the file. Highlight every finding line in the window.
        finding_lines = sorted({int(f.get("line") or 0) for f in findings if int(f.get("line") or 0) > 0})
        if finding_lines:
            anchor = min(finding_lines, key=lambda ln: abs(ln - node_line)) if node_line else finding_lines[0]
        else:
            anchor = node_line

        if not rel or anchor <= 0 or not (findings or on_path):
            continue
        if rel not in cache:
            try:
                cache[rel] = (repo_root / rel).read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                cache[rel] = None
        lines = cache[rel]
        if not lines:
            continue

        highlight = set(finding_lines) if finding_lines else {anchor}
        lo = max(1, anchor - context)
        hi = min(len(lines), anchor + context)
        rendered = []
        for n in range(lo, hi + 1):
            raw = lines[n - 1]
            was_redacted = False
            if redact_secrets:
                raw, was_redacted = _redact_line(raw)
            rendered.append(
                {"n": n, "text": html.escape(raw), "highlight": n in highlight, "redacted": was_redacted}
            )
        node["snippet"] = {"file": rel, "start": lo, "lines": rendered}
        attached += 1

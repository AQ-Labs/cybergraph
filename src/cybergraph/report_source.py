"""Attach bounded, HTML-escaped, secret-redacted source snippets to graph nodes.

Opt-in: only called when the report is generated with source embedding enabled.
The report is a shareable artifact, so snippets for secret-category findings have
their value masked, and every line is HTML-escaped."""

from __future__ import annotations

import html
from pathlib import Path

_REDACTED = '"***redacted***"'


def _is_secret_finding(findings: list) -> bool:
    for f in findings or []:
        rule = str(f.get("rule_id", "")).upper()
        if "SECRET" in rule or "CREDENTIAL" in rule or "PASSWORD" in rule:
            return True
    return False


def _redact(text: str) -> str:
    """Mask a value after the first '=' or ':' so a shared report never leaks it."""
    for sep in ("=", ":"):
        idx = text.find(sep)
        if idx != -1:
            return text[: idx + 1] + " " + _REDACTED
    return _REDACTED


def attach_source_snippets(
    repo_root: Path,
    graph_data: dict,
    *,
    context: int = 3,
    max_nodes: int = 200,
    redact_secrets: bool = True,
) -> None:
    repo_root = Path(repo_root).resolve()
    cache: dict[str, list[str] | None] = {}
    attached = 0
    for node in graph_data.get("nodes", []):
        if attached >= max_nodes:
            break
        rel = node.get("file") or ""
        line = int(node.get("line") or 0)
        findings = node.get("findings") or []
        on_path = bool(node.get("on_path"))
        if not rel or line <= 0 or not (findings or on_path):
            continue
        if rel not in cache:
            try:
                cache[rel] = (repo_root / rel).read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                cache[rel] = None
        lines = cache[rel]
        if not lines:
            continue
        secret = redact_secrets and _is_secret_finding(findings)
        lo = max(1, line - context)
        hi = min(len(lines), line + context)
        rendered = []
        for n in range(lo, hi + 1):
            raw = lines[n - 1]
            highlight = n == line
            if highlight and secret:
                raw = _redact(raw)
            rendered.append({"n": n, "text": html.escape(raw), "highlight": highlight})
        node["snippet"] = {"file": rel, "start": lo, "lines": rendered}
        attached += 1

"""Dockerfile security analyzer.

Line-based (mirroring the other lightweight analyzers). Dockerfiles are nearly
universal in application repos, so a handful of high-signal container
misconfigurations cover a lot of real risk:

* runs as root (no ``USER`` sets a non-root user, or ``USER root``);
* hardcoded credentials in ``ENV`` / ``ARG`` baked into image layers;
* remote code execution at build time (``RUN curl ... | sh``);
* ``ADD`` from a remote URL (unverified fetch; ``COPY`` is preferred);
* unpinned base image (``:latest`` or no tag/digest).

Conservative by design: the file always yields a File node and never crashes the
build. Findings carry a CWE and a verbatim evidence line, consistent with the
other analyzers, and honor inline ``# cybergraph: ignore`` suppression.
"""

from __future__ import annotations

import re
from pathlib import Path

from cybergraph.graph import Edge, Finding, Node
from cybergraph.suppressions import is_inline_suppressed

FROM_RE = re.compile(r"^\s*FROM\s+(?P<image>\S+)(?:\s+AS\s+(?P<alias>\S+))?", re.IGNORECASE)
USER_RE = re.compile(r"^\s*USER\s+(?P<user>\S+)", re.IGNORECASE)
ADD_REMOTE_RE = re.compile(r"^\s*ADD\s+(?:--\S+\s+)*https?://", re.IGNORECASE)
CURL_PIPE_SH_RE = re.compile(
    r"^\s*RUN\s+.*\b(?:curl|wget)\b.*\|\s*(?:sudo\s+)?(?:sh|bash)\b", re.IGNORECASE
)
SECRET_ENV_RE = re.compile(
    r"^\s*(?:ENV|ARG)\s+(?P<key>[A-Za-z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY)[A-Za-z0-9_]*)"
    r"\s*[=\s]\s*(?P<val>\S+)",
    re.IGNORECASE,
)


def analyze_dockerfile_file(
    path: Path,
    repo_root: Path,
    secret_markers: tuple[str, ...] = (),
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()
    rel = path.relative_to(repo_root).as_posix()
    nodes: list[Node] = [Node("File", rel, rel, rel, 1, len(lines), {"language": "dockerfile"})]
    findings: list[Finding] = []

    stage_aliases: set[str] = set()
    from_line = 0
    sets_non_root_user = False

    for line_no, line in enumerate(lines, start=1):
        from_match = FROM_RE.match(line)
        if from_match:
            from_line = from_line or line_no
            alias = from_match.group("alias")
            if alias:
                stage_aliases.add(alias.lower())
            _check_base_image(
                findings, lines, rel, line_no, from_match.group("image"), stage_aliases
            )

        user_match = USER_RE.match(line)
        if user_match and user_match.group("user").lower() not in {"root", "0"}:
            sets_non_root_user = True

        if ADD_REMOTE_RE.match(line):
            _emit(findings, lines, rel, "CG-DOCKER-ADD-REMOTE", "medium",
                  "ADD fetches from a remote URL (use COPY or a verified download)",
                  line_no, "CWE-494")

        if CURL_PIPE_SH_RE.match(line):
            _emit(findings, lines, rel, "CG-DOCKER-REMOTE-EXEC", "high",
                  "RUN pipes a remote download straight into a shell (remote code execution)",
                  line_no, "CWE-494")

        secret_match = SECRET_ENV_RE.match(line)
        if secret_match and _is_literal_secret(secret_match.group("val")):
            _emit(findings, lines, rel, "CG-DOCKER-SECRET", "critical",
                  f"hardcoded {secret_match.group('key').lower()} baked into an image layer",
                  line_no, "CWE-798")

    if from_line and not sets_non_root_user:
        _emit(findings, lines, rel, "CG-DOCKER-ROOT-USER", "medium",
              "container runs as root (no USER sets a non-root user)",
              from_line, "CWE-250")

    return nodes, [], findings


def _check_base_image(
    findings: list[Finding],
    lines: list[str],
    rel: str,
    line_no: int,
    image: str,
    stage_aliases: set[str],
) -> None:
    ref = image.lower()
    if ref in stage_aliases or ref == "scratch":
        return  # references a prior build stage or the empty base
    if "@sha256:" in ref:
        return  # pinned by digest
    if ":" in ref:
        if ref.rsplit(":", 1)[1] == "latest":
            _emit(findings, lines, rel, "CG-DOCKER-UNPINNED-BASE", "low",
                  f"base image `{image}` uses the floating `latest` tag", line_no, "CWE-1104")
        return
    _emit(findings, lines, rel, "CG-DOCKER-UNPINNED-BASE", "low",
          f"base image `{image}` has no version tag or digest (pin it)", line_no, "CWE-1104")


def _is_literal_secret(value: str) -> bool:
    """Skip build-arg/interpolation placeholders; only flag literal values."""
    val = value.strip().strip('"').strip("'")
    if len(val) < 4:
        return False
    return not (val.startswith("$") or "${" in val)


def _emit(
    findings: list[Finding],
    lines: list[str],
    rel: str,
    rule_id: str,
    severity: str,
    message: str,
    line_no: int,
    cwe: str,
) -> None:
    if is_inline_suppressed(lines, line_no, rule_id):
        return
    evidence = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
    findings.append(
        Finding(
            rule_id=rule_id,
            severity=severity,
            message=message,
            file_path=rel,
            line_start=line_no,
            cwe=cwe,
            evidence=evidence,
        )
    )

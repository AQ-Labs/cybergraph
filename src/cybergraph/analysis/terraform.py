"""Terraform (HCL) infrastructure-as-code security analyzer.

Regex/brace-based (no HCL dependency), mirroring the other lightweight analyzers.
Each ``resource "<type>" "<name>" {...}`` block becomes a ``Resource`` node (layer
``infrastructure``), and the analyzer flags cloud misconfigurations that are the
building blocks of cloud attack paths:

* public network exposure (``0.0.0.0/0`` / ``::/0`` ingress) -- also modeled as an
  external ``Entrypoint`` because an internet-open resource is a trust boundary;
* publicly accessible storage (S3 ACL ``public-read`` / disabled public-access block);
* over-broad IAM (Action/Resource ``"*"``);
* hardcoded credentials embedded in IaC.

Conservative by design: an unrecognised block still yields a Resource node, and the
file always produces a valid File node so the build never crashes. Findings carry a
CWE and a verbatim evidence line, consistent with the code analyzers. Cross-resource
attack-path traversal (public ingress -> compute -> privileged IAM) builds on these
nodes and is layered on separately.
"""

from __future__ import annotations

import re
from pathlib import Path

from cybergraph.graph import Edge, Finding, Node
from cybergraph.security.ontology import EDGE_EXPOSES_ENTRYPOINT
from cybergraph.suppressions import is_inline_suppressed

RESOURCE_RE = re.compile(r'resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{')
OPEN_CIDR_RE = re.compile(r'"(?:0\.0\.0\.0/0|::/0)"')
WILDCARD_ACTION_RE = re.compile(r'"?actions?"?\s*[=:]\s*\[?\s*"\*"', re.IGNORECASE)
PUBLIC_ACL_RE = re.compile(r'acl\s*=\s*"public-read(?:-write)?"')
PUBLIC_ACCESS_BLOCK_RE = re.compile(
    r"(?:block_public_acls|ignore_public_acls|block_public_policy|restrict_public_buckets)\s*=\s*false"
)
SECRET_ASSIGN_RE = re.compile(
    r'\b(?P<key>access_key|secret_key|secret|password|passwd|token|api_key|apikey|private_key)'
    r'\s*=\s*"(?P<val>[^"${}]{4,})"',
    re.IGNORECASE,
)


def analyze_terraform_file(
    path: Path,
    repo_root: Path,
    secret_markers: tuple[str, ...] = (),
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()
    rel = path.relative_to(repo_root).as_posix()
    nodes: list[Node] = [Node("File", rel, rel, rel, 1, len(lines), {"language": "terraform"})]
    edges: list[Edge] = []
    findings: list[Finding] = []

    for match in RESOURCE_RE.finditer(source):
        rtype = match.group("type")
        rname = match.group("name")
        body = _block_body(source, match.end() - 1)
        start_line = source.count("\n", 0, match.start()) + 1
        end_line = start_line + body.count("\n")
        key = f"{rel}::{rtype}.{rname}"

        public_ingress = bool(OPEN_CIDR_RE.search(body)) and (
            "security_group" in rtype or "firewall" in rtype or "ingress" in body
        )
        wildcard_iam = ("iam" in rtype or "policy" in rtype) and bool(WILDCARD_ACTION_RE.search(body))
        public_bucket = (
            rtype.endswith("s3_bucket") and bool(PUBLIC_ACL_RE.search(body))
        ) or (
            rtype.endswith("s3_bucket_public_access_block") and bool(PUBLIC_ACCESS_BLOCK_RE.search(body))
        )

        props = {"resource_type": rtype, "layer": "infrastructure"}
        if public_ingress:
            props["public_exposure"] = True
        if wildcard_iam:
            props["privileged"] = True
        nodes.append(Node("Resource", key, f"{rtype}.{rname}", rel, start_line, end_line, props))

        if public_ingress:
            line_no = _match_line(lines, start_line, end_line, OPEN_CIDR_RE)
            _emit(
                findings, lines, rel, "CG-IAC-OPEN-INGRESS", "high",
                f"`{rtype}.{rname}` allows ingress from the public internet (0.0.0.0/0)",
                line_no, "CWE-284",
            )
            ep_key = f"{rel}::entrypoint:{rtype}.{rname}"
            nodes.append(
                Node("Entrypoint", ep_key, f"{rtype}.{rname}", rel, start_line, start_line,
                     {"framework": "terraform", "exposure": "public-ingress"})
            )
            edges.append(Edge(EDGE_EXPOSES_ENTRYPOINT, rel, ep_key, rel, line_no))

        if public_bucket:
            line_no = _match_line(lines, start_line, end_line, PUBLIC_ACL_RE) or _match_line(
                lines, start_line, end_line, PUBLIC_ACCESS_BLOCK_RE
            )
            _emit(
                findings, lines, rel, "CG-IAC-PUBLIC-BUCKET", "high",
                f"`{rtype}.{rname}` is publicly accessible storage",
                line_no, "CWE-732",
            )

        if wildcard_iam:
            line_no = _match_line(lines, start_line, end_line, WILDCARD_ACTION_RE)
            _emit(
                findings, lines, rel, "CG-IAC-WILDCARD-IAM", "high",
                f"`{rtype}.{rname}` grants wildcard privileges (Action/Resource \"*\")",
                line_no, "CWE-269",
            )

        secret_match = SECRET_ASSIGN_RE.search(body)
        if secret_match:
            line_no = _match_line(lines, start_line, end_line, SECRET_ASSIGN_RE)
            _emit(
                findings, lines, rel, "CG-IAC-HARDCODED-SECRET", "critical",
                f"`{rtype}.{rname}` embeds a hardcoded {secret_match.group('key').lower()}",
                line_no, "CWE-798",
            )

    return nodes, edges, findings


def _block_body(source: str, brace_index: int) -> str:
    """Return the substring from an opening brace through its matching close."""
    depth = 0
    for i in range(brace_index, len(source)):
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace_index : i + 1]
    return source[brace_index:]


def _match_line(lines: list[str], start_line: int, end_line: int, pattern: re.Pattern) -> int:
    for line_no in range(start_line, min(end_line, len(lines)) + 1):
        if pattern.search(lines[line_no - 1]):
            return line_no
    return start_line


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

"""Lightweight Java (Spring Boot) security analyzer.

Regex-based, mirroring the Go and JavaScript analyzers. Recognises Spring MVC
route annotations, common JDBC / command / filesystem sinks, and secret access
via System.getenv or @Value placeholders. Unrecognised constructs are ignored
so the file always yields a valid File node.
"""

from __future__ import annotations

import re
from pathlib import Path

from cybergraph.graph import Edge, Finding, Node
from cybergraph.security.ontology import (
    EDGE_EXPOSES_ENTRYPOINT,
    EDGE_REACHES_SINK,
    EDGE_USES_SECRET,
)
from cybergraph.suppressions import is_inline_suppressed

# Method declarations: optional annotations are matched separately; this matches
# `public List<User> listUsers(...)` style signatures (not control-flow keywords).
METHOD_RE = re.compile(
    r"\b(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?"
    r"[\w<>\[\],.\s]+?\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{]*\)\s*(?:throws[\w,\s]+)?\{"
)
SPRING_ROUTE_RE = re.compile(
    r"@(?:(?P<verb>Get|Post|Put|Patch|Delete)Mapping|RequestMapping)"
    r"\s*(?:\(\s*(?:value\s*=\s*)?\"(?P<path>[^\"]*)\")?"
)
CALL_RE = re.compile(r"(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*\(")

SINK_CALLS = {
    "executequery", "executeupdate", "statement.execute",
    "jdbctemplate.query", "jdbctemplate.update",
    "createnativequery", "createquery",
    "getruntime", "runtime.exec", "processbuilder", "process.start",
    "files.write", "files.readallbytes", "filewriter", "filereader", "fileinputstream",
}
SECRET_MARKERS = {"system.getenv", "@value", "secret", "password", "token", "apikey", "api_key"}


def analyze_java_file(
    path: Path,
    repo_root: Path,
    custom_sinks: tuple[str, ...] = (),
    secret_markers: tuple[str, ...] = (),
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()
    rel = path.relative_to(repo_root).as_posix()
    nodes: list[Node] = [Node("File", rel, rel, rel, 1, len(lines), {"language": "java"})]
    edges: list[Edge] = []
    findings: list[Finding] = []

    pending_route: dict | None = None
    current_function: str | None = None
    for line_no, line in enumerate(lines, start=1):
        route_match = SPRING_ROUTE_RE.search(line)
        if route_match:
            pending_route = {
                "path": route_match.group("path") or "/",
                "method": (route_match.group("verb") or "ANY").upper(),
                "line": line_no,
            }

        method_match = METHOD_RE.search(line)
        if method_match:
            name = method_match.group("name")
            key = f"{rel}::{name}"
            current_function = key
            nodes.append(Node("Function", key, name, rel, line_no, line_no, _classify_java_name(name)))
            if pending_route is not None:
                route_key = f"{rel}::route:{pending_route['path']}:{pending_route['line']}"
                nodes.append(
                    Node(
                        "Entrypoint", route_key, pending_route["path"], rel,
                        pending_route["line"], pending_route["line"],
                        {"framework": "spring", "method": pending_route["method"]},
                    )
                )
                edges.append(Edge(EDGE_EXPOSES_ENTRYPOINT, rel, route_key, rel, pending_route["line"]))
                edges.append(Edge("CALLS", route_key, name, rel, line_no))
                pending_route = None

        sink_source = current_function or rel
        lowered_line = line.lower()
        if any(marker in lowered_line for marker in SECRET_MARKERS | set(secret_markers)):
            edges.append(Edge(EDGE_USES_SECRET, sink_source, "secret", rel, line_no))

        for call in CALL_RE.finditer(line):
            call_name = call.group("name")
            if _is_sink(call_name, custom_sinks):
                edges.append(Edge(EDGE_REACHES_SINK, sink_source, call_name, rel, line_no))
                if not is_inline_suppressed(lines, line_no, "CG-JAVA-SINK-CALL"):
                    findings.append(
                        Finding(
                            rule_id="CG-JAVA-SINK-CALL",
                            severity="medium",
                            message=f"Java file reaches sensitive sink `{call_name}`",
                            file_path=rel,
                            line_start=line_no,
                            cwe="CWE-20",
                            evidence=line.strip(),
                        )
                    )

    return nodes, edges, findings


def _classify_java_name(name: str) -> dict[str, bool]:
    lowered = name.lower()
    return {
        "auth_related": "auth" in lowered or "login" in lowered,
        "authorization_related": "permission" in lowered or "role" in lowered or "admin" in lowered,
        "validation_related": "validate" in lowered or "sanitize" in lowered or "clean" in lowered,
        "secret_related": "secret" in lowered or "token" in lowered or "password" in lowered,
        "crypto_related": "hash" in lowered or "encrypt" in lowered or "sign" in lowered,
        "sink_related": "query" in lowered or "exec" in lowered,
    }


def _is_sink(call_name: str, custom_sinks: tuple[str, ...] = ()) -> bool:
    lowered = call_name.lower()
    return any(sink in lowered for sink in SINK_CALLS) or any(
        sink.lower() in lowered for sink in custom_sinks
    )

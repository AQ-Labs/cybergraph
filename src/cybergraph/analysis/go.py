"""Lightweight Go security analyzer.

Regex-based (the standard library has no Go parser), mirroring the JavaScript
analyzer. Recognises routes from net/http, Gin, and Echo; sensitive sinks for
SQL, command execution, and filesystem; and secret access via os.Getenv. It is
deliberately conservative: unrecognised constructs are simply ignored so the
file still produces a valid File node and never crashes the build.
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

FUNC_RE = re.compile(
    r"^\s*func\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\("
)
# net/http: http.HandleFunc("/path", handler) or mux.Handle("/path", ...)
NET_HTTP_RE = re.compile(
    r"\b(?:http|mux|r|router)\.(?:HandleFunc|Handle)\s*\(\s*\"(?P<path>[^\"]+)\""
)
# Gin / Echo / chi: r.GET("/path", handler), e.POST("/path", ...), group.DELETE(...)
ROUTER_VERB_RE = re.compile(
    r"\b[A-Za-z_]\w*\.(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any)\s*\(\s*\"(?P<path>[^\"]+)\""
)
CALL_RE = re.compile(r"(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*\(")

SINK_CALLS = {
    "db.query", "db.exec", "db.queryrow", "db.querycontext", "db.execcontext",
    "tx.query", "tx.exec", "exec.command", "exec.commandcontext",
    "os.open", "os.openfile", "os.readfile", "os.writefile", "ioutil.writefile",
    "os.remove", "template.html", "fmt.sprintf",
}
SECRET_MARKERS = {"os.getenv", "secret", "password", "token", "apikey", "api_key", "private_key"}


def analyze_go_file(
    path: Path,
    repo_root: Path,
    custom_sinks: tuple[str, ...] = (),
    secret_markers: tuple[str, ...] = (),
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()
    rel = path.relative_to(repo_root).as_posix()
    nodes: list[Node] = [Node("File", rel, rel, rel, 1, len(lines), {"language": "go"})]
    edges: list[Edge] = []
    findings: list[Finding] = []

    for line_no, line in enumerate(lines, start=1):
        func_match = FUNC_RE.search(line)
        if func_match:
            name = func_match.group("name")
            key = f"{rel}::{name}"
            nodes.append(Node("Function", key, name, rel, line_no, line_no, _classify_go_name(name)))

        for route_match in (NET_HTTP_RE.search(line), ROUTER_VERB_RE.search(line)):
            if not route_match:
                continue
            route_path = route_match.group("path")
            method = (
                route_match.groupdict().get("method")
                or "ANY"
            )
            framework = "net/http" if route_match.re is NET_HTTP_RE else "gin/echo"
            key = f"{rel}::route:{route_path}:{line_no}"
            nodes.append(
                Node(
                    "Entrypoint", key, route_path, rel, line_no, line_no,
                    {"framework": framework, "method": method},
                )
            )
            edges.append(Edge(EDGE_EXPOSES_ENTRYPOINT, rel, key, rel, line_no))

        lowered_line = line.lower()
        if any(marker in lowered_line for marker in SECRET_MARKERS | set(secret_markers)):
            edges.append(Edge(EDGE_USES_SECRET, rel, "secret", rel, line_no))

        for call in CALL_RE.finditer(line):
            call_name = call.group("name")
            if _is_sink(call_name, custom_sinks):
                edges.append(Edge(EDGE_REACHES_SINK, rel, call_name, rel, line_no))
                if not is_inline_suppressed(lines, line_no, "CG-GO-SINK-CALL"):
                    findings.append(
                        Finding(
                            rule_id="CG-GO-SINK-CALL",
                            severity="medium",
                            message=f"Go file reaches sensitive sink `{call_name}`",
                            file_path=rel,
                            line_start=line_no,
                            cwe="CWE-20",
                            evidence=line.strip(),
                        )
                    )

    return nodes, edges, findings


def _classify_go_name(name: str) -> dict[str, bool]:
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

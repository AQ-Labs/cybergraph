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
    EDGE_EXPOSES_SECRET,
    EDGE_FLOWS_TO,
    EDGE_REACHES_SINK,
    EDGE_READS_INPUT,
    EDGE_TAINTS,
    EDGE_USES_SECRET,
)
from cybergraph.suppressions import is_inline_suppressed

FUNC_RE = re.compile(
    r"^\s*func\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\("
)
# net/http: http.HandleFunc("/path", handler) or mux.Handle("/path", ...)
NET_HTTP_RE = re.compile(
    r"\b(?:http|mux|r|router)\.(?:HandleFunc|Handle)\s*\(\s*\"(?P<path>[^\"]+)\""
    r"(?:\s*,\s*(?P<handler>[A-Za-z_]\w*))?"
)
# Gin / Echo / chi: r.GET("/path", handler), e.POST("/path", ...), group.DELETE(...)
ROUTER_VERB_RE = re.compile(
    r"\b[A-Za-z_]\w*\.(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any)\s*\(\s*\"(?P<path>[^\"]+)\""
    r"(?:\s*,\s*(?P<handler>[A-Za-z_]\w*))?"
)
CALL_RE = re.compile(r"(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*\(")
ASSIGN_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<expr>.+)")

SINK_CALLS = {
    "db.query", "db.exec", "db.queryrow", "db.querycontext", "db.execcontext",
    "tx.query", "tx.exec", "exec.command", "exec.commandcontext",
    "os.open", "os.openfile", "os.readfile", "os.writefile", "ioutil.writefile",
    "os.remove", "template.html", "fmt.sprintf",
}
SECRET_MARKERS = {"os.getenv", "secret", "password", "token", "apikey", "api_key", "private_key"}
INPUT_MARKERS = {"url.query", "formvalue", "postformvalue", ".query(", ".param(", ".bind(", ".body"}
SECRET_EXPOSURE_SINKS = {
    "fmt.print",
    "log.print",
    "log.printf",
    "http.post",
    "http.client.do",
    "exec.command",
    "responsewriter.write",
}


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

    current_function: str | None = None
    tainted_by_function: dict[str, dict[str, str]] = {}
    for line_no, line in enumerate(lines, start=1):
        func_match = FUNC_RE.search(line)
        if func_match:
            name = func_match.group("name")
            current_function = f"{rel}::{name}"
            tainted_by_function.setdefault(current_function, {})
            nodes.append(
                Node(
                    "Function", current_function, name, rel, line_no, line_no,
                    _classify_go_name(name),
                )
            )

        for route_match in (NET_HTTP_RE.search(line), ROUTER_VERB_RE.search(line)):
            if not route_match:
                continue
            route_path = route_match.group("path")
            method = route_match.groupdict().get("method") or "ANY"
            framework = "net/http" if route_match.re is NET_HTTP_RE else "gin/echo"
            key = f"{rel}::route:{route_path}:{line_no}"
            nodes.append(
                Node(
                    "Entrypoint", key, route_path, rel, line_no, line_no,
                    {"framework": framework, "method": method},
                )
            )
            edges.append(Edge(EDGE_EXPOSES_ENTRYPOINT, rel, key, rel, line_no))
            _add_input_source(key, "request", rel, line_no, nodes, edges, route_path)
            handler = route_match.groupdict().get("handler")
            if handler:
                # Link the route to its handler so traversal reaches the handler's sinks.
                edges.append(Edge("CALLS", key, handler, rel, line_no))

        # Attribute sinks/secrets to the enclosing function so interprocedural
        # reachability (route -> handler -> sink) works uniformly across languages.
        sink_source = current_function or rel
        tainted = tainted_by_function.setdefault(sink_source, {})
        lowered_line = line.lower()
        input_key = _line_input_source(sink_source, lowered_line, rel, line_no, nodes, edges)
        source_key = input_key or _tainted_source_for_line(line, tainted)
        if source_key:
            assigned = _assigned_name(line)
            if assigned:
                flow_key = f"{sink_source}::flow:{assigned}:{line_no}"
                nodes.append(
                    Node(
                        "DataFlow",
                        flow_key,
                        assigned,
                        rel,
                        line_no,
                        line_no,
                        {"user_controlled": True, "source": source_key},
                    )
                )
                edges.append(Edge(EDGE_FLOWS_TO, source_key, flow_key, rel, line_no))
                tainted[assigned] = flow_key
        if any(marker in lowered_line for marker in SECRET_MARKERS | set(secret_markers)):
            edges.append(Edge(EDGE_USES_SECRET, sink_source, "secret", rel, line_no))

        for call in CALL_RE.finditer(line):
            call_name = call.group("name")
            if any(
                marker in lowered_line for marker in SECRET_MARKERS | set(secret_markers)
            ) and _is_secret_exposure(call_name):
                edges.append(
                    Edge(
                        EDGE_EXPOSES_SECRET,
                        sink_source,
                        call_name,
                        rel,
                        line_no,
                        {"reason": "secret passed to exposure sink"},
                    )
                )
            if _is_sink(call_name, custom_sinks):
                edges.append(Edge(EDGE_REACHES_SINK, sink_source, call_name, rel, line_no))
                taint_source = source_key or _tainted_source_for_line(line, tainted)
                if taint_source:
                    edges.append(
                        Edge(
                            EDGE_TAINTS,
                            taint_source,
                            call_name,
                            rel,
                            line_no,
                            {"function": sink_source, "reason": "tainted argument"},
                        )
                    )
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


def _add_input_source(
    owner_key: str,
    name: str,
    rel: str,
    line_no: int,
    nodes: list[Node],
    edges: list[Edge],
    route: str = "",
) -> str:
    input_key = f"{owner_key}::input:{name}:{line_no}"
    nodes.append(
        Node(
            "Input",
            input_key,
            name,
            rel,
            line_no,
            line_no,
            {"source": "request", "route": route, "user_controlled": True},
        )
    )
    edges.append(Edge(EDGE_READS_INPUT, owner_key, input_key, rel, line_no))
    return input_key


def _line_input_source(
    owner_key: str,
    lowered_line: str,
    rel: str,
    line_no: int,
    nodes: list[Node],
    edges: list[Edge],
) -> str:
    if not any(marker in lowered_line for marker in INPUT_MARKERS):
        return ""
    return _add_input_source(owner_key, "request", rel, line_no, nodes, edges)


def _assigned_name(line: str) -> str:
    match = ASSIGN_RE.search(line)
    return match.group("name") if match else ""


def _tainted_source_for_line(line: str, tainted: dict[str, str]) -> str:
    for name, key in tainted.items():
        if re.search(rf"\b{re.escape(name)}\b", line):
            return key
    return ""


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


def _is_secret_exposure(call_name: str) -> bool:
    lowered = call_name.lower()
    return any(sink in lowered for sink in SECRET_EXPOSURE_SINKS)

"""Lightweight JavaScript and TypeScript security analyzer."""

from __future__ import annotations

import re
from pathlib import Path

from cybergraph.analysis._source_text import strip_code
from cybergraph.graph import Edge, Finding, Node
from cybergraph.security.ontology import (
    EDGE_EXPOSES_ENTRYPOINT,
    EDGE_EXPOSES_SECRET,
    EDGE_FLOWS_TO,
    EDGE_IMPORTS,
    EDGE_REACHES_SINK,
    EDGE_READS_INPUT,
    EDGE_TAINTS,
    EDGE_USES_SECRET,
)
from cybergraph.suppressions import is_inline_suppressed

FUNCTION_RE = re.compile(
    r"(?:export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\(|"
    r"(?:const|let|var)\s+(?P<var>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"
)
ROUTE_RE = re.compile(
    r"(?P<router>\b(?:app|router|server)\s*\.\s*(?:get|post|put|patch|delete|all|use))"
    r"\s*\(\s*['\"](?P<path>[^'\"]+)['\"]"
)
ROUTE_HANDLER_RE = re.compile(
    r"\b(?:app|router|server)\s*\.\s*(?:get|post|put|patch|delete|all|use)"
    r"\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(?P<handler>[A-Za-z_$][\w$]*)\b"
)
NEXT_EXPORT_RE = re.compile(
    r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\s*\("
)
CALL_RE = re.compile(r"(?P<name>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")
IMPORT_RE = re.compile(
    r"""(?:import\b[^'"]*?from\s*|import\s*|require\s*\(\s*)['"](?P<mod>[^'"]+)['"]"""
)
ASSIGN_RE = re.compile(
    r"\b(?:const|let|var)?\s*(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>[^;]+)"
)

SINK_CALLS = {
    "db.query",
    "client.query",
    "connection.query",
    "pool.query",
    "exec",
    "child_process.exec",
    "eval",
    "fs.writeFile",
    "fs.readFile",
    "res.render",
}
SECRET_MARKERS = {"process.env", "secret", "password", "token", "api_key", "apikey"}
INPUT_MARKERS = {
    "req.query",
    "req.body",
    "req.params",
    "req.headers",
    "request.query",
    "request.body",
}
SECRET_EXPOSURE_SINKS = {
    "console.log",
    "logger.info",
    "logger.warn",
    "logger.error",
    "res.send",
    "res.json",
    "response.send",
    "fetch",
    "axios.post",
    "child_process.exec",
}

_CORS_CALL_RE = re.compile(r"\bcors\s*\(\s*\{")
_ORIGIN_ALL_RE = re.compile(r"""origin\s*:\s*(?:['"]\*['"]|true)""")
_CREDENTIALS_TRUE_RE = re.compile(r"credentials\s*:\s*true")
_NEXT_PUBLIC_RE = re.compile(r"NEXT_PUBLIC_[A-Za-z0-9_]+")
_STRONG_SECRET_SEGMENTS = {
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PRIVATE",
    "CREDENTIAL",
    "CREDENTIALS",
}
_KEYLIKE_SEGMENTS = {"KEY", "APIKEY"}
_PUBLIC_MARKER_SEGMENTS = {"PUBLIC", "PUBLISHABLE"}


def _next_public_is_secret(name: str) -> bool:
    # name like "NEXT_PUBLIC_STRIPE_SECRET_KEY" -> segments after the prefix.
    # A strong secret segment always flags. A key-like segment only flags when
    # the name has no public-by-design marker (e.g. Stripe publishable keys are
    # meant to ship to the browser and should not false-flag). The NEXT_PUBLIC_
    # prefix itself is stripped first so its own literal "PUBLIC" segment can't
    # be mistaken for an explicit public-by-design marker on the suffix.
    upper = name.upper()
    suffix = upper[len("NEXT_PUBLIC_"):] if upper.startswith("NEXT_PUBLIC_") else upper
    segments = set(suffix.split("_"))
    if _STRONG_SECRET_SEGMENTS & segments:
        return True
    if _KEYLIKE_SEGMENTS & segments and not (_PUBLIC_MARKER_SEGMENTS & segments):
        return True
    return False


def analyze_javascript_file(
    path: Path,
    repo_root: Path,
    custom_sinks: tuple[str, ...] = (),
    secret_markers: tuple[str, ...] = (),
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    rel = path.relative_to(repo_root).as_posix()
    lines = source.splitlines()
    # Code view with comments and string literals blanked (template interpolation
    # holes kept as code), aligned 1:1 with `lines`, so an input marker in a
    # comment or a string cannot fabricate a taint source.
    code_lines = strip_code(source, "javascript")
    nodes: list[Node] = [Node("File", rel, rel, rel, 1, len(lines), {"language": _language(path)})]
    edges: list[Edge] = []
    findings: list[Finding] = []

    functions = _function_lines(lines)
    for name, line_no in functions:
        key = f"{rel}::{name}"
        nodes.append(Node("Function", key, name, rel, line_no, line_no, _classify_js_name(name)))

    current_function: str | None = None
    tainted_by_function: dict[str, dict[str, str]] = {}
    for line_no, line in enumerate(lines, start=1):
        fn_match = FUNCTION_RE.search(line)
        if fn_match:
            current_function = f"{rel}::{fn_match.group('name') or fn_match.group('var')}"
            tainted_by_function.setdefault(current_function, {})

        route_match = ROUTE_RE.search(line)
        if route_match:
            key = f"{rel}::route:{route_match.group('path')}:{line_no}"
            nodes.append(
                Node(
                    "Entrypoint",
                    key,
                    route_match.group("path"),
                    rel,
                    line_no,
                    line_no,
                    {"framework": "express", "method": route_match.group("router").split(".")[-1]},
                )
            )
            edges.append(Edge(EDGE_EXPOSES_ENTRYPOINT, rel, key, rel, line_no))
            _add_input_source(key, "request", rel, line_no, nodes, edges, route_match.group("path"))
            handler = _route_handler_name(line)
            if handler:
                edges.append(Edge("CALLS", key, handler, rel, line_no, {"via": "express-route"}))

        if NEXT_EXPORT_RE.search(line):
            method = NEXT_EXPORT_RE.search(line).group(1)
            key = f"{rel}::route:{method}:{line_no}"
            nodes.append(
                Node(
                    "Entrypoint",
                    key,
                    key.rsplit(":", 2)[1],
                    rel,
                    line_no,
                    line_no,
                    {"framework": "nextjs"},
                )
            )
            edges.append(Edge(EDGE_EXPOSES_ENTRYPOINT, rel, key, rel, line_no))
            _add_input_source(key, "request", rel, line_no, nodes, edges, method)

        sink_source = current_function or rel
        tainted = tainted_by_function.setdefault(sink_source, {})
        code_line = code_lines[line_no - 1] if line_no - 1 < len(code_lines) else line
        input_key = _line_input_source(sink_source, code_line, rel, line_no, nodes, edges)
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
        if any(marker in line.lower() for marker in SECRET_MARKERS):
            edges.append(Edge(EDGE_USES_SECRET, sink_source, "secret", rel, line_no))

        for call in CALL_RE.finditer(line):
            call_name = call.group("name")
            if _is_declaration_call(line, call.start()):
                continue
            edges.append(Edge("CALLS", sink_source, call_name, rel, line_no))
            if _is_sink(call_name, custom_sinks):
                edges.append(Edge(EDGE_REACHES_SINK, sink_source, call_name, rel, line_no))
                if not is_inline_suppressed(lines, line_no, "CG-JS-SINK-CALL"):
                    findings.append(
                        Finding(
                            rule_id="CG-JS-SINK-CALL",
                            severity="medium",
                            message=(
                                "JavaScript/TypeScript file reaches sensitive sink "
                                f"`{call_name}`"
                            ),
                            file_path=rel,
                            line_start=line_no,
                            cwe="CWE-20",
                            evidence=line.strip(),
                        )
                    )
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
            if any(marker in line.lower() for marker in SECRET_MARKERS | set(secret_markers)):
                edges.append(Edge(EDGE_USES_SECRET, sink_source, call_name, rel, line_no))
                if _is_secret_exposure(call_name):
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

    _add_imports(lines, rel, edges)
    _add_js_web_findings(source, lines, rel, findings)
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
    line: str,
    rel: str,
    line_no: int,
    nodes: list[Node],
    edges: list[Edge],
) -> str:
    lowered = line.lower()
    if not any(marker in lowered for marker in INPUT_MARKERS):
        return ""
    return _add_input_source(owner_key, "request", rel, line_no, nodes, edges)


def _assigned_name(line: str) -> str:
    match = ASSIGN_RE.search(line)
    if not match:
        return ""
    expr = match.group("expr")
    if "=>" in expr or "function" in expr:
        return ""
    return match.group("name")


def _tainted_source_for_line(line: str, tainted: dict[str, str]) -> str:
    for name, key in tainted.items():
        if re.search(rf"\b{re.escape(name)}\b", line):
            return key
    return ""


def _add_imports(lines: list[str], rel: str, edges: list[Edge]) -> None:
    """Emit ``IMPORTS`` edges (File -> package name) for ES imports and require().

    Bare specifiers map to their package: ``lodash/fp`` -> ``lodash`` and a scoped
    ``@scope/pkg/sub`` -> ``@scope/pkg``. Relative imports (``./x``, ``../x``, ``/x``)
    are local and skipped. A later pass links these to declared Dependency nodes for
    reachability-based SCA."""
    seen: set[str] = set()
    for line_no, line in enumerate(lines, start=1):
        for match in IMPORT_RE.finditer(line):
            package = _package_specifier(match.group("mod"))
            if package and package not in seen:
                seen.add(package)
                edges.append(Edge(EDGE_IMPORTS, rel, package, rel, line_no))


def _package_specifier(raw: str) -> str:
    """Reduce an import specifier to its installable package name (or '' if local)."""
    spec = raw.strip()
    if not spec or spec.startswith(".") or spec.startswith("/"):
        return ""
    parts = spec.split("/")
    if spec.startswith("@") and len(parts) >= 2:  # scoped: @scope/pkg
        return "/".join(parts[:2])
    return parts[0]


def _function_lines(lines: list[str]) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for line_no, line in enumerate(lines, start=1):
        match = FUNCTION_RE.search(line)
        if match:
            found.append((match.group("name") or match.group("var"), line_no))
    return found


def _route_handler_name(line: str) -> str:
    match = ROUTE_HANDLER_RE.search(line)
    if not match:
        return ""
    handler = match.group("handler")
    return "" if handler in {"async", "function"} else handler


def _is_declaration_call(line: str, start: int) -> bool:
    prefix = line[:start].strip()
    return prefix.endswith("function") or prefix.endswith("function*")


def _classify_js_name(name: str) -> dict[str, bool]:
    lowered = name.lower()
    return {
        "auth_related": "auth" in lowered or "login" in lowered,
        "authorization_related": "permission" in lowered or "role" in lowered,
        "validation_related": "validate" in lowered or "sanitize" in lowered,
        "secret_related": "secret" in lowered or "token" in lowered or "password" in lowered,
        "crypto_related": "hash" in lowered or "encrypt" in lowered or "sign" in lowered,
        "sink_related": "query" in lowered or "exec" in lowered,
    }


def _is_sink(call_name: str, custom_sinks: tuple[str, ...] = ()) -> bool:
    lowered = call_name.lower()
    return any(sink.lower() in lowered for sink in SINK_CALLS | set(custom_sinks))


def _is_secret_exposure(call_name: str) -> bool:
    lowered = call_name.lower()
    return any(sink in lowered for sink in SECRET_EXPOSURE_SINKS)


def _language(path: Path) -> str:
    return "typescript" if path.suffix.lower() in {".ts", ".tsx"} else "javascript"


def _brace_object(source: str, open_index: int) -> tuple[str, int]:
    """From the '{' at open_index, return (object_text, end_index) at its match.

    String-literal-aware: braces inside quoted strings (single, double, or
    backtick, with backslash escapes) do not affect the depth count.
    """
    depth = 0
    quote: str | None = None
    i = open_index
    while i < len(source):
        c = source[i]
        if quote is not None:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[open_index : i + 1], i
        i += 1
    return source[open_index:], len(source)


def _line_of(source: str, index: int) -> int:
    return source.count("\n", 0, index) + 1


def _add_js_web_findings(
    source: str, lines: list[str], rel: str, findings: list[Finding]
) -> None:
    # CORS: cors({ ... origin:*/true ... credentials:true ... })
    for m in _CORS_CALL_RE.finditer(source):
        obj, _end = _brace_object(source, m.end() - 1)
        if _ORIGIN_ALL_RE.search(obj) and _CREDENTIALS_TRUE_RE.search(obj):
            line_no = _line_of(source, m.start())
            if is_inline_suppressed(lines, line_no, "CG-CORS-CREDENTIALED-WILDCARD"):
                continue
            findings.append(
                Finding(
                    rule_id="CG-CORS-CREDENTIALED-WILDCARD",
                    severity="high",
                    message="CORS allows any origin with credentials "
                            "(origin '*'/true + credentials: true)",
                    file_path=rel,
                    line_start=line_no,
                    cwe="CWE-942",
                    evidence=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "",
                )
            )
    # Next.js: a NEXT_PUBLIC_ name that looks like a secret -> inlined into the bundle.
    seen: set[int] = set()
    for m in _NEXT_PUBLIC_RE.finditer(source):
        if not _next_public_is_secret(m.group(0)):
            continue
        line_no = _line_of(source, m.start())
        if line_no in seen:
            continue
        seen.add(line_no)
        if is_inline_suppressed(lines, line_no, "CG-CLIENT-SECRET-EXPOSED"):
            continue
        findings.append(
            Finding(
                rule_id="CG-CLIENT-SECRET-EXPOSED",
                severity="high",
                message=f"`{m.group(0)}` ships a secret to the browser bundle "
                        "(NEXT_PUBLIC_ is inlined client-side)",
                file_path=rel,
                line_start=line_no,
                cwe="CWE-200",
                evidence=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "",
            )
        )

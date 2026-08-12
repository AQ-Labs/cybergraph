"""Lightweight C# (ASP.NET Core) security analyzer.

Regex-based, mirroring the Java/Go analyzers. Recognises attribute-routed
controllers ([HttpGet], [Route]) and minimal-API route registrations
(app.MapGet), common ADO.NET / process / filesystem sinks, and secret access
via Environment.GetEnvironmentVariable or IConfiguration indexers.
"""

from __future__ import annotations

import re
from pathlib import Path

from cybergraph.analysis._source_text import strip_code
from cybergraph.analysis.csharp_provenance import (
    assess,
    assess_command,
    assess_deserialization,
    extract_all_args,
    extract_first_arg,
)
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
from cybergraph.security.predicates import VERDICT_SAFE, VERDICT_UNSAFE
from cybergraph.security.sinks import lookup_sink
from cybergraph.suppressions import is_inline_suppressed

METHOD_RE = re.compile(
    r"\b(?:public|private|protected|internal)\s+(?:static\s+|async\s+|virtual\s+|override\s+)*"
    r"[\w<>\[\],.\s]+?\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{]*\)\s*\{"
)
METHOD_PARAMS_RE = re.compile(r"\((?P<params>[^)]*)\)")
# Matches a sink call the general dotted CALL_RE misses: a constructor `new
# Ctor(` or a method call `.method(` (including one that follows a `)` in a
# chain). Run over the whole `source` (not per-line) so a chained call after a
# `)` is still found.
_CSHARP_SINK_CALL_RE = re.compile(
    r"\bnew\s+(?P<ctor>[A-Z]\w*)\s*\(|\.(?P<method>[A-Za-z_]\w*)\s*\("
)
ATTR_ROUTE_RE = re.compile(
    r"\[(?:Http(?P<verb>Get|Post|Put|Patch|Delete)|Route)\s*(?:\(\s*\"(?P<path>[^\"]*)\")?"
)
MINIMAL_API_RE = re.compile(
    r"\bapp\.Map(?P<verb>Get|Post|Put|Patch|Delete)\s*\(\s*\"(?P<path>[^\"]+)\""
)
CALL_RE = re.compile(r"(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*\(")
ASSIGN_RE = re.compile(
    r"\b(?:var|string|int|long|bool|Path|FileInfo|[\w<>]+)"
    r"\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<expr>.+)"
)

SINK_CALLS = {
    "executereader", "executenonquery", "executescalar",
    "process.start", "file.writealltext", "file.readalltext", "file.delete",
    "file.open", "streamwriter", "streamreader",
}
SECRET_MARKERS = {
    "environment.getenvironmentvariable", "configuration[", "_configuration[",
    "secret", "password", "token", "apikey", "api_key",
}
INPUT_MARKERS = {
    "request.query", "request.form", "request.headers", "request.body",
    "fromquery", "frombody", "fromroute",
}
SECRET_EXPOSURE_SINKS = {
    "console.writeline",
    "logger.loginformation",
    "logger.logwarning",
    "logger.logerror",
    "response.writeasync",
    "httpclient.postasync",
    "process.start",
}


def analyze_csharp_file(
    path: Path,
    repo_root: Path,
    custom_sinks: tuple[str, ...] = (),
    secret_markers: tuple[str, ...] = (),
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()
    # Code view with comments and string literals (incl. @"verbatim") blanked,
    # aligned 1:1 with `lines`; $"interpolated" holes are kept as code so a real
    # source inside them survives. An input marker in a comment or a string can
    # no longer fabricate a taint source.
    code_lines = strip_code(source, "csharp")
    rel = path.relative_to(repo_root).as_posix()
    nodes: list[Node] = [Node("File", rel, rel, rel, 1, len(lines), {"language": "csharp"})]
    edges: list[Edge] = []
    findings: list[Finding] = []

    pending_route: dict | None = None
    current_function: str | None = None
    tainted_by_function: dict[str, dict[str, str]] = {}
    # The owning function key (or `rel` at file scope) for each 1-based line,
    # recorded as the main loop attributes sinks/taint to `sink_source` --
    # reused by the second-pass sink-call matcher below so a call the general
    # `CALL_RE` cannot see (a constructor, or a chained call after `)`) is
    # still attributed to the right function and taint set.
    line_owner: list[str] = []
    for line_no, line in enumerate(lines, start=1):
        attr_match = ATTR_ROUTE_RE.search(line)
        if attr_match:
            pending_route = {
                "path": attr_match.group("path") or "/",
                "method": (attr_match.group("verb") or "ANY").upper(),
                "line": line_no,
            }

        minimal_match = MINIMAL_API_RE.search(line)
        if minimal_match:
            route_key = f"{rel}::route:{minimal_match.group('path')}:{line_no}"
            nodes.append(
                Node(
                    "Entrypoint", route_key, minimal_match.group("path"), rel, line_no, line_no,
                    {"framework": "aspnet-minimal", "method": minimal_match.group("verb").upper()},
                )
            )
            edges.append(Edge(EDGE_EXPOSES_ENTRYPOINT, rel, route_key, rel, line_no))

        method_match = METHOD_RE.search(line)
        if method_match:
            name = method_match.group("name")
            key = f"{rel}::{name}"
            current_function = key
            tainted_by_function.setdefault(current_function, {})
            nodes.append(
                Node("Function", key, name, rel, line_no, line_no, _classify_csharp_name(name))
            )
            if pending_route is not None:
                route_key = f"{rel}::route:{pending_route['path']}:{pending_route['line']}"
                nodes.append(
                    Node(
                        "Entrypoint", route_key, pending_route["path"], rel,
                        pending_route["line"], pending_route["line"],
                        {"framework": "aspnet", "method": pending_route["method"]},
                    )
                )
                edges.append(
                    Edge(EDGE_EXPOSES_ENTRYPOINT, rel, route_key, rel, pending_route["line"])
                )
                edges.append(Edge("CALLS", route_key, name, rel, line_no))
                _add_route_params(
                    key, line, rel, line_no, pending_route["path"],
                    nodes, edges, tainted_by_function[key],
                )
                pending_route = None

        sink_source = current_function or rel
        line_owner.append(sink_source)
        tainted = tainted_by_function.setdefault(sink_source, {})
        lowered_line = line.lower()
        code_line = code_lines[line_no - 1] if line_no - 1 < len(code_lines) else line
        input_key = _line_input_source(sink_source, code_line.lower(), rel, line_no, nodes, edges)
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
            # A call_name whose bare tail resolves to a registered sink is graded
            # by the dedicated matcher/second pass below instead -- skip it here
            # so the same sink never double-emits (once as this legacy inventory
            # finding, once as a graded verdict).
            if _is_sink(call_name, custom_sinks) and lookup_sink(call_name, "csharp") is None:
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
                if not is_inline_suppressed(lines, line_no, "CG-CSHARP-SINK-CALL"):
                    findings.append(
                        Finding(
                            rule_id="CG-CSHARP-SINK-CALL",
                            severity="medium",
                            message=f"C# file reaches sensitive sink `{call_name}`",
                            file_path=rel,
                            line_start=line_no,
                            cwe="CWE-20",
                            evidence=line.strip(),
                        )
                    )

    _grade_csharp_sinks(source, lines, rel, line_owner, tainted_by_function, edges, findings)
    return nodes, edges, findings


def _add_route_params(
    function_key: str,
    signature_line: str,
    rel: str,
    line_no: int,
    route: str,
    nodes: list[Node],
    edges: list[Edge],
    tainted: dict[str, str],
) -> None:
    match = METHOD_PARAMS_RE.search(signature_line)
    if not match:
        return
    for raw_param in match.group("params").split(","):
        param = raw_param.strip()
        if not param:
            continue
        parts = re.findall(r"[A-Za-z_]\w*", param)
        if not parts:
            continue
        name = parts[-1]
        input_key = f"{function_key}::input:{name}"
        nodes.append(
            Node(
                "Input",
                input_key,
                name,
                rel,
                line_no,
                line_no,
                {"source": "parameter", "route": route, "user_controlled": True},
            )
        )
        edges.append(Edge(EDGE_READS_INPUT, function_key, input_key, rel, line_no))
        edges.append(
            Edge(
                EDGE_TAINTS, input_key, function_key, rel, line_no,
                {"reason": "route parameter"},
            )
        )
        tainted[name] = input_key


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
    input_key = f"{owner_key}::input:request:{line_no}"
    nodes.append(
        Node(
            "Input", input_key, "request", rel, line_no, line_no,
            {"source": "request", "user_controlled": True},
        )
    )
    edges.append(Edge(EDGE_READS_INPUT, owner_key, input_key, rel, line_no))
    return input_key


def _assigned_name(line: str) -> str:
    match = ASSIGN_RE.search(line)
    return match.group("name") if match else ""


def _tainted_source_for_line(line: str, tainted: dict[str, str]) -> str:
    for name, key in tainted.items():
        if re.search(rf"\b{re.escape(name)}\b", line):
            return key
    return ""


def _grade_csharp_sinks(
    source: str,
    lines: list[str],
    rel: str,
    line_owner: list[str],
    tainted_by_function: dict[str, dict[str, str]],
    edges: list[Edge],
    findings: list[Finding],
) -> None:
    """Second pass: grade every sink `_CSHARP_SINK_CALL_RE`/`CALL_RE` finds into a
    real verdict.

    Matching runs over `code` -- `strip_code(source, "csharp")` rejoined, so
    every comment AND every string literal (except a live interpolation hole)
    is blanked -- so a commented-out sink call is invisible here, never graded
    as live, and a call-shaped fragment sitting inside a string literal cannot
    be mistaken for a real one. `code` is exactly as long as `source` (each
    input character maps to exactly one output character, and `source` was
    already read with universal newlines, so a `"\\n".join` of the split lines
    reproduces `source` verbatim short of a possible single trailing
    newline) -- so `line_no`/`open_paren` computed against it are equally
    valid used against `source`.

    Argument extraction, though, runs against RAW `source`, not `code`: `code`
    blanks a plain/interpolated string's own quotes and literal text (keeping
    only an interpolation hole's expression live), which is exactly the
    content `classify`/`assess` need to tell LITERAL from COMPOSED -- grading
    off `code` would see a proven-literal query as an empty, unreadable
    argument and misreport it as UNKNOWN. Position alignment with `code` makes
    this safe: `open_paren` in `code` is also `open_paren` in `source`.

    `_CSHARP_SINK_CALL_RE` catches a constructor (`new SqlCommand(...)`) or a
    bare `.method(` the dotted `CALL_RE` misses; `CALL_RE` is ALSO run here
    (in addition to its per-line use above) so a fully-qualified code-exec
    name (`Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript.EvaluateAsync`)
    still resolves -- `lookup_sink` only exact-matches a NON-bare sink's full
    name (`CSharpScript.EvaluateAsync`, not the whole namespace chain), so the
    last two dotted segments are tried too. Both regexes can match the SAME
    physical call (e.g. `.Start(` via one, the fully dotted `Process.Start` via
    the other); `candidates` is keyed by `open_paren` so each call is graded
    exactly once.
    """
    code = "\n".join(strip_code(source, "csharp"))

    candidates: dict[int, tuple[str, object]] = {}
    for call in _CSHARP_SINK_CALL_RE.finditer(code):
        name = call.group("ctor") or call.group("method")
        sink = lookup_sink(name, "csharp")
        if sink is not None:
            candidates.setdefault(call.end() - 1, (name, sink))
    for call in CALL_RE.finditer(code):
        call_name = call.group("name")
        sink = lookup_sink(call_name, "csharp")
        if sink is None:
            tail2 = ".".join(call_name.split(".")[-2:])
            sink = lookup_sink(tail2, "csharp")
        if sink is not None:
            candidates.setdefault(call.end() - 1, (call_name, sink))

    for open_paren in sorted(candidates):
        name, sink = candidates[open_paren]
        line_no = code.count("\n", 0, open_paren) + 1
        owner = line_owner[line_no - 1] if 0 < line_no <= len(line_owner) else rel
        tainted_map = tainted_by_function.get(owner, {})
        line_text = lines[line_no - 1] if 0 < line_no <= len(lines) else ""

        # Zero-argument guard: `cmd.ExecuteReader()`/`ProcessStartInfo.Start()`
        # have empty parens and are not a string-injection sink call -- the
        # query/command lives elsewhere (`new SqlCommand("...", conn)` / a
        # separately-constructed `ProcessStartInfo`), matched and assessed
        # separately. Deserialization is exempt: `.Deserialize(stream)` is the
        # normal, always-one-argument form, so it must always be graded. An
        # unbalanced/unreadable arg list is NOT genuinely empty and must still
        # be assessed as unknown, not skipped.
        if sink.vuln_class != "deserialize" and _call_is_empty(code, open_paren) is True:
            continue

        edges.append(Edge(EDGE_REACHES_SINK, owner, name, rel, line_no))
        taint_key = _tainted_source_for_line(line_text, tainted_map)
        if taint_key:
            edges.append(
                Edge(
                    EDGE_TAINTS, taint_key, name, rel, line_no,
                    {"function": owner, "reason": "tainted argument"},
                )
            )

        tainted_names = set(tainted_map)
        if sink.vuln_class == "deserialize":
            verdict = assess_deserialization(bool(taint_key))
        elif sink.vuln_class == "command":
            verdict = assess_command(extract_all_args(source, open_paren), tainted_names)
        else:  # sql / path / code
            verdict = assess(sink, extract_first_arg(source, open_paren), tainted_names)

        finding = _csharp_verdict_finding(sink, verdict, rel, line_no, line_text)
        if finding is not None and not is_inline_suppressed(lines, line_no, finding.rule_id):
            findings.append(finding)


def _call_is_empty(source: str, open_paren: int) -> bool | None:
    """True for a genuinely empty `()`, False if it has content, None if unbalanced.

    Quote/bracket-aware, mirroring `extract_first_arg`'s scan -- so a `)`/`,`
    inside a nested string literal never mistakenly closes the call early.
    `None` (unbalanced) is deliberately distinct from `True`: the zero-arg
    guard must only fire on a call *proven* to take no arguments, never on one
    that merely could not be read.
    """
    depth = 0
    quote: str | None = None
    i = open_paren
    while i < len(source):
        c = source[i]
        if quote is not None:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return not source[open_paren + 1 : i].strip()
        i += 1
    return None


def _csharp_verdict_finding(
    sink, verdict: str, rel: str, line_no: int, line: str
) -> Finding | None:
    if verdict == VERDICT_SAFE:
        return None
    unsafe = verdict == VERDICT_UNSAFE
    return Finding(
        rule_id=sink.rule_id if unsafe else f"{sink.rule_id}-UNVERIFIED",
        severity=sink.severity if unsafe else "medium",
        message=(f"`{sink.name}` {sink.plain}" if unsafe
                 else f"`{sink.name}` {sink.plain}, and CyberGraph could not confirm "
                      "the value is safe"),
        file_path=rel,
        line_start=line_no,
        cwe=sink.cwe,
        evidence=line.strip(),
    )


def _classify_csharp_name(name: str) -> dict[str, bool]:
    lowered = name.lower()
    return {
        "auth_related": "auth" in lowered or "login" in lowered,
        "authorization_related": "permission" in lowered or "role" in lowered or "admin" in lowered,
        "validation_related": "validate" in lowered or "sanitize" in lowered or "clean" in lowered,
        "secret_related": "secret" in lowered or "token" in lowered or "password" in lowered,
        "crypto_related": "hash" in lowered or "encrypt" in lowered or "sign" in lowered,
        "sink_related": "query" in lowered or "command" in lowered,
    }


def _is_sink(call_name: str, custom_sinks: tuple[str, ...] = ()) -> bool:
    lowered = call_name.lower()
    return any(sink in lowered for sink in SINK_CALLS) or any(
        sink.lower() in lowered for sink in custom_sinks
    )


def _is_secret_exposure(call_name: str) -> bool:
    lowered = call_name.lower()
    return any(sink in lowered for sink in SECRET_EXPOSURE_SINKS)

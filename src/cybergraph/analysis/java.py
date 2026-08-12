"""Lightweight Java (Spring Boot) security analyzer.

Regex-based, mirroring the Go and JavaScript analyzers. Recognises Spring MVC
route annotations, common JDBC / command / filesystem sinks, and secret access
via System.getenv or @Value placeholders. Unrecognised constructs are ignored
so the file always yields a valid File node.
"""

from __future__ import annotations

import re
from pathlib import Path

from cybergraph.analysis._source_text import strip_code
from cybergraph.analysis.java_provenance import (
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

# Method declarations: optional annotations are matched separately; this matches
# `public List<User> listUsers(...)` style signatures (not control-flow keywords).
METHOD_RE = re.compile(
    r"\b(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?"
    r"[\w<>\[\],.\s]+?\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{]*\)\s*(?:throws[\w,\s]+)?\{"
)
METHOD_PARAMS_RE = re.compile(r"\((?P<params>[^)]*)\)")
SPRING_ROUTE_RE = re.compile(
    r"@(?:(?P<verb>Get|Post|Put|Patch|Delete)Mapping|RequestMapping)"
    r"\s*(?:\(\s*(?:value\s*=\s*)?\"(?P<path>[^\"]*)\")?"
)
CALL_RE = re.compile(r"(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*\(")
# Matches a sink call the general CALL_RE misses: a constructor `new Ctor(` or a
# method call `.method(` (including one that follows a `)` in a chain). Run over
# the whole `source` (not per-line) so a chained call after a `)` is still found.
_JAVA_SINK_CALL_RE = re.compile(r"\bnew\s+(?P<ctor>[A-Z]\w*)\s*\(|\.(?P<method>[A-Za-z_]\w*)\s*\(")
ASSIGN_RE = re.compile(
    r"\b(?:final\s+)?(?:var|String|int|long|boolean|Path|File|[\w<>]+)"
    r"\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<expr>.+)"
)

SINK_CALLS = {
    "executequery", "executeupdate", "statement.execute",
    "jdbctemplate.query", "jdbctemplate.update",
    "createnativequery", "createquery",
    "getruntime", "runtime.exec", "processbuilder", "process.start",
    "files.write", "files.readallbytes", "filewriter", "filereader", "fileinputstream",
}
SECRET_MARKERS = {"system.getenv", "@value", "secret", "password", "token", "apikey", "api_key"}
INPUT_MARKERS = {
    "getparameter", "@requestparam", "@pathvariable", "request.getheader",
    "request.getinputstream",
}
SECRET_EXPOSURE_SINKS = {
    "system.out.print",
    "logger.info",
    "logger.warn",
    "logger.error",
    "response.getwriter",
    "httpclient.execute",
    "resttemplate.postfor",
    "runtime.exec",
}


def analyze_java_file(
    path: Path,
    repo_root: Path,
    custom_sinks: tuple[str, ...] = (),
    secret_markers: tuple[str, ...] = (),
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()
    # Code view with comments and string literals (incl. """text blocks""")
    # blanked, aligned 1:1 with `lines`, so an input marker in a comment or a
    # string cannot fabricate a taint source.
    code_lines = strip_code(source, "java")
    rel = path.relative_to(repo_root).as_posix()
    nodes: list[Node] = [Node("File", rel, rel, rel, 1, len(lines), {"language": "java"})]
    edges: list[Edge] = []
    findings: list[Finding] = []

    pending_route: dict | None = None
    current_function: str | None = None
    tainted_by_function: dict[str, dict[str, str]] = {}
    # The owning function key (or `rel` at file scope) for each 1-based line,
    # recorded as the main loop attributes sinks/taint to `sink_source` -- reused
    # by the second-pass sink-call matcher below so a call the general `CALL_RE`
    # cannot see (a constructor, or a chained call after `)`) is still attributed
    # to the right function and taint set.
    line_owner: list[str] = []
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
            tainted_by_function.setdefault(current_function, {})
            nodes.append(
                Node("Function", key, name, rel, line_no, line_no, _classify_java_name(name))
            )
            if pending_route is not None:
                route_key = f"{rel}::route:{pending_route['path']}:{pending_route['line']}"
                nodes.append(
                    Node(
                        "Entrypoint", route_key, pending_route["path"], rel,
                        pending_route["line"], pending_route["line"],
                        {"framework": "spring", "method": pending_route["method"]},
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
            if _is_sink(call_name, custom_sinks) and lookup_sink(call_name, "java") is None:
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

    _grade_java_sinks(source, lines, rel, line_owner, tainted_by_function, edges, findings)
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


def _grade_java_sinks(
    source: str,
    lines: list[str],
    rel: str,
    line_owner: list[str],
    tainted_by_function: dict[str, dict[str, str]],
    edges: list[Edge],
    findings: list[Finding],
) -> None:
    """Second pass: grade every sink `_JAVA_SINK_CALL_RE` finds into a real verdict.

    Runs over the whole `source` (not per-line) so a constructor (`new File(...)`)
    or a chained call after a `)` (`Runtime.getRuntime().exec(...)`) -- both
    invisible to `CALL_RE` -- is still located. Taint is fully known by the time
    this runs, so each match's line is mapped to its owning function via
    `line_owner` (built by the main per-line loop) rather than re-tracking
    `current_function`.

    Matches, the zero-arg check, and argument extraction all run against
    `code` -- `source` with `//`/`/* */` comments blanked (string/char literals
    left untouched) -- not raw `source`, so a commented-out sink call is
    invisible here and never graded as live. `code` is exactly as long as
    `source` (comment text becomes spaces, line boundaries are kept), so every
    offset computed against it -- `line_no`, `open_paren` -- is equally valid
    used against `source`; nothing needs translating.
    """
    code = _blank_java_comments(source)
    for call in _JAVA_SINK_CALL_RE.finditer(code):
        name = call.group("ctor") or call.group("method")
        sink = lookup_sink(name, "java")
        if sink is None:
            continue  # not a registered sink -- left to the legacy inventory scan
        line_no = code.count("\n", 0, call.start()) + 1
        open_paren = call.end() - 1
        owner = line_owner[line_no - 1] if 0 < line_no <= len(line_owner) else rel
        tainted_map = tainted_by_function.get(owner, {})
        line_text = lines[line_no - 1] if 0 < line_no <= len(lines) else ""

        # Zero-argument guard: `ps.executeQuery()`/`pb.start()` have empty parens
        # and are not a string-injection sink call -- the query/command lives
        # elsewhere (`prepareStatement("...")` / `new ProcessBuilder(...)`),
        # matched and assessed separately. Deserialization is exempt:
        # `readObject()`/`readUnshared()` are zero-argument by nature. An
        # unbalanced/unreadable arg list is NOT genuinely empty and must still
        # be assessed as unknown, not skipped. Checked against `code` too, so a
        # call with only a comment between its parens (`executeQuery(/* n/a */)`)
        # reads as empty rather than as an opaque, unreadable argument.
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

        if sink.vuln_class == "deserialize":
            verdict = assess_deserialization(bool(taint_key))
        elif sink.vuln_class == "command":
            verdict = assess_command(extract_all_args(code, open_paren), set(tainted_map))
        else:  # sql / path
            verdict = assess(sink, extract_first_arg(code, open_paren), set(tainted_map))

        finding = _java_verdict_finding(sink, verdict, rel, line_no, line_text)
        if finding is not None and not is_inline_suppressed(lines, line_no, finding.rule_id):
            findings.append(finding)


def _blank_java_comments(source: str) -> str:
    """Blank `//` and `/* */` comments; leave everything else -- including every
    string/char literal -- untouched, character-for-character.

    A commented-out sink call must not be graded as live (a `//`/`/* */`'d out
    `new File(tainted)` is dead code), but a REAL sink's string-literal argument
    must survive completely intact for `extract_first_arg`/`assess` to classify
    -- so, unlike `strip_code` (which also blanks string literals, for a
    different consumer), this only ever blanks comment text. Quote-aware so a
    `//`/`/*` inside a string or char literal (`"http://x"`) is never mistaken
    for a comment opener; escape-aware so `'\\''` does not end a char literal
    early. Same length as `source`, with line boundaries preserved, so a
    position computed against the result is equally valid against `source`.
    """
    out: list[str] = []
    quote: str | None = None
    i = 0
    n = len(source)
    while i < n:
        c = source[i]
        if quote is not None:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(source[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "\"'":
            quote = c
            out.append(c)
            i += 1
            continue
        if source.startswith("//", i):
            j = i
            while j < n and source[j] not in "\n\r":
                out.append(" ")
                j += 1
            i = j
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = n if end == -1 else end + 2
            for k in range(i, end):
                out.append(source[k] if source[k] in "\n\r" else " ")
            i = end
            continue
        out.append(c)
        i += 1
    return "".join(out)


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


def _java_verdict_finding(sink, verdict: str, rel: str, line_no: int, line: str) -> Finding | None:
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


def _is_secret_exposure(call_name: str) -> bool:
    lowered = call_name.lower()
    return any(sink in lowered for sink in SECRET_EXPOSURE_SINKS)

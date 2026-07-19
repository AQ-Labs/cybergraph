"""Python AST security analyzer."""

from __future__ import annotations

import ast
from pathlib import Path

from cybergraph.graph import Edge, Finding, Node
from cybergraph.security.ontology import (
    AUTH_KEYWORDS,
    AUTHZ_KEYWORDS,
    CRYPTO_KEYWORDS,
    EDGE_EXPOSES_ENTRYPOINT,
    EDGE_EXPOSES_SECRET,
    EDGE_FLOWS_TO,
    EDGE_GUARDS,
    EDGE_IMPORTS,
    EDGE_REACHES_SINK,
    EDGE_READS_INPUT,
    EDGE_SANITIZES,
    EDGE_TAINTS,
    EDGE_USES_SECRET,
    SECRET_KEYWORDS,
    SINK_KEYWORDS,
    SOURCE_KEYWORDS,
    VALIDATION_KEYWORDS,
)
from cybergraph.suppressions import is_inline_suppressed

SECRET_EXPOSURE_SINKS = {
    "print",
    "logger.info",
    "logger.warning",
    "logger.error",
    "logging.info",
    "logging.warning",
    "logging.error",
    "requests.post",
    "requests.put",
    "subprocess.run",
    "subprocess.call",
    "os.system",
}


def analyze_python_file(
    path: Path,
    repo_root: Path,
    custom_sinks: tuple[str, ...] = (),
    auth_markers: tuple[str, ...] = (),
    validation_markers: tuple[str, ...] = (),
    secret_markers: tuple[str, ...] = (),
) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()
    rel = path.relative_to(repo_root).as_posix()
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        finding = Finding(
            rule_id="PY-SYNTAX",
            severity="info",
            message="Python file could not be parsed",
            file_path=rel,
            line_start=exc.lineno or 0,
            evidence=str(exc),
        )
        return [Node("File", rel, rel, rel, 1, len(lines))], [], [finding]

    nodes: list[Node] = [Node("File", rel, rel, rel, 1, len(lines), {"language": "python"})]
    edges: list[Edge] = []
    findings: list[Finding] = []

    for item in ast.walk(tree):
        if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
            key = f"{rel}::{item.name}"
            props = classify_name(
                item.name, auth_markers, validation_markers, secret_markers, custom_sinks
            )
            decorators = _decorator_texts(item)
            props["decorators"] = decorators
            route = _route_metadata(item)
            if route:
                props["entrypoint"] = True
                props["route"] = route
            nodes.append(
                Node(
                    "Function",
                    key,
                    item.name,
                    rel,
                    item.lineno,
                    getattr(item, "end_lineno", item.lineno) or item.lineno,
                    props,
                )
            )
            if route:
                edges.append(Edge(EDGE_EXPOSES_ENTRYPOINT, rel, key, rel, item.lineno))
            tainted_values = _route_inputs(item, key, rel, route, nodes, edges)
            for decorator in decorators:
                lowered_decorator = decorator.lower()
                if any(
                    kw in lowered_decorator
                    for kw in AUTH_KEYWORDS | AUTHZ_KEYWORDS | set(auth_markers)
                ):
                    edges.append(Edge(EDGE_GUARDS, key, decorator, rel, item.lineno))
            for dependency in _fastapi_depends_guards(item, auth_markers):
                edges.append(
                    Edge(EDGE_GUARDS, key, dependency, rel, item.lineno, {"framework": "fastapi"})
                )

            _add_python_dataflows(item, key, rel, tainted_values, nodes, edges)

            for call in [n for n in ast.walk(item) if isinstance(n, ast.Call)]:
                call_name = _call_name(call)
                if not call_name:
                    continue
                edges.append(
                    Edge("CALLS", key, call_name, rel, getattr(call, "lineno", item.lineno))
                )
                lowered = call_name.lower()
                if any(kw in lowered for kw in SINK_KEYWORDS | set(custom_sinks)):
                    line_no = getattr(call, "lineno", item.lineno)
                    edges.append(Edge(EDGE_REACHES_SINK, key, call_name, rel, line_no))
                    if not is_inline_suppressed(lines, line_no, "CG-SINK-CALL"):
                        findings.append(
                            Finding(
                                rule_id="CG-SINK-CALL",
                                severity="medium",
                                message=f"Function reaches sensitive sink `{call_name}`",
                                file_path=rel,
                                line_start=line_no,
                                cwe="CWE-20",
                                evidence=call_name,
                            )
                    )
                if any(kw in lowered for kw in SECRET_KEYWORDS | set(secret_markers)):
                    edges.append(
                        Edge(
                            EDGE_USES_SECRET, key, call_name, rel,
                            getattr(call, "lineno", item.lineno),
                        )
                    )
                call_text = ast.unparse(call).lower() if hasattr(ast, "unparse") else lowered
                if _is_secret_exposure(call_name, call_text, secret_markers):
                    edges.append(
                        Edge(
                            EDGE_EXPOSES_SECRET,
                            key,
                            call_name,
                            rel,
                            getattr(call, "lineno", item.lineno),
                            {"reason": "secret passed to exposure sink"},
                        )
                    )
                if any(kw in lowered for kw in VALIDATION_KEYWORDS | set(validation_markers)):
                    edges.append(
                        Edge(
                            EDGE_SANITIZES, key, call_name, rel,
                            getattr(call, "lineno", item.lineno),
                        )
                    )

    _add_django_url_routes(tree, rel, nodes, edges)
    _add_imports(tree, rel, edges)
    return nodes, edges, findings


def _add_imports(tree: ast.AST, rel: str, edges: list[Edge]) -> None:
    """Emit ``IMPORTS`` edges (File -> top-level module name) for absolute imports.

    These ground reachability-based SCA: a later pass links them to declared
    Dependency nodes so vulnerabilities in *used* packages can be prioritized over
    ones that are merely declared. Relative imports (``from . import x``) are local
    and skipped. Only the top-level module is recorded (``a.b.c`` -> ``a``)."""
    seen: set[str] = set()
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:  # relative import -> local, not a dependency
                continue
            if node.module:
                modules = [node.module]
        for module in modules:
            top = module.split(".", 1)[0].strip()
            if top and top not in seen:
                seen.add(top)
                edges.append(Edge(EDGE_IMPORTS, rel, top, rel, getattr(node, "lineno", 0)))


def _route_inputs(
    item: ast.FunctionDef | ast.AsyncFunctionDef,
    function_key: str,
    rel: str,
    route: dict[str, str],
    nodes: list[Node],
    edges: list[Edge],
) -> dict[str, str]:
    """Model route handler parameters as user-controlled input sources."""
    tainted: dict[str, str] = {}
    if not route:
        return tainted
    for arg in [*item.args.posonlyargs, *item.args.args, *item.args.kwonlyargs]:
        if arg.arg in {"self", "cls"}:
            continue
        input_key = f"{function_key}::input:{arg.arg}"
        nodes.append(
            Node(
                "Input",
                input_key,
                arg.arg,
                rel,
                getattr(arg, "lineno", item.lineno),
                getattr(arg, "lineno", item.lineno),
                {"source": "parameter", "route": route.get("path", ""), "user_controlled": True},
            )
        )
        edges.append(Edge(EDGE_READS_INPUT, function_key, input_key, rel, item.lineno))
        edges.append(
            Edge(
                EDGE_TAINTS, input_key, function_key, rel, item.lineno,
                {"reason": "route parameter"},
            )
        )
        tainted[arg.arg] = input_key
    return tainted


def _add_python_dataflows(
    item: ast.FunctionDef | ast.AsyncFunctionDef,
    function_key: str,
    rel: str,
    tainted_values: dict[str, str],
    nodes: list[Node],
    edges: list[Edge],
) -> None:
    """Track simple local propagation from request inputs into sink arguments."""
    tainted = dict(tainted_values)
    for node in ast.walk(item):
        if isinstance(node, ast.Assign):
            source_key = _tainted_source_key(node.value, tainted)
            if not source_key and _is_user_input_expr(node.value):
                source_key = _ensure_input_node(
                    function_key, rel, getattr(node, "lineno", item.lineno), "request", nodes, edges
                )
            if not source_key:
                continue
            for target in node.targets:
                for name in _assigned_names(target):
                    flow_key = f"{function_key}::flow:{name}:{getattr(node, 'lineno', item.lineno)}"
                    nodes.append(
                        Node(
                            "DataFlow",
                            flow_key,
                            name,
                            rel,
                            getattr(node, "lineno", item.lineno),
                            getattr(node, "lineno", item.lineno),
                            {"user_controlled": True, "source": source_key},
                        )
                    )
                    edges.append(
                        Edge(
                            EDGE_FLOWS_TO, source_key, flow_key, rel,
                            getattr(node, "lineno", item.lineno),
                        )
                    )
                    tainted[name] = flow_key
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            source_key = _tainted_source_key(node.value, tainted) if node.value is not None else ""
            if not source_key and node.value is not None and _is_user_input_expr(node.value):
                source_key = _ensure_input_node(
                    function_key, rel, getattr(node, "lineno", item.lineno), "request", nodes, edges
                )
            if source_key:
                name = node.target.id
                flow_key = f"{function_key}::flow:{name}:{getattr(node, 'lineno', item.lineno)}"
                nodes.append(
                    Node(
                        "DataFlow",
                        flow_key,
                        name,
                        rel,
                        getattr(node, "lineno", item.lineno),
                        getattr(node, "lineno", item.lineno),
                        {"user_controlled": True, "source": source_key},
                    )
                )
                edges.append(
                    Edge(
                        EDGE_FLOWS_TO, source_key, flow_key, rel,
                        getattr(node, "lineno", item.lineno),
                    )
                )
                tainted[name] = flow_key
        elif isinstance(node, ast.Call):
            call_name = _call_name(node)
            if not call_name:
                continue
            source_key = _tainted_source_key(node, tainted)
            if source_key:
                edges.append(
                    Edge(
                        EDGE_TAINTS,
                        source_key,
                        call_name,
                        rel,
                        getattr(node, "lineno", item.lineno),
                        {"function": function_key, "reason": "tainted argument"},
                    )
                )


def _ensure_input_node(
    function_key: str,
    rel: str,
    line_no: int,
    name: str,
    nodes: list[Node],
    edges: list[Edge],
) -> str:
    input_key = f"{function_key}::input:{name}:{line_no}"
    nodes.append(
        Node(
            "Input",
            input_key,
            name,
            rel,
            line_no,
            line_no,
            {"source": "request", "user_controlled": True},
        )
    )
    edges.append(Edge(EDGE_READS_INPUT, function_key, input_key, rel, line_no))
    return input_key


def _assigned_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Tuple | ast.List):
        names: list[str] = []
        for elt in target.elts:
            names.extend(_assigned_names(elt))
        return names
    return []


def _tainted_source_key(node: ast.AST | None, tainted: dict[str, str]) -> str:
    if node is None:
        return ""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tainted:
            return tainted[child.id]
    return ""


def _is_user_input_expr(node: ast.AST) -> bool:
    text = ast.unparse(node).lower() if hasattr(ast, "unparse") else ""
    return any(keyword in text for keyword in SOURCE_KEYWORDS)


def _is_secret_exposure(call_name: str, call_text: str, secret_markers: tuple[str, ...]) -> bool:
    lowered_name = call_name.lower()
    if not any(sink in lowered_name for sink in SECRET_EXPOSURE_SINKS):
        return False
    return any(marker in call_text for marker in SECRET_KEYWORDS | set(secret_markers))


def _add_django_url_routes(tree: ast.AST, rel: str, nodes: list[Node], edges: list[Edge]) -> None:
    """Detect Django URLconf entries (``path``/``re_path``/``url``) as entrypoints.

    Django function/class views carry no route decorator; the route lives in a
    ``urls.py`` ``path('users/', views.list_users)`` call. We model the route as
    an Entrypoint and link it to its view by name so interprocedural traversal
    can reach the view's sinks (route -> view -> sink).
    """
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if _callable_name(call.func) not in {"path", "re_path", "url"} or len(call.args) < 2:
            continue
        route_arg = call.args[0]
        if not (isinstance(route_arg, ast.Constant) and isinstance(route_arg.value, str)):
            continue
        line_no = getattr(call, "lineno", 1)
        route = route_arg.value or "/"
        key = f"{rel}::route:{route}:{line_no}"
        nodes.append(Node("Entrypoint", key, route, rel, line_no, line_no, {"framework": "django"}))
        edges.append(Edge(EDGE_EXPOSES_ENTRYPOINT, rel, key, rel, line_no))
        view_name = _callable_name(call.args[1])
        if view_name:
            edges.append(Edge("CALLS", key, view_name, rel, line_no))


def classify_name(
    name: str,
    auth_markers: tuple[str, ...] = (),
    validation_markers: tuple[str, ...] = (),
    secret_markers: tuple[str, ...] = (),
    custom_sinks: tuple[str, ...] = (),
) -> dict[str, bool]:
    lowered = name.lower()
    return {
        "auth_related": any(kw in lowered for kw in AUTH_KEYWORDS | set(auth_markers)),
        "authorization_related": any(kw in lowered for kw in AUTHZ_KEYWORDS),
        "validation_related": any(
            kw in lowered for kw in VALIDATION_KEYWORDS | set(validation_markers)
        ),
        "secret_related": any(kw in lowered for kw in SECRET_KEYWORDS | set(secret_markers)),
        "crypto_related": any(kw in lowered for kw in CRYPTO_KEYWORDS),
        "sink_related": any(kw in lowered for kw in SINK_KEYWORDS | set(custom_sinks)),
    }


def _decorator_texts(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [ast.unparse(decorator) for decorator in node.decorator_list if hasattr(ast, "unparse")]


def _route_metadata(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, str]:
    for decorator in node.decorator_list:
        text = ast.unparse(decorator).lower() if hasattr(ast, "unparse") else ""
        func_name = ""
        route_path = ""
        if isinstance(decorator, ast.Call):
            func_name = _callable_name(decorator.func)
            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                route_path = str(decorator.args[0].value)
        else:
            func_name = _callable_name(decorator)
        lowered_func = func_name.lower()
        framework_route = (
            lowered_func.endswith(".route")
            or lowered_func in {"route", "app.route"}
            or any(
                lowered_func.endswith(f".{method}")
                for method in ("get", "post", "put", "delete", "patch", "head", "options")
            )
            or text.startswith("@require_")
        )
        if framework_route:
            return {"decorator": func_name or text, "path": route_path}
    return {}


def _call_name(call: ast.Call) -> str:
    return _callable_name(call.func)


def _fastapi_depends_guards(
    node: ast.FunctionDef | ast.AsyncFunctionDef, auth_markers: tuple[str, ...]
) -> list[str]:
    guards: list[str] = []
    defaults = list(node.args.defaults) + [
        default for default in node.args.kw_defaults if default is not None
    ]
    for default in defaults:
        if not isinstance(default, ast.Call):
            continue
        if _callable_name(default.func).lower() != "depends" or not default.args:
            continue
        dependency = _callable_name(default.args[0])
        if not dependency:
            continue
        lowered = dependency.lower()
        if any(kw in lowered for kw in AUTH_KEYWORDS | AUTHZ_KEYWORDS | set(auth_markers)):
            guards.append(dependency)
    return guards


def _callable_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = [func.attr]
        value = func.value
        while isinstance(value, ast.Attribute):
            parts.append(value.attr)
            value = value.value
        if isinstance(value, ast.Name):
            parts.append(value.id)
        return ".".join(reversed(parts))
    return ""

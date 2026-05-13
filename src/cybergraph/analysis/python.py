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
    EDGE_GUARDS,
    EDGE_REACHES_SINK,
    EDGE_SANITIZES,
    EDGE_USES_SECRET,
    SECRET_KEYWORDS,
    SINK_KEYWORDS,
    VALIDATION_KEYWORDS,
)


def analyze_python_file(path: Path, repo_root: Path) -> tuple[list[Node], list[Edge], list[Finding]]:
    source = path.read_text(encoding="utf-8", errors="ignore")
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
        return [Node("File", rel, rel, rel, 1, len(source.splitlines()))], [], [finding]

    nodes: list[Node] = [Node("File", rel, rel, rel, 1, len(source.splitlines()), {"language": "python"})]
    edges: list[Edge] = []
    findings: list[Finding] = []

    for item in ast.walk(tree):
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            key = f"{rel}::{item.name}"
            props = classify_name(item.name)
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
            for decorator in decorators:
                lowered_decorator = decorator.lower()
                if any(kw in lowered_decorator for kw in AUTH_KEYWORDS | AUTHZ_KEYWORDS):
                    edges.append(Edge(EDGE_GUARDS, key, decorator, rel, item.lineno))

            for call in [n for n in ast.walk(item) if isinstance(n, ast.Call)]:
                call_name = _call_name(call)
                if not call_name:
                    continue
                edges.append(Edge("CALLS", key, call_name, rel, getattr(call, "lineno", item.lineno)))
                lowered = call_name.lower()
                if any(kw in lowered for kw in SINK_KEYWORDS):
                    edges.append(Edge(EDGE_REACHES_SINK, key, call_name, rel, getattr(call, "lineno", item.lineno)))
                    findings.append(
                        Finding(
                            rule_id="CG-SINK-CALL",
                            severity="medium",
                            message=f"Function reaches sensitive sink `{call_name}`",
                            file_path=rel,
                            line_start=getattr(call, "lineno", item.lineno),
                            cwe="CWE-20",
                            evidence=call_name,
                        )
                    )
                if any(kw in lowered for kw in SECRET_KEYWORDS):
                    edges.append(Edge(EDGE_USES_SECRET, key, call_name, rel, getattr(call, "lineno", item.lineno)))
                if any(kw in lowered for kw in VALIDATION_KEYWORDS):
                    edges.append(Edge(EDGE_SANITIZES, key, call_name, rel, getattr(call, "lineno", item.lineno)))

    return nodes, edges, findings


def classify_name(name: str) -> dict[str, bool]:
    lowered = name.lower()
    return {
        "auth_related": any(kw in lowered for kw in AUTH_KEYWORDS),
        "authorization_related": any(kw in lowered for kw in AUTHZ_KEYWORDS),
        "validation_related": any(kw in lowered for kw in VALIDATION_KEYWORDS),
        "secret_related": any(kw in lowered for kw in SECRET_KEYWORDS),
        "crypto_related": any(kw in lowered for kw in CRYPTO_KEYWORDS),
        "sink_related": any(kw in lowered for kw in SINK_KEYWORDS),
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

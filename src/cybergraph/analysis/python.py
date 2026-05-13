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
    EDGE_REACHES_SINK,
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
            if _looks_like_route(item):
                edges.append(Edge(EDGE_EXPOSES_ENTRYPOINT, rel, key, rel, item.lineno))

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


def _looks_like_route(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in node.decorator_list:
        text = ast.unparse(decorator).lower() if hasattr(ast, "unparse") else ""
        if any(marker in text for marker in ("route", "get", "post", "put", "delete", "patch")):
            return True
    return False


def _call_name(call: ast.Call) -> str:
    func = call.func
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

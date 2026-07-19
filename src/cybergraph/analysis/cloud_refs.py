"""Link application code to IaC resources by stable resource hints."""

from __future__ import annotations

from pathlib import Path

from cybergraph.graph import Edge, Node
from cybergraph.security.ontology import EDGE_USES_RESOURCE


def link_code_resource_usage(repo_root: Path, nodes: list[Node]) -> list[Edge]:
    resources = [node for node in nodes if node.kind == "Resource"]
    code_nodes = [node for node in nodes if node.kind in {"Function", "File"} and node.file_path]
    if not resources or not code_nodes:
        return []

    file_text: dict[str, str] = {}
    for node in code_nodes:
        if node.file_path not in file_text:
            path = repo_root / node.file_path
            file_text[node.file_path] = (
                path.read_text(encoding="utf-8", errors="ignore").lower()
                if path.exists()
                else ""
            )

    edges: list[Edge] = []
    seen: set[tuple[str, str]] = set()
    for code in code_nodes:
        text = _node_text(code, file_text.get(code.file_path, ""))
        if not text:
            continue
        for resource in resources:
            hint = _resource_hint(resource)
            if not hint or hint not in text:
                continue
            pair = (code.key, resource.key)
            if pair in seen:
                continue
            seen.add(pair)
            edges.append(
                Edge(
                    EDGE_USES_RESOURCE,
                    code.key,
                    resource.key,
                    code.file_path,
                    code.line_start,
                    {"hint": hint, "resource": resource.name},
                )
            )
    return edges


def _resource_hint(resource: Node) -> str:
    return resource.name.split(".", 1)[-1].replace("_", "-").lower()


def _node_text(node: Node, file_text: str) -> str:
    if node.kind != "Function" or not node.line_start:
        return file_text
    lines = file_text.splitlines()
    start = max(node.line_start - 1, 0)
    end = node.line_end if node.line_end else len(lines)
    return "\n".join(lines[start:end])

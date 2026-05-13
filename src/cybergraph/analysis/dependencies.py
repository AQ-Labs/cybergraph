"""Dependency manifest analyzer."""

from __future__ import annotations

import json
from pathlib import Path

from cybergraph.graph import Edge, Node


MANIFEST_NAMES = {"package.json", "requirements.txt", "pyproject.toml"}


def is_dependency_manifest(path: Path) -> bool:
    return path.name in MANIFEST_NAMES


def analyze_dependency_manifest(path: Path, repo_root: Path) -> tuple[list[Node], list[Edge]]:
    rel = path.relative_to(repo_root).as_posix()
    manifest = Node("DependencyManifest", rel, path.name, rel, 1, _line_count(path), {"layer": "dependency"})
    dependencies = _extract_dependencies(path)
    nodes = [manifest]
    edges: list[Edge] = []
    for name, spec in dependencies.items():
        key = f"{rel}::{name}"
        nodes.append(Node("Dependency", key, name, rel, 0, 0, {"version": spec, "layer": "dependency"}))
        edges.append(Edge("DECLARES_DEPENDENCY", rel, key, rel, 0, {"version": spec}))
    return nodes, edges


def _extract_dependencies(path: Path) -> dict[str, str]:
    if path.name == "package.json":
        return _package_json_dependencies(path)
    if path.name == "requirements.txt":
        return _requirements_dependencies(path)
    if path.name == "pyproject.toml":
        return _pyproject_dependencies(path)
    return {}


def _package_json_dependencies(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, spec in data.get(section, {}).items():
            deps[name] = str(spec)
    return deps


def _requirements_dependencies(path: Path) -> dict[str, str]:
    deps: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        name = line
        spec = ""
        for marker in ("==", ">=", "<=", "~=", ">", "<"):
            if marker in line:
                name, spec = line.split(marker, 1)
                spec = marker + spec
                break
        deps[name.strip()] = spec.strip()
    return deps


def _pyproject_dependencies(path: Path) -> dict[str, str]:
    deps: dict[str, str] = {}
    in_dependencies = False
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if line.startswith("dependencies") and "[" in line:
            in_dependencies = True
            continue
        if in_dependencies and line.startswith("]"):
            break
        if in_dependencies:
            dep = line.strip(",").strip("\"'")
            if dep:
                deps.update(_requirements_dependencies_from_line(dep))
    return deps


def _requirements_dependencies_from_line(line: str) -> dict[str, str]:
    for marker in ("==", ">=", "<=", "~=", ">", "<"):
        if marker in line:
            name, spec = line.split(marker, 1)
            return {name.strip(): (marker + spec).strip()}
    return {line.strip(): ""}


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8", errors="ignore").splitlines())

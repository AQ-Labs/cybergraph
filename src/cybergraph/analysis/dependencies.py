"""Dependency manifest analyzer."""

from __future__ import annotations

import ast
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from cybergraph.graph import Edge, Node

MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile.lock",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "packages.lock.json",
}


def is_dependency_manifest(path: Path) -> bool:
    return path.name in MANIFEST_NAMES or path.suffix.lower() == ".csproj"


def analyze_dependency_manifest(path: Path, repo_root: Path) -> tuple[list[Node], list[Edge]]:
    rel = path.relative_to(repo_root).as_posix()
    manifest = Node(
        "DependencyManifest",
        rel,
        path.name,
        rel,
        1,
        _line_count(path),
        {"layer": "dependency"},
    )
    dependencies = _extract_dependencies(path)
    nodes = [manifest]
    edges: list[Edge] = []
    for name, spec in dependencies.items():
        key = f"{rel}::{name}"
        nodes.append(
            Node("Dependency", key, name, rel, 0, 0, {"version": spec, "layer": "dependency"})
        )
        edges.append(Edge("DECLARES_DEPENDENCY", rel, key, rel, 0, {"version": spec}))
    return nodes, edges


def _extract_dependencies(path: Path) -> dict[str, str]:
    if path.name == "package.json":
        return _package_json_dependencies(path)
    if path.name == "package-lock.json":
        return _package_lock_dependencies(path)
    if path.name == "pnpm-lock.yaml":
        return _pnpm_lock_dependencies(path)
    if path.name == "yarn.lock":
        return _yarn_lock_dependencies(path)
    if path.name == "requirements.txt":
        return _requirements_dependencies(path)
    if path.name == "pyproject.toml":
        return _pyproject_dependencies(path)
    if path.name == "poetry.lock":
        return _poetry_lock_dependencies(path)
    if path.name == "Pipfile.lock":
        return _pipfile_lock_dependencies(path)
    if path.name == "go.sum":
        return _go_sum_dependencies(path)
    if path.name == "pom.xml":
        return _pom_dependencies(path)
    if path.name in {"build.gradle", "build.gradle.kts"}:
        return _gradle_dependencies(path)
    if path.name == "packages.lock.json":
        return _dotnet_packages_lock_dependencies(path)
    if path.suffix.lower() == ".csproj":
        return _csproj_dependencies(path)
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


def _package_lock_dependencies(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    deps: dict[str, str] = {}
    for name, meta in data.get("dependencies", {}).items():
        if isinstance(meta, dict):
            deps[name] = str(meta.get("version", ""))
    for package_path, meta in data.get("packages", {}).items():
        if not package_path.startswith("node_modules/") or not isinstance(meta, dict):
            continue
        name = package_path.removeprefix("node_modules/")
        if name and "/" not in name.removeprefix("@").split("/", 1)[-1]:
            deps[name] = str(meta.get("version", ""))
    return deps


def _pnpm_lock_dependencies(path: Path) -> dict[str, str]:
    deps: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip().strip("'\"")
        match = re.match(r"/(?P<name>(?:@[^/]+/)?[^/@]+)@(?P<version>[^:()]+)", line)
        if match:
            deps[match.group("name")] = match.group("version")
    return deps


def _yarn_lock_dependencies(path: Path) -> dict[str, str]:
    deps: dict[str, str] = {}
    current: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if raw and not raw.startswith((" ", "\t")) and raw.rstrip().endswith(":"):
            current = [
                _package_from_yarn_selector(part.strip().strip("'\""))
                for part in raw[:-1].split(",")
            ]
            current = [name for name in current if name]
            continue
        version_match = re.match(r"\s*version\s+\"(?P<version>[^\"]+)\"", raw)
        if version_match:
            for name in current:
                deps[name] = version_match.group("version")
    return deps


def _package_from_yarn_selector(selector: str) -> str:
    if selector.startswith("@"):
        parts = selector.split("@")
        return "@".join(parts[:2]) if len(parts) >= 2 else selector
    return selector.split("@", 1)[0]


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
    array_text = _toml_array_value(
        path.read_text(encoding="utf-8", errors="ignore"), "dependencies"
    )
    if not array_text:
        return deps
    try:
        values = ast.literal_eval(array_text)
    except (SyntaxError, ValueError):
        return deps
    if not isinstance(values, list):
        return deps
    for value in values:
        if isinstance(value, str):
            deps.update(_requirements_dependencies_from_line(value))
    return deps


def _toml_array_value(text: str, key: str) -> str:
    """Extract a simple TOML array assigned to ``key``.

    PEP 621 project dependencies are string arrays. Using the bracket span avoids
    the previous line scanner bug where single-line arrays were skipped and the
    parser kept reading unrelated sections as dependencies.
    """
    match = re.search(rf"(?m)^\s*{re.escape(key)}\s*=\s*\[", text)
    if not match:
        return ""
    start = match.end() - 1
    depth = 0
    quote = ""
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return ""


def _poetry_lock_dependencies(path: Path) -> dict[str, str]:
    deps: dict[str, str] = {}
    current = ""
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if line.startswith("name ="):
            current = line.split("=", 1)[1].strip().strip("\"'")
        elif line.startswith("version =") and current:
            deps[current] = line.split("=", 1)[1].strip().strip("\"'")
            current = ""
    return deps


def _pipfile_lock_dependencies(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    deps: dict[str, str] = {}
    for section in ("default", "develop"):
        for name, meta in data.get(section, {}).items():
            deps[name] = str(meta.get("version", "")) if isinstance(meta, dict) else str(meta)
    return deps


def _go_sum_dependencies(path: Path) -> dict[str, str]:
    deps: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = raw.split()
        if len(parts) >= 2:
            deps.setdefault(parts[0], parts[1].removesuffix("/go.mod"))
    return deps


def _pom_dependencies(path: Path) -> dict[str, str]:
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8", errors="ignore"))
    except ET.ParseError:
        return {}
    deps: dict[str, str] = {}
    ns = _xml_namespace(root.tag)
    for dep in root.findall(f".//{ns}dependency"):
        artifact = dep.findtext(f"{ns}artifactId") or ""
        version = dep.findtext(f"{ns}version") or ""
        if artifact:
            deps[artifact] = version
    return deps


def _gradle_dependencies(path: Path) -> dict[str, str]:
    deps: dict[str, str] = {}
    text = path.read_text(encoding="utf-8", errors="ignore")
    patterns = [
        r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s+['\"](?P<group>[^:'\"]+):(?P<name>[^:'\"]+):(?P<version>[^'\"]+)['\"]",
        r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(\s*['\"](?P<group>[^:'\"]+):(?P<name>[^:'\"]+):(?P<version>[^'\"]+)['\"]\s*\)",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            deps[match.group("name")] = match.group("version")
    return deps


def _csproj_dependencies(path: Path) -> dict[str, str]:
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8", errors="ignore"))
    except ET.ParseError:
        return {}
    deps: dict[str, str] = {}
    for ref in root.findall(".//PackageReference"):
        name = ref.attrib.get("Include") or ref.attrib.get("Update") or ""
        version = ref.attrib.get("Version") or (ref.findtext("Version") or "")
        if name:
            deps[name] = version
    return deps


def _dotnet_packages_lock_dependencies(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    deps: dict[str, str] = {}
    for target in data.get("dependencies", {}).values():
        if not isinstance(target, dict):
            continue
        for name, meta in target.items():
            if isinstance(meta, dict):
                deps[name] = str(meta.get("resolved") or meta.get("version") or "")
    return deps


def _xml_namespace(tag: str) -> str:
    if tag.startswith("{") and "}" in tag:
        return tag.split("}", 1)[0] + "}"
    return ""


def _requirements_dependencies_from_line(line: str) -> dict[str, str]:
    for marker in ("==", ">=", "<=", "~=", ">", "<"):
        if marker in line:
            name, spec = line.split(marker, 1)
            return {name.strip(): (marker + spec).strip()}
    return {line.strip(): ""}


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8", errors="ignore").splitlines())

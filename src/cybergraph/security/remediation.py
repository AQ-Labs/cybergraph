"""Deterministic security narratives and remediation templates."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cybergraph.security.attack_paths import AttackPath


def remediation_for_sink(sink: str) -> str:
    lowered = sink.lower()
    if any(token in lowered for token in ("execute", "query", "sql")):
        return (
            "Use parameterized queries or an ORM query builder; "
            "never concatenate user input into SQL."
        )
    if any(
        token in lowered
        for token in ("exec", "shell", "command", "subprocess", "process.start")
    ):
        return "Avoid shell execution; pass an argv array and validate inputs with an allowlist."
    if any(token in lowered for token in ("open", "read", "write", "file")):
        return (
            "Normalize the path, reject traversal, and enforce that resolved paths "
            "stay under an approved base directory."
        )
    if any(token in lowered for token in ("deserialize", "pickle")):
        return "Avoid deserializing untrusted data or require a safe, schema-validated format."
    if "render_template_string" in lowered or "template" in lowered:
        return (
            "Render trusted templates only and escape or strictly validate "
            "user-controlled template data."
        )
    if "eval" in lowered:
        return (
            "Remove dynamic evaluation of user-controlled strings "
            "and replace it with explicit dispatch."
        )
    return "Validate and constrain user-controlled data before it reaches this sensitive sink."


def narrative_for_attack_path(path: AttackPath) -> str:
    source = (
        ", ".join(path.taint_sources)
        if path.taint_sources
        else "no specific user input identified"
    )
    data = (
        "user-controlled data reaches the sink"
        if path.data_reachable
        else "the graph shows structural reachability"
    )
    control = (
        "A sanitizer or validation barrier appears on the path."
        if path.sanitized
        else "No sanitizer barrier was detected on the path."
    )
    risk = f" Risk is {path.risk.label} ({path.risk.score}/100)." if path.risk else ""
    return (
        f"Entry point `{path.entrypoint}` reaches `{path.sink}` via "
        f"`{' -> '.join(path.nodes)}`. Source: {source}; {data}. {control}{risk} "
        f"Recommended fix: {remediation_for_sink(path.sink)}"
    )


def remediation_for_rule(rule_id: str, message: str = "") -> str:
    text = f"{rule_id} {message}".lower()
    if "docker" in text and "digest" in text:
        return "Pin container images by immutable digest and keep base images patched."
    if "docker" in text and "root" in text:
        return "Create and switch to a non-root user before running application code."
    if "iam" in text or "wildcard" in text:
        return "Replace wildcard IAM actions/resources with the minimum required permissions."
    if "0.0.0.0/0" in text or "public" in text:
        return "Restrict public exposure to trusted CIDRs or require an authenticated edge."
    if "secret" in text:
        return (
            "Move secrets to a managed secret store and prevent logging, "
            "response, or image-layer exposure."
        )
    return remediation_for_sink(message or rule_id)

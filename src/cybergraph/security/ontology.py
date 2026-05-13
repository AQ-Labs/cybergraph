"""Security ontology used by CyberGraph analyzers and answers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityLayer:
    key: str
    label: str
    description: str


LAYERS: tuple[SecurityLayer, ...] = (
    SecurityLayer("entrypoint", "Entrypoints", "External inputs such as routes, handlers, CLIs, and webhooks."),
    SecurityLayer("authentication", "Authentication", "Identity checks and session/token verification."),
    SecurityLayer("authorization", "Authorization", "Permission, role, policy, and ownership checks."),
    SecurityLayer("validation", "Validation", "Input validation, parsing, canonicalization, and sanitization."),
    SecurityLayer("secrets", "Secrets", "Credential, token, key, and environment variable handling."),
    SecurityLayer("crypto", "Cryptography", "Hashing, signing, encryption, verification, and key use."),
    SecurityLayer("sink", "Sensitive Sinks", "Database, shell, filesystem, network, template, and deserialization sinks."),
    SecurityLayer("dependency", "Dependencies", "Third-party packages and known vulnerable components."),
)

SOURCE_KEYWORDS = {
    "request", "body", "query", "params", "headers", "cookie", "form", "input", "argv", "webhook",
}

AUTH_KEYWORDS = {
    "auth", "authenticate", "authenticated", "login", "session", "jwt", "token", "principal",
}

AUTHZ_KEYWORDS = {
    "authorize", "permission", "role", "policy", "admin", "owner", "scope", "privilege", "acl",
}

VALIDATION_KEYWORDS = {
    "validate", "sanitize", "schema", "escape", "clean", "parse", "normalize", "allowlist",
}

SECRET_KEYWORDS = {
    "secret", "password", "credential", "apikey", "api_key", "private_key", "token", "env",
}

CRYPTO_KEYWORDS = {
    "encrypt", "decrypt", "hash", "hmac", "sign", "verify", "bcrypt", "argon", "cipher",
}

SINK_KEYWORDS = {
    "execute", "query", "raw", "shell", "subprocess", "eval", "exec", "open", "write", "connect",
    "deserialize", "pickle", "render_template_string",
}

EDGE_GUARDS = "GUARDS"
EDGE_SANITIZES = "SANITIZES"
EDGE_REACHES_SINK = "REACHES_SINK"
EDGE_USES_SECRET = "USES_SECRET"
EDGE_EXPOSES_ENTRYPOINT = "EXPOSES_ENTRYPOINT"
EDGE_CROSSES_TRUST_BOUNDARY = "CROSSES_TRUST_BOUNDARY"

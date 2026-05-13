# Security Ontology

CyberGraph uses a security-first vocabulary so evidence is not just a bag of scanner messages.

## Layers

- Entrypoints: routes, webhooks, CLIs, queue consumers, and external input handlers.
- Authentication: identity verification and session/token checks.
- Authorization: roles, ownership, policies, scopes, and permissions.
- Validation: schema checks, sanitization, escaping, and normalization.
- Secrets: credentials, tokens, keys, and environment-sourced sensitive values.
- Cryptography: hashing, signing, encryption, verification, and key handling.
- Sensitive sinks: SQL, shell, filesystem, network, templates, deserialization, and eval-like APIs.
- Dependencies: third-party packages and known vulnerabilities.

## Relationships

- `EXPOSES_ENTRYPOINT`
- `GUARDS`
- `SANITIZES`
- `REACHES_SINK`
- `USES_SECRET`
- `CROSSES_TRUST_BOUNDARY`

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
- Data flow: user-controlled inputs, local propagation, and tainted sink arguments.
- Dependencies: third-party packages and known vulnerabilities.
- Infrastructure: Terraform/cloud resources, public exposure, privilege, and code-resource links.

## Relationships

- `EXPOSES_ENTRYPOINT`
- `GUARDS`
- `SANITIZES`
- `REACHES_SINK`
- `USES_SECRET`
- `EXPOSES_SECRET`
- `READS_INPUT`
- `FLOWS_TO`
- `TAINTS`
- `IMPORTS`
- `USES_DEPENDENCY`
- `AFFECTS_DEPENDENCY`
- `REFERENCES`
- `REFERENCES_RESOLVED`
- `USES_RESOURCE`
- `CROSSES_TRUST_BOUNDARY`

## Risk Model

Risk scores are transparent 0-100 values built from normalized factors:

- reachability: whether the issue is entrypoint/data reachable or only structurally present.
- exposure: whether the path crosses a public route, public cloud resource, or external sink.
- exploitability: severity, EPSS, CISA KEV, exploit maturity, or dangerous sink type.
- impact: expected consequence of the sink, privilege, secret exposure, or vulnerable package.
- controls: validation/sanitization/guard evidence that reduces but does not erase risk.
- confidence: high/medium/low confidence based on graph evidence quality.

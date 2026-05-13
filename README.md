# CyberGraph

Security review for codebases, powered by knowledge graphs.

CyberGraph maps a repository into a cybersecurity knowledge graph so developers can inspect security layers, risky code paths, scanner findings, and evidence-backed answers without reading the whole codebase by hand.

## Early goals

- Build a local graph of files, symbols, security controls, findings, and attack-relevant paths.
- Answer security review questions with file and line evidence.
- Connect scanner findings to reachable code instead of leaving them as flat reports.
- Provide a CLI first, then MCP tools for AI coding assistants.

## Example questions

```text
Which endpoints can reach SQL execution?
What changed in this PR that affects authentication?
Where are secrets loaded and passed into network clients?
Which vulnerable dependency is reachable from production code?
```

## Status

Private bootstrap. The initial version focuses on a small, inspectable Python package with a SQLite graph store and security-first analyzers.

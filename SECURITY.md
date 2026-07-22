# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest 0.x release | ✅ |
| older releases | ❌ |

## Reporting a Vulnerability

**Please do not open a public issue for security reports.**

1. **Preferred:** use GitHub's private vulnerability reporting — go to the
   repository's **Security** tab → **Report a vulnerability**. Your report is
   visible only to the maintainers.
2. **Fallback:** email `lxh417bham@gmail.com` with a description, reproduction
   steps, and the affected version/commit.

## What to expect

- **Initial response within 14 days** of your report (usually much sooner).
- Confirmed vulnerabilities of medium or higher severity are targeted for a
  fix **within 60 days** of the report or of the issue becoming publicly known.
- We practice coordinated disclosure: we will agree a disclosure timeline with
  you and credit you in the advisory unless you prefer otherwise.

## Scope

- The `cybergraph` CLI and library (`src/cybergraph/`).
- The MCP server (`cybergraph-mcp`) — a **programmatic surface**: reports about
  prompt-injection, tool-abuse, or data exfiltration through the MCP interface
  are explicitly in scope.
- The generated HTML report (XSS/redaction bypasses are in scope; see the
  secret-redaction tests before filing).

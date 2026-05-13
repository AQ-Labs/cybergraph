# Product Plan

## Wedge

CyberGraph should be the tool that answers security review questions with code evidence.

## First delightful workflow

```bash
cybergraph build
cybergraph ask "Which endpoints can reach SQL execution?"
cybergraph paths
```

## What makes it different

Most scanners return flat findings. CyberGraph maps those findings onto reachable code, security controls, and attack paths.

## Public launch checklist

- Strong README with real examples and screenshots.
- Demo vulnerable FastAPI and Express apps.
- GitHub Action for security graph summaries on pull requests.
- VS Code or MCP integration examples.
- Clear privacy story: local-first graph, no code upload by default.

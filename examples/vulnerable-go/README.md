# Vulnerable Go Demo

A tiny, intentionally insecure Go (`net/http`) service. It shows CyberGraph's
**interprocedural** reachability in a compiled language: an unauthenticated
route reaches a SQL sink through its handler.

## Try it

```bash
cybergraph build examples/vulnerable-go
cybergraph paths --repo examples/vulnerable-go
cybergraph explain "Which routes reach SQL execution?" --repo examples/vulnerable-go
cybergraph visualize examples/vulnerable-go --output examples/vulnerable-go/cybergraph-report.html
```

Expected themes:

- `/users` and `/health` are entrypoints (`http.HandleFunc`).
- The `/users` route links to `listUsers`, which reaches a SQL sink (`db.Query`).
- `cybergraph paths` reports `route:/users -> listUsers -> db.Query`.
- `adminConfig` reads a secret via `os.Getenv`.
- `--shallow` disables interprocedural traversal, showing the contrast.

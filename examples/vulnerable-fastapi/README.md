# Vulnerable FastAPI Demo

This tiny app is intentionally insecure. It exists so new CyberGraph users can see useful output in under a minute.

## Try it

```bash
cybergraph build examples/vulnerable-fastapi
cybergraph ask "Which routes reach SQL execution?" --repo examples/vulnerable-fastapi
cybergraph paths --repo examples/vulnerable-fastapi
cybergraph layers --repo examples/vulnerable-fastapi
cybergraph visualize examples/vulnerable-fastapi --output examples/vulnerable-fastapi/cybergraph-report.html
```

Expected themes:

- `/users` is an entrypoint.
- `list_users` reaches a SQL sink.
- `validate_name` is detected as a validation helper.
- `require_admin` is a custom auth marker configured in `.cybergraph.toml`.

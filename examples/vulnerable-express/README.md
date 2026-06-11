# Vulnerable Express Demo

A tiny, intentionally insecure Express app. It demonstrates CyberGraph's
JavaScript/TypeScript coverage: route entrypoints, a SQL sink reached from a
handler, a dependency manifest, and secret access via `process.env`.

## Try it

```bash
cybergraph build examples/vulnerable-express
cybergraph layers --repo examples/vulnerable-express
cybergraph explain "Where does the app reach a database query?" --repo examples/vulnerable-express
cybergraph visualize examples/vulnerable-express --output examples/vulnerable-express/cybergraph-report.html
```

Expected themes:

- `/users` and `/health` are entrypoints (`app.get`).
- `listUsers` reaches a SQL sink (`db.query`).
- `dbUrl` reads a secret (`process.env.DATABASE_URL`).
- `express` appears as a dependency from `package.json`.

> Note: Express handlers passed inline as arrow callbacks are not linked to a
> named function, so interprocedural path stitching is strongest for named
> handlers (as in `listUsers`). This is a documented limitation of the
> regex-based JS analyzer.

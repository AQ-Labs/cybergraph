# Getting Started

CyberGraph is easiest to understand by running it on a small app first.

## 1. Install locally

From this repository:

```bash
python -m pip install -e .
```

## 2. Try the demo

```bash
cybergraph build examples/vulnerable-fastapi
cybergraph ask "Which routes reach SQL execution?" --repo examples/vulnerable-fastapi
cybergraph paths --repo examples/vulnerable-fastapi
cybergraph visualize examples/vulnerable-fastapi --output cybergraph-report.html
```

Open `cybergraph-report.html` to inspect the HTML report.

## 3. Initialize your own repository

Inside another project:

```bash
cybergraph init .
cybergraph doctor .
cybergraph build .
cybergraph ask "Which routes reach sensitive sinks?" --repo .
```

`cybergraph init` creates:

- `.cybergraph.toml`
- `.github/workflows/cybergraph.yml`

## 4. Customize detection

Edit `.cybergraph.toml`:

```toml
[ignore]
paths = ["vendor/**", "generated/**"]

[security]
sinks = ["raw_sql", "dangerous_call"]
auth_markers = ["require_admin", "login_required"]
validation_markers = ["validate_payload"]
secret_markers = ["DATABASE_URL"]
```

## 5. Use it in pull requests

The generated GitHub Action builds the graph, creates a PR review comment, exports SARIF, and uploads an HTML report artifact.

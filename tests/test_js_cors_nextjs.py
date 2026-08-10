from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.javascript import analyze_javascript_file


def _run(tmp_path: Path, name: str, src: str):
    p = tmp_path / name
    p.write_text(src, encoding="utf-8")
    _n, _e, findings = analyze_javascript_file(p, tmp_path)
    return [f.rule_id for f in findings]


def test_express_credentialed_wildcard_cors_is_flagged(tmp_path):
    src = "const cors = require('cors');\napp.use(cors({ origin: '*', credentials: true }));\n"
    assert "CG-CORS-CREDENTIALED-WILDCARD" in _run(tmp_path, "server.js", src)


def test_express_origin_true_with_credentials_is_flagged(tmp_path):
    src = "app.use(cors({ origin: true, credentials: true }));\n"
    assert "CG-CORS-CREDENTIALED-WILDCARD" in _run(tmp_path, "server.js", src)


def test_scoped_cors_is_clean(tmp_path):
    src = "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));\n"
    assert "CG-CORS-CREDENTIALED-WILDCARD" not in _run(tmp_path, "server.js", src)


def test_bare_cors_is_clean(tmp_path):
    src = "app.use(cors());\n"
    assert "CG-CORS-CREDENTIALED-WILDCARD" not in _run(tmp_path, "server.js", src)


def test_next_public_secret_is_flagged(tmp_path):
    src = "const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n"
    assert "CG-CLIENT-SECRET-EXPOSED" in _run(tmp_path, "config.ts", src)


def test_next_public_url_is_clean(tmp_path):
    src = "const u = process.env.NEXT_PUBLIC_API_URL;\n"
    assert "CG-CLIENT-SECRET-EXPOSED" not in _run(tmp_path, "config.ts", src)


def test_server_side_secret_is_not_a_client_boundary_finding(tmp_path):
    src = "const k = process.env.STRIPE_SECRET_KEY;\n"
    assert "CG-CLIENT-SECRET-EXPOSED" not in _run(tmp_path, "server.ts", src)


def test_next_public_key_substring_names_are_clean(tmp_path):
    src = (
        "const a = process.env.NEXT_PUBLIC_TURNKEY_URL;\n"
        "const b = process.env.NEXT_PUBLIC_MONKEY_ISLAND;\n"
        "const c = process.env.NEXT_PUBLIC_KEYBOARD_LAYOUT;\n"
    )
    assert "CG-CLIENT-SECRET-EXPOSED" not in _run(tmp_path, "config.ts", src)


def test_next_public_api_key_is_flagged(tmp_path):
    src = "const k = process.env.NEXT_PUBLIC_API_KEY;\n"
    assert "CG-CLIENT-SECRET-EXPOSED" in _run(tmp_path, "config.ts", src)


def test_publishable_key_is_clean(tmp_path):
    src = (
        "const a = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;\n"
        "const b = process.env.NEXT_PUBLIC_PUBLIC_KEY;\n"
    )
    assert "CG-CLIENT-SECRET-EXPOSED" not in _run(tmp_path, "config.ts", src)


def test_public_but_strong_secret_still_flags(tmp_path):
    src = "const k = process.env.NEXT_PUBLIC_PUBLIC_SECRET_KEY;\n"
    assert "CG-CLIENT-SECRET-EXPOSED" in _run(tmp_path, "config.ts", src)


def test_api_key_still_flags(tmp_path):
    src = "const k = process.env.NEXT_PUBLIC_API_KEY;\n"
    assert "CG-CLIENT-SECRET-EXPOSED" in _run(tmp_path, "config.ts", src)


def test_brace_string_with_stray_brace_does_not_false_flag(tmp_path):
    src = (
        "app.use(cors({ origin: '*', credentials: false, "
        "fmt: 'status { code' }));\n"
        "otherMiddleware({ credentials: true });\n"
    )
    assert "CG-CORS-CREDENTIALED-WILDCARD" not in _run(tmp_path, "server.js", src)

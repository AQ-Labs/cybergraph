from __future__ import annotations

from pathlib import Path

from cybergraph.analysis.python import analyze_python_file


def _run(tmp_path: Path, src: str):
    p = tmp_path / "main.py"
    p.write_text(src, encoding="utf-8")
    _nodes, _edges, findings = analyze_python_file(p, tmp_path)
    return [f.rule_id for f in findings]


CRED_WILDCARD = """from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
"""

SCOPED = """from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(
    CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True
)
"""

WILDCARD_NO_CREDS = """from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"])
"""

REGEX_ALL = """from starlette.middleware.cors import CORSMiddleware
app.add_middleware(CORSMiddleware, allow_origin_regex=".*", allow_credentials=True)
"""


def test_credentialed_wildcard_is_flagged(tmp_path):
    assert _run(tmp_path, CRED_WILDCARD) == ["CG-CORS-CREDENTIALED-WILDCARD"]


def test_scoped_origin_is_clean(tmp_path):
    assert "CG-CORS-CREDENTIALED-WILDCARD" not in _run(tmp_path, SCOPED)


def test_wildcard_without_credentials_is_clean(tmp_path):
    assert "CG-CORS-CREDENTIALED-WILDCARD" not in _run(tmp_path, WILDCARD_NO_CREDS)


def test_regex_all_origins_with_credentials_is_flagged(tmp_path):
    assert _run(tmp_path, REGEX_ALL) == ["CG-CORS-CREDENTIALED-WILDCARD"]

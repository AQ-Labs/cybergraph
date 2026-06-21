"""Tests for the Dockerfile security analyzer."""

from __future__ import annotations

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph import GraphStore

_RISKY = """\
FROM python:latest
ENV API_KEY=supersecretvalue
ADD https://example.com/install.sh /tmp/install.sh
RUN curl https://get.example.com | bash
CMD ["python", "app.py"]
"""

_SAFE = """\
FROM python:3.12-slim
ARG BUILD_VERSION
ENV APP_VERSION=$BUILD_VERSION
COPY . /app
RUN pip install -r /app/requirements.txt
USER appuser
CMD ["python", "app.py"]
"""


def _build(tmp_path: Path, name: str, content: str) -> Path:
    repo = tmp_path / "svc"
    repo.mkdir(exist_ok=True)
    (repo / name).write_text(content, encoding="utf-8")
    build_graph(repo)
    return repo


def _findings(repo: Path) -> dict[str, str]:
    store = GraphStore.open_for_repo(repo.resolve())
    try:
        return {
            r["rule_id"]: r["severity"]
            for r in store.conn.execute("SELECT rule_id, severity FROM findings")
        }
    finally:
        store.close()


def test_risky_dockerfile_flags_all(tmp_path: Path):
    repo = _build(tmp_path, "Dockerfile", _RISKY)
    findings = _findings(repo)
    assert findings.get("CG-DOCKER-UNPINNED-BASE") == "low"     # :latest
    assert findings.get("CG-DOCKER-SECRET") == "critical"        # ENV API_KEY=literal
    assert findings.get("CG-DOCKER-ADD-REMOTE") == "medium"
    assert findings.get("CG-DOCKER-REMOTE-EXEC") == "high"       # curl | bash
    assert findings.get("CG-DOCKER-ROOT-USER") == "medium"       # no USER


def test_safe_dockerfile_is_clean(tmp_path: Path):
    repo = _build(tmp_path, "Dockerfile", _SAFE)
    findings = _findings(repo)
    # Pinned tag, non-literal ENV (build arg), COPY, and a non-root USER -> nothing.
    assert findings == {}


def test_dockerfile_suffix_variant_is_analyzed(tmp_path: Path):
    repo = _build(tmp_path, "api.dockerfile", "FROM node\nRUN echo hi\n")
    findings = _findings(repo)
    # No tag -> unpinned; no USER -> root.
    assert "CG-DOCKER-UNPINNED-BASE" in findings
    assert "CG-DOCKER-ROOT-USER" in findings


def test_inline_suppression_silences_docker_finding(tmp_path: Path):
    repo = _build(
        tmp_path,
        "Dockerfile",
        "# cybergraph: ignore CG-DOCKER-UNPINNED-BASE\nFROM python:latest\nUSER app\n",
    )
    assert "CG-DOCKER-UNPINNED-BASE" not in _findings(repo)


def test_digest_pinned_base_not_flagged(tmp_path: Path):
    repo = _build(
        tmp_path,
        "Dockerfile",
        "FROM python@sha256:abc123\nUSER app\n",
    )
    assert "CG-DOCKER-UNPINNED-BASE" not in _findings(repo)

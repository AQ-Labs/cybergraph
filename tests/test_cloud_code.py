"""Tests for cloud/IaC to application-code correlation."""

from __future__ import annotations

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph import GraphStore
from cybergraph.security.cloud import find_cloud_code_paths, format_cloud_code_paths
from cybergraph.security.ontology import EDGE_USES_RESOURCE


def test_code_references_public_iac_resource(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "main.tf").write_text(
        'resource "aws_s3_bucket" "uploads" {\n'
        '  bucket = "uploads"\n'
        '  acl    = "public-read"\n'
        "}\n",
        encoding="utf-8",
    )
    (repo / "app.py").write_text(
        "@app.get('/download')\n"
        "def download(request):\n"
        "    bucket = 'uploads'\n"
        "    q = request.query['q']\n"
        "    return db.execute('select ' + q)\n",
        encoding="utf-8",
    )

    build_graph(repo)

    store = GraphStore.open_for_repo(repo)
    try:
        uses_resource = store.conn.execute(
            "SELECT COUNT(*) FROM edges WHERE kind = ?", (EDGE_USES_RESOURCE,)
        ).fetchone()[0]
    finally:
        store.close()

    paths = find_cloud_code_paths(repo)
    output = format_cloud_code_paths(paths)

    assert uses_resource >= 1
    assert any(path.resource == "aws_s3_bucket.uploads" for path in paths)
    assert "aws_s3_bucket.uploads" in output
    assert "db.execute" in output

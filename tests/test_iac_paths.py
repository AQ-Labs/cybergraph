"""Tests for cross-resource cloud attack paths over Terraform resources."""

from __future__ import annotations

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph import GraphStore
from cybergraph.security.iac_paths import find_iac_attack_paths

# Public SG -> EC2 instance (references the SG and the admin policy) -> wildcard IAM.
_CONNECTED = """
resource "aws_security_group" "web" {
  ingress { cidr_blocks = ["0.0.0.0/0"] }
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}

resource "aws_instance" "app" {
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_policy_arn         = aws_iam_policy.admin.arn
}
"""

# Public SG and wildcard IAM exist but nothing references them together.
_DISCONNECTED = """
resource "aws_security_group" "web" {
  ingress { cidr_blocks = ["0.0.0.0/0"] }
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}
"""


def _build(tmp_path: Path, tf: str) -> Path:
    repo = tmp_path / "infra"
    repo.mkdir()
    (repo / "main.tf").write_text(tf, encoding="utf-8")
    build_graph(repo)
    return repo


def test_references_resolved_edges_created(tmp_path: Path):
    repo = _build(tmp_path, _CONNECTED)
    store = GraphStore.open_for_repo(repo.resolve())
    try:
        refs = [
            (r["source"], r["target"])
            for r in store.conn.execute(
                "SELECT source, target FROM edges WHERE kind = 'REFERENCES_RESOLVED'"
            )
        ]
    finally:
        store.close()
    targets = {t.split("::", 1)[1] for _, t in refs}
    assert "aws_security_group.web" in targets
    assert "aws_iam_policy.admin" in targets


def test_attack_path_public_to_privileged(tmp_path: Path):
    repo = _build(tmp_path, _CONNECTED)
    paths = find_iac_attack_paths(repo)

    assert paths, "expected a public-exposure -> privileged path"
    path = paths[0]
    assert path.entrypoint == "aws_security_group.web"
    assert path.sink == "aws_iam_policy.admin"
    assert "aws_instance.app" in path.nodes  # pivots through the compute resource
    assert path.confidence == "high"          # two hops


def test_no_path_when_resources_disconnected(tmp_path: Path):
    repo = _build(tmp_path, _DISCONNECTED)
    assert find_iac_attack_paths(repo) == []


def test_no_path_without_privileged_resource(tmp_path: Path):
    repo = _build(
        tmp_path,
        'resource "aws_security_group" "web" {\n  ingress { cidr_blocks = ["0.0.0.0/0"] }\n}\n',
    )
    assert find_iac_attack_paths(repo) == []

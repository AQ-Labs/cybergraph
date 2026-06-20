"""Tests for the Terraform (IaC) misconfiguration analyzer."""

from __future__ import annotations

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph import GraphStore
from cybergraph.security.layers import summarize_layers

_TF = """
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  acl    = "public-read"
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_db_instance" "main" {
  username = "admin"
  password = "hunter2supersecret"
}

resource "aws_instance" "app" {
  ami = "ami-123"
}
"""


def _build(tmp_path: Path) -> Path:
    repo = tmp_path / "infra"
    repo.mkdir()
    (repo / "main.tf").write_text(_TF, encoding="utf-8")
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


def _nodes(repo: Path, kind: str) -> list[str]:
    store = GraphStore.open_for_repo(repo.resolve())
    try:
        return [r["name"] for r in store.conn.execute("SELECT name FROM nodes WHERE kind = ?", (kind,))]
    finally:
        store.close()


def test_terraform_misconfigurations_detected(tmp_path: Path):
    repo = _build(tmp_path)
    findings = _findings(repo)

    assert findings.get("CG-IAC-OPEN-INGRESS") == "high"
    assert findings.get("CG-IAC-PUBLIC-BUCKET") == "high"
    assert findings.get("CG-IAC-WILDCARD-IAM") == "high"
    assert findings.get("CG-IAC-HARDCODED-SECRET") == "critical"


def test_terraform_creates_resource_nodes(tmp_path: Path):
    repo = _build(tmp_path)
    resources = _nodes(repo, "Resource")
    # One Resource node per resource block (5 blocks).
    assert len(resources) == 5
    assert "aws_security_group.web" in resources
    assert "aws_instance.app" in resources


def test_public_ingress_modeled_as_entrypoint(tmp_path: Path):
    repo = _build(tmp_path)
    entrypoints = _nodes(repo, "Entrypoint")
    assert "aws_security_group.web" in entrypoints


def test_benign_resource_has_no_finding(tmp_path: Path):
    """The plain aws_instance must not raise any IaC finding (no false positive)."""
    repo = tmp_path / "infra"
    repo.mkdir()
    (repo / "ok.tf").write_text(
        'resource "aws_instance" "app" {\n  ami = "ami-123"\n  instance_type = "t3.micro"\n}\n',
        encoding="utf-8",
    )
    build_graph(repo)
    assert _findings(repo) == {}


def test_inline_suppression_silences_iac_finding(tmp_path: Path):
    repo = tmp_path / "infra"
    repo.mkdir()
    (repo / "sg.tf").write_text(
        'resource "aws_security_group" "web" {\n'
        "  ingress {\n"
        "    # cybergraph: ignore CG-IAC-OPEN-INGRESS\n"
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    build_graph(repo)
    assert "CG-IAC-OPEN-INGRESS" not in _findings(repo)


def test_layers_reports_infrastructure(tmp_path: Path):
    repo = _build(tmp_path)
    summary = summarize_layers(repo)
    infra = next(item for item in summary if item.key == "infrastructure")
    assert infra.node_count == 5          # five Resource nodes
    assert infra.finding_count >= 4       # the IaC findings

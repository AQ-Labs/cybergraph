from __future__ import annotations

import json
from pathlib import Path

import pytest

from cybergraph.analysis.bucket_policy import analyze_bucket_policy_file

S3_PUBLIC = {
    "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::b/*"}
    ]
}
S3_SCOPED = {
    "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:role/r"},
         "Action": "s3:GetObject"}
    ]
}
GCS_PUBLIC = {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}


def _write(tmp_path: Path, obj) -> Path:
    p = tmp_path / "bucket-policy.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def test_s3_public_principal_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, S3_PUBLIC)
    _n, _e, findings = analyze_bucket_policy_file(p, tmp_path)
    assert [f.rule_id for f in findings] == ["CG-STORAGE-BUCKET-PUBLIC"]
    assert findings[0].cwe == "CWE-732"


def test_s3_scoped_principal_is_clean(tmp_path: Path) -> None:
    p = _write(tmp_path, S3_SCOPED)
    _n, _e, findings = analyze_bucket_policy_file(p, tmp_path)
    assert findings == []


def test_gcs_all_users_is_flagged(tmp_path: Path) -> None:
    p = _write(tmp_path, GCS_PUBLIC)
    _n, _e, findings = analyze_bucket_policy_file(p, tmp_path)
    assert [f.rule_id for f in findings] == ["CG-STORAGE-BUCKET-PUBLIC"]


def test_non_policy_json_is_clean(tmp_path: Path) -> None:
    p = _write(tmp_path, {"name": "not a policy", "version": 3})
    nodes, _e, findings = analyze_bucket_policy_file(p, tmp_path)
    assert findings == []
    assert any(n.kind == "File" for n in nodes)


def test_malformed_json_propagates_valueerror(tmp_path: Path) -> None:
    p = tmp_path / "bucket-policy.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):  # JSONDecodeError is a ValueError
        analyze_bucket_policy_file(p, tmp_path)

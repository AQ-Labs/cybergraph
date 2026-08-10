from __future__ import annotations

import json
import sys

import pytest

from cybergraph.hooks import base


def test_resolve_invocation_is_path_independent() -> None:
    assert base.resolve_invocation() == [sys.executable, "-m", "cybergraph"]
    assert "-m cybergraph" in base.quoted_invocation()


def test_read_json_missing_and_blank_are_empty(tmp_path) -> None:
    assert base.read_json(tmp_path / "nope.json") == {}
    blank = tmp_path / "blank.json"
    blank.write_text("   \n", encoding="utf-8")
    assert base.read_json(blank) == {}


def test_read_json_malformed_raises(tmp_path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        base.read_json(bad)


def test_write_json_roundtrips_and_creates_parents(tmp_path) -> None:
    target = tmp_path / "nested" / "settings.json"
    base.write_json(target, {"a": 1, "hooks": {"Stop": []}})
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1, "hooks": {"Stop": []}}


def test_install_result_ok_flags() -> None:
    assert base.InstallResult(base.Status.INSTALLED, "x").ok
    assert base.InstallResult(base.Status.ALREADY_PRESENT, "x").ok
    assert base.InstallResult(base.Status.ABSENT, "x").ok
    assert not base.InstallResult(base.Status.REFUSED_FOREIGN, "x").ok
    assert not base.InstallResult(base.Status.NOT_A_REPO, "x").ok

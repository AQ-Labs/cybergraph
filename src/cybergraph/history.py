"""Persist finding snapshots and compute what changed between scans."""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cybergraph.graph import GraphStore


def fingerprint(rule_id: str, tool: str, file_path: str, message: str) -> str:
    """Line-independent identity for a finding across scans."""
    raw = f"{rule_id}|{tool}|{file_path}|{message}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()

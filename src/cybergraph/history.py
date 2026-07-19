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


@dataclass
class ScanResult:
    scan_id: int
    no_change: bool
    is_first: bool
    new: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    regressed: list[str] = field(default_factory=list)
    persisting: list[str] = field(default_factory=list)


def _git_head(repo_root: Path) -> tuple[str, str]:
    def _run(args: list[str]) -> str:
        try:
            out = subprocess.run(
                ["git", "-C", str(repo_root), *args],
                capture_output=True, text=True, timeout=5,
            )
            return out.stdout.strip() if out.returncode == 0 else ""
        except Exception:
            return ""
    sha = _run(["rev-parse", "HEAD"])
    branch = _run(["rev-parse", "--abbrev-ref", "HEAD"]) if sha else ""
    return sha, branch


def record_scan(
    repo_root: Path, *, top_risk_score: int = 0, top_risk_label: str = ""
) -> ScanResult:
    repo_root = Path(repo_root).resolve()
    store = GraphStore.open_for_repo(repo_root)
    conn = store.conn
    ts = datetime.now(timezone.utc).isoformat()
    sha, branch = _git_head(repo_root)
    try:
        current: dict[str, dict] = {}
        for r in conn.execute(
            "SELECT rule_id, tool, file_path, message, severity, line_start FROM findings"
        ):
            fp = fingerprint(r["rule_id"], r["tool"], r["file_path"], r["message"])
            current[fp] = dict(r)
        current_set = set(current)

        prev = conn.execute("SELECT id, git_sha FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        is_first = prev is None
        prev_set: set[str] = set()
        if prev is not None:
            prev_set = {row["fingerprint"] for row in conn.execute(
                "SELECT fingerprint FROM scan_findings WHERE scan_id = ?", (prev["id"],))}

        # No-change shortcut: identical set + same SHA -> no new row, but still
        # advance last_seen and refresh severity/line (a finding can be re-rated
        # in place without changing the fingerprint set).
        if prev is not None and current_set == prev_set and (prev["git_sha"] or "") == sha:
            with conn:
                conn.executemany(
                    "UPDATE finding_history SET last_seen_ts = ?, severity = ?, "
                    "line_start = ? WHERE fingerprint = ?",
                    [(ts, current[fp]["severity"], current[fp]["line_start"], fp)
                     for fp in current_set],
                )
            return ScanResult(prev["id"], no_change=True, is_first=False,
                              persisting=sorted(current_set))

        counts = store.counts()
        new: list[str] = []
        regressed: list[str] = []
        persisting: list[str] = []
        fixed: list[str] = []
        with conn:
            cur = conn.execute(
                "INSERT INTO scans(ts, git_sha, git_branch, node_count, edge_count, "
                "finding_count, top_risk_score, top_risk_label) VALUES (?,?,?,?,?,?,?,?)",
                (ts, sha, branch, counts["nodes"], counts["edges"], counts["findings"],
                 top_risk_score, top_risk_label),
            )
            scan_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO scan_findings(scan_id, fingerprint) VALUES (?, ?)",
                [(scan_id, fp) for fp in current_set],
            )
            for fp in current_set:
                r = current[fp]
                existing = conn.execute(
                    "SELECT status FROM finding_history WHERE fingerprint = ?", (fp,)).fetchone()
                if existing is None:
                    conn.execute(
                        "INSERT INTO finding_history(fingerprint, rule_id, tool, file_path, "
                        "severity, message, line_start, first_seen_scan, last_seen_scan, "
                        "first_seen_ts, last_seen_ts, status, reopened_count) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?, 'open', 0)",
                        (fp, r["rule_id"], r["tool"], r["file_path"], r["severity"],
                         r["message"], r["line_start"], scan_id, scan_id, ts, ts),
                    )
                    new.append(fp)
                elif existing["status"] == "fixed":
                    # Refresh severity/line (not part of the fingerprint) so a re-rated
                    # finding doesn't keep stale metadata the trends slice will read.
                    conn.execute(
                        "UPDATE finding_history SET status='open', fixed_ts='', "
                        "reopened_count = reopened_count + 1, severity = ?, line_start = ?, "
                        "last_seen_scan = ?, last_seen_ts = ? WHERE fingerprint = ?",
                        (r["severity"], r["line_start"], scan_id, ts, fp))
                    regressed.append(fp)
                else:
                    conn.execute(
                        "UPDATE finding_history SET severity = ?, line_start = ?, "
                        "last_seen_scan = ?, last_seen_ts = ? WHERE fingerprint = ?",
                        (r["severity"], r["line_start"], scan_id, ts, fp))
                    persisting.append(fp)
            for row in conn.execute(
                "SELECT fingerprint FROM finding_history WHERE status = 'open'").fetchall():
                fp = row["fingerprint"]
                if fp not in current_set:
                    conn.execute(
                        "UPDATE finding_history SET status='fixed', fixed_ts = ? "
                        "WHERE fingerprint = ?", (ts, fp))
                    fixed.append(fp)
        return ScanResult(scan_id, no_change=False, is_first=is_first,
                          new=sorted(new), fixed=sorted(fixed),
                          regressed=sorted(regressed), persisting=sorted(persisting))
    finally:
        store.close()


@dataclass
class Delta:
    is_first: bool
    new: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    regressed: list[str] = field(default_factory=list)
    persisting: list[str] = field(default_factory=list)


def scan_delta(repo_root: Path) -> Delta:
    """Change between the two most recent scans (from stored membership)."""
    store = GraphStore.open_for_repo(Path(repo_root).resolve())
    conn = store.conn
    try:
        scans = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 2").fetchall()
        if not scans:
            return Delta(is_first=True)
        curr = scans[0]["id"]
        curr_set = {r["fingerprint"] for r in conn.execute(
            "SELECT fingerprint FROM scan_findings WHERE scan_id = ?", (curr,))}
        if len(scans) == 1:
            return Delta(is_first=True, new=sorted(curr_set))
        prev = scans[1]["id"]
        prev_set = {r["fingerprint"] for r in conn.execute(
            "SELECT fingerprint FROM scan_findings WHERE scan_id = ?", (prev,))}
        appeared = curr_set - prev_set
        fixed = sorted(prev_set - curr_set)
        persisting = sorted(curr_set & prev_set)
        # appeared before this scan's predecessor -> regression; else genuinely new.
        regressed, new = [], []
        for fp in sorted(appeared):
            row = conn.execute(
                "SELECT first_seen_scan FROM finding_history WHERE fingerprint = ?", (fp,)
            ).fetchone()
            if row is not None and row["first_seen_scan"] < curr:
                regressed.append(fp)
            else:
                new.append(fp)
        return Delta(
            is_first=False, new=new, fixed=fixed, regressed=regressed, persisting=persisting
        )
    finally:
        store.close()


def list_scans(repo_root: Path, limit: int = 20) -> list[dict]:
    store = GraphStore.open_for_repo(Path(repo_root).resolve())
    try:
        return [dict(r) for r in store.conn.execute(
            "SELECT id, ts, git_sha, git_branch, node_count, edge_count, finding_count, "
            "top_risk_score, top_risk_label FROM scans ORDER BY id DESC LIMIT ?", (limit,))]
    finally:
        store.close()


def format_delta_line(d: Delta) -> str:
    return f"+{len(d.new)} new, -{len(d.fixed)} fixed, {len(d.regressed)} regressed"


def format_history(rows: list[dict], delta: Delta) -> str:
    if not rows:
        return "No scan history yet. Run 'cybergraph analyze' or 'build' to record one."
    lines = [f"Scan history ({len(rows)} most recent):"]
    for r in rows:
        sha = (r["git_sha"] or "")[:7] or "-"
        lines.append(
            f"  #{r['id']} {r['ts']} [{sha}] "
            f"findings={r['finding_count']} nodes={r['node_count']}"
        )
    if not delta.is_first:
        lines.append(f"Since previous scan: {format_delta_line(delta)}.")
    return "\n".join(lines)

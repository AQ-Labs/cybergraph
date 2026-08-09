"""Traversal invariants stated only in docstrings, asserted nowhere.

The path-depth bound, the weakest-edge confidence rule, the unknown-edge
confidence default, and the fail-open behaviour of ``path_is_suppressed`` for a
path with no identifiable file. Each is a single character or default away from
a silent miss and none had a test.
"""

from __future__ import annotations

import json
from pathlib import Path

from cybergraph.analysis.resolve import EDGE_CALLS_RESOLVED
from cybergraph.build import build_graph
from cybergraph.graph import GraphStore
from cybergraph.security.attack_paths import find_attack_paths, path_is_suppressed

# route -> a -> b -> db.execute: two resolved-call hops, so the path has a
# confidence made of more than one edge, and a depth of four nodes.
CHAIN = (
    "@app.get('/u')\n"
    "def route(name: str):\n"
    "    return a(name)\n"
    "def a(name):\n"
    "    return b(name)\n"
    "def b(name):\n"
    "    return db.execute('select ' + name)\n"
)


def _chain_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "chain"
    repo.mkdir()
    (repo / "app.py").write_text(CHAIN, encoding="utf-8")
    build_graph(repo)
    return repo


def _set_edge_confidence(repo: Path, source: str, confidence: str) -> None:
    """Rewrite one ``CALLS_RESOLVED`` edge's confidence in the stored graph."""
    store = GraphStore.open_for_repo(repo)
    try:
        with store.conn:
            for row in store.conn.execute(
                "SELECT rowid AS rid, properties FROM edges WHERE kind = ? AND source = ?",
                (EDGE_CALLS_RESOLVED, source),
            ).fetchall():
                props = json.loads(row["properties"]) if row["properties"] else {}
                props["confidence"] = confidence
                store.conn.execute(
                    "UPDATE edges SET properties = ? WHERE rowid = ?",
                    (json.dumps(props), row["rid"]),
                )
    finally:
        store.close()


def _the_chain_path(repo: Path, **kwargs):
    paths = find_attack_paths(repo, **kwargs)
    return next(
        (p for p in paths if p.nodes == ("app.py::route", "app.py::a", "app.py::b", "db.execute")),
        None,
    )


def test_the_max_depth_bound_is_inclusive(tmp_path: Path) -> None:
    """`if len(path) > max_depth` admits a path exactly ``max_depth`` hops deep.

    Turning it into ``>=`` truncates every path by one hop -- the last resolved
    call is never expanded, so the four-node chain vanishes at ``max_depth=2``.
    """
    repo = _chain_repo(tmp_path)
    assert _the_chain_path(repo, max_depth=2) is not None, find_attack_paths(repo, max_depth=2)


def test_path_confidence_is_the_weakest_edge(tmp_path: Path) -> None:
    """Confidence is the minimum over resolved edges, not the maximum.

    One hop is forced to ``low`` while the other stays ``high``; the path must
    read ``low``. Taking the strongest edge instead reports ``high`` on a path
    whose weakest link is anything but.
    """
    repo = _chain_repo(tmp_path)
    _set_edge_confidence(repo, "app.py::route", "low")

    path = _the_chain_path(repo)
    assert path is not None
    assert path.confidence == "low", path.confidence


def test_an_unknown_edge_confidence_defaults_to_low(tmp_path: Path) -> None:
    """An unrecognised confidence token ranks as low, not high.

    ``_CONF_RANK.get(edge_conf, 1)`` fails safe: a confidence the ranking does
    not recognise must weaken the path, never strengthen it. Defaulting to ``3``
    would let an unreadable edge silently upgrade a path to ``high``.
    """
    repo = _chain_repo(tmp_path)
    _set_edge_confidence(repo, "app.py::route", "totally-unknown-token")

    path = _the_chain_path(repo)
    assert path is not None
    assert path.confidence == "low", path.confidence


def test_a_path_with_no_identifiable_file_is_never_suppressed() -> None:
    """A path whose nodes carry no file component must abstain from hiding.

    ``if not files: return False`` -- an unknown file is treated as
    unsuppressed, so incomplete information never hides a path silently.
    Flipping it to ``return True`` would suppress any bare-sink-only path against
    any config.
    """
    assert path_is_suppressed(("subprocess.run",), ("*",)) is False
    # Calibration: when every node *does* carry a suppressed file, it hides.
    assert path_is_suppressed(("app.py::f", "subprocess.run"), ("app.py",)) is True

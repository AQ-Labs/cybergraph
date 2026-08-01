# tests/test_report_banner.py
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.visualize import _truncation_banner, generate_html_report


def test_banner_when_truncated():
    html = _truncation_banner({"truncated": True, "nodes": [0] * 600, "counts": {"nodes": 1500}})
    assert "600" in html and "1500" in html and "max-nodes" in html


def test_no_banner_when_not_truncated():
    assert (
        _truncation_banner({"truncated": False, "nodes": [0] * 10, "counts": {"nodes": 10}})
        == ""
    )


def test_max_nodes_flag_lifts_the_cap(tmp_path: Path) -> None:
    """`visualize --max-nodes` must be able to raise the cap the banner mentions."""
    repo = tmp_path / "repo"
    repo.mkdir()
    # Enough functions to exceed a deliberately tiny cap.
    lines = ["import sqlite3", "from fastapi import FastAPI", "app = FastAPI()"]
    for i in range(30):
        lines += [
            f"@app.get('/r{i}')",
            f"def route_{i}(q: str):",
            "    db = sqlite3.connect('x.db')",
            "    return db.execute('select ' + q)",
        ]
    (repo / "app.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    build_graph(repo)

    capped = tmp_path / "capped.html"
    generate_html_report(repo, capped, max_nodes=5)
    assert "raise <code>--max-nodes</code>" in capped.read_text(encoding="utf-8")

    full = tmp_path / "full.html"
    generate_html_report(repo, full, max_nodes=5000)
    assert "raise <code>--max-nodes</code>" not in full.read_text(encoding="utf-8")


def test_visualize_cli_accepts_max_nodes() -> None:
    """The flag the banner tells users to raise must exist on `visualize`."""
    from cybergraph.cli import build_parser

    args = build_parser().parse_args(["visualize", ".", "--max-nodes", "900"])
    assert args.max_nodes == 900


def test_banner_denominator_counts_exported_nodes() -> None:
    """`shown` and `total` must both count exported nodes.

    counts["nodes"] is the database row count, which is smaller than the
    exported graph (the export synthesises edge-endpoint nodes), so using it
    as the denominator produced nonsense like "Showing 900 of 826".
    """
    html = _truncation_banner(
        {
            "truncated": True,
            "nodes": [0] * 900,
            "counts": {"nodes": 826},
            "graph_nodes_total": 1247,
        }
    )
    assert "900 of 1247" in html
    assert "of 826" not in html

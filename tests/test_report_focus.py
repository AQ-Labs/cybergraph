"""Focused graph presentation remains self-contained and does not change evidence."""

from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph import GraphStore
from cybergraph.visualize import generate_html_report


def test_focus_assets_are_offline_and_preserve_graph(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\napp = Flask(__name__)\n"
        '@app.route("/run")\ndef run():\n    return eval(request.args["q"])\n',
        encoding="utf-8",
    )
    build_graph(tmp_path)
    store = GraphStore.open_for_repo(tmp_path)
    before = store.counts()
    store.close()
    report = generate_html_report(tmp_path, with_source=True).read_text(encoding="utf-8")
    assert "CyberGraph connected shield" in report
    assert 'id="cg-focus"' in report
    assert 'id="cg-motion"' in report
    assert "focusedEdges.has(e.id())" in report
    assert "document.addEventListener('visibilitychange', syncMotion)" in report
    assert "motionControl.disabled = !focusedIds || reducedMotion.matches" in report
    assert "if (reducedMotion.matches || focusControl.checked) return" in report
    assert "__BRAND_MARK__" not in report
    assert "<script src=" not in report
    store = GraphStore.open_for_repo(tmp_path)
    assert store.counts() == before
    store.close()

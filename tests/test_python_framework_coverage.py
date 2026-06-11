"""Framework-specific Python coverage: Flask blueprints and Django URLconf."""

from __future__ import annotations

import json
from pathlib import Path

from cybergraph.build import build_graph
from cybergraph.graph import GraphStore
from cybergraph.security.attack_paths import find_attack_paths


def _entrypoint_frameworks(repo: Path) -> set[str]:
    store = GraphStore.open_for_repo(repo)
    try:
        rows = store.conn.execute(
            "SELECT properties FROM nodes WHERE kind = 'Entrypoint'"
        ).fetchall()
    finally:
        store.close()
    frameworks: set[str] = set()
    for row in rows:
        props = json.loads(row["properties"] or "{}")
        if props.get("framework"):
            frameworks.add(props["framework"])
    return frameworks


def test_flask_blueprint_route_is_entrypoint(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "views.py").write_text(
        "bp = Blueprint('main', __name__)\n"
        "\n"
        "@bp.route('/profile')\n"
        "def profile(request):\n"
        "    return db.execute('select 1')\n",
        encoding="utf-8",
    )
    build_graph(repo)

    store = GraphStore.open_for_repo(repo)
    try:
        entrypoints = store.conn.execute(
            "SELECT COUNT(*) FROM edges WHERE kind = 'EXPOSES_ENTRYPOINT'"
        ).fetchone()[0]
    finally:
        store.close()
    assert entrypoints >= 1  # @bp.route is recognised


def test_django_urlconf_route_reaches_view_sink(tmp_path: Path) -> None:
    repo = tmp_path / "site"
    repo.mkdir()
    (repo / "urls.py").write_text(
        "from django.urls import path\n"
        "from . import views\n"
        "urlpatterns = [\n"
        "    path('users/', views.list_users),\n"
        "]\n",
        encoding="utf-8",
    )
    (repo / "views.py").write_text(
        "def list_users(request):\n"
        "    name = request.GET['q']\n"
        "    return User.objects.raw('select * from users where n=' + name)\n",
        encoding="utf-8",
    )
    build_graph(repo)

    assert "django" in _entrypoint_frameworks(repo)

    # The Django route should reach the raw() sink in the view, across files.
    paths = find_attack_paths(repo)
    reaches_view = any(
        "views.py::list_users" in p.nodes and "urls.py::route:users/" in p.nodes[0]
        for p in paths
    )
    assert reaches_view, f"expected route->view->sink path, got {[p.nodes for p in paths]}"

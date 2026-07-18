import os

from cybergraph.output import render_text, should_color
from cybergraph.report_model import AnalysisResult
from cybergraph.security.investigate import TopRisk


def _result(**over):
    base = dict(
        repo="/x/app", counts={"nodes": 5, "edges": 3, "findings": 2},
        top_risks=[TopRisk("attack-path", "route -> sink", 82, "high", "reachable")],
        attack_paths=[1], secret_exposures=[], sca=[], iac_paths=[], cloud_code_paths=[],
        layers=[], truncated=False, timings={}, llm_configured=False, errors={},
    )
    base.update(over)
    return AnalysisResult(**base)


def test_render_text_plain_lists_top_risks_and_counts():
    out = render_text(_result(), color=False)
    assert "route -> sink" in out
    assert "HIGH" in out and "82" in out
    assert "Nodes: 5" in out
    assert "\x1b[" not in out  # no ANSI when color=False


def test_render_text_color_emits_ansi():
    out = render_text(_result(), color=True)
    assert "\x1b[" in out


def test_truncation_banner_shown_only_when_truncated():
    assert "truncated" in render_text(_result(truncated=True), color=False).lower()
    assert "truncated" not in render_text(_result(truncated=False), color=False).lower()


def test_should_color_respects_no_color_env(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert should_color() is False

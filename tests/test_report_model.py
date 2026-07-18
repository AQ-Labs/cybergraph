from cybergraph.report_model import AnalysisResult, to_json
from cybergraph.security.investigate import TopRisk
from cybergraph.security.layers import LayerSummary


def _sample() -> AnalysisResult:
    return AnalysisResult(
        repo="/x/app",
        counts={"nodes": 5, "edges": 3, "findings": 2},
        top_risks=[TopRisk("attack-path", "route -> sink", 82, "high", "why")],
        attack_paths=[object()],
        secret_exposures=[],
        sca=[object(), object()],
        iac_paths=[],
        cloud_code_paths=[],
        layers=[LayerSummary("sink", "Sensitive Sinks", "d", 1, 1, 1)],
        truncated=True,
        timings={"build": 0.1},
        llm_configured=False,
        errors={},
    )


def test_to_json_has_stable_schema_and_counts():
    doc = to_json(_sample())
    assert doc["schema"] == "cybergraph.analysis/1"
    assert doc["repo"] == "/x/app"
    assert doc["counts"] == {"nodes": 5, "edges": 3, "findings": 2}
    assert doc["truncated"] is True
    assert doc["llm_configured"] is False
    # top risks serialized fully
    assert doc["top_risks"][0] == {
        "category": "attack-path", "title": "route -> sink",
        "risk_score": 82, "risk_label": "high", "detail": "why",
    }
    # component lists represented as counts in v1
    assert doc["component_counts"] == {
        "attack_paths": 1, "secret_exposures": 0, "sca": 2,
        "iac_paths": 0, "cloud_code_paths": 0,
    }
    assert doc["layers"][0]["key"] == "sink"
    assert doc["errors"] == {}

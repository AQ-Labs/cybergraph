"""Tests for the multi-provider LLM client configuration.

These tests never hit the network: they only exercise env-driven configuration
and the client protocol with a fake implementation.
"""

from __future__ import annotations

import pytest

from cybergraph.llm import (
    LLMClient,
    LLMConfig,
    LLMUnavailable,
    build_client,
    load_llm_config_from_env,
)


def test_no_config_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in [
        "CYBERGRAPH_LLM_PROVIDER",
        "CYBERGRAPH_LLM_API_KEY",
        "CYBERGRAPH_LLM_MODEL",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "MOONSHOT_API_KEY",
        "KIMI_API_KEY",
    ]:
        monkeypatch.delenv(key, raising=False)
    # Local-only by default: no provider configured -> no LLM.
    assert load_llm_config_from_env() is None


def test_kimi_config_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CYBERGRAPH_LLM_PROVIDER", "kimi")
    monkeypatch.setenv("MOONSHOT_API_KEY", "sk-test")
    monkeypatch.delenv("CYBERGRAPH_LLM_MODEL", raising=False)
    monkeypatch.delenv("CYBERGRAPH_LLM_BASE_URL", raising=False)

    config = load_llm_config_from_env()

    assert config is not None
    assert config.provider == "kimi"
    assert config.api_key == "sk-test"
    assert config.model == "kimi-k2"  # provider default
    assert config.base_url == "https://api.moonshot.ai/v1"


def test_missing_api_key_yields_no_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CYBERGRAPH_LLM_PROVIDER", "openai")
    for key in ["CYBERGRAPH_LLM_API_KEY", "OPENAI_API_KEY"]:
        monkeypatch.delenv(key, raising=False)
    assert load_llm_config_from_env() is None


def test_unknown_provider_raises() -> None:
    config = LLMConfig(provider="bogus", model="x", api_key="k")
    with pytest.raises(LLMUnavailable):
        build_client(config)


def test_fake_client_satisfies_protocol() -> None:
    class FakeClient:
        def complete(self, system: str, user: str) -> str:
            return f"{system[:4]}|{user[:4]}"

    client = FakeClient()
    assert isinstance(client, LLMClient)
    assert client.complete("system prompt", "user prompt") == "syst|user"

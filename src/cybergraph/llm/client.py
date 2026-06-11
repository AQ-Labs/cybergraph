"""Multi-provider LLM client.

Supports Anthropic (Claude) and any OpenAI-compatible endpoint, which covers
both OpenAI/GPT and Kimi 2.6 (Moonshot). Providers and credentials come from
environment variables; the underlying SDKs are optional dependencies imported
lazily so the rest of CyberGraph keeps working without them. Clients are a thin
protocol so tests can inject a fake.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class LLMUnavailable(RuntimeError):
    """Raised when an LLM is requested but cannot be constructed/used."""


@runtime_checkable
class LLMClient(Protocol):
    """Minimal completion interface. ``complete`` returns the model's text."""

    def complete(self, system: str, user: str) -> str:  # pragma: no cover - protocol
        ...


# provider -> (default base_url, default model). base_url None means "use the
# provider SDK's own default" (Anthropic / OpenAI).
_PROVIDER_DEFAULTS: dict[str, tuple[str | None, str]] = {
    "anthropic": (None, "claude-opus-4-8"),
    "openai": (None, "gpt-4o-mini"),
    "kimi": ("https://api.moonshot.ai/v1", "kimi-k2"),
    "moonshot": ("https://api.moonshot.ai/v1", "kimi-k2"),
}


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str
    api_key: str
    base_url: str | None = None
    temperature: float = 0.0
    max_tokens: int = 1024


def load_llm_config_from_env() -> LLMConfig | None:
    """Build a config from ``CYBERGRAPH_LLM_*`` env vars, or ``None`` if unset.

    Returning ``None`` keeps CyberGraph local-only: callers must treat a missing
    config as "no LLM" and fall back to deterministic, evidence-only answers.
    """
    provider = (os.environ.get("CYBERGRAPH_LLM_PROVIDER") or "").strip().lower()
    if not provider:
        return None
    default_base, default_model = _PROVIDER_DEFAULTS.get(provider, (None, ""))
    api_key = (
        os.environ.get("CYBERGRAPH_LLM_API_KEY")
        or _provider_env_key(provider)
        or ""
    )
    if not api_key:
        return None
    model = os.environ.get("CYBERGRAPH_LLM_MODEL") or default_model
    if not model:
        return None
    base_url = os.environ.get("CYBERGRAPH_LLM_BASE_URL") or default_base
    temperature = float(os.environ.get("CYBERGRAPH_LLM_TEMPERATURE", "0") or 0)
    max_tokens = int(os.environ.get("CYBERGRAPH_LLM_MAX_TOKENS", "1024") or 1024)
    return LLMConfig(
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=base_url,
        temperature=temperature,
        max_tokens=max_tokens,
    )


def _provider_env_key(provider: str) -> str | None:
    return {
        "anthropic": os.environ.get("ANTHROPIC_API_KEY"),
        "openai": os.environ.get("OPENAI_API_KEY"),
        "kimi": os.environ.get("MOONSHOT_API_KEY") or os.environ.get("KIMI_API_KEY"),
        "moonshot": os.environ.get("MOONSHOT_API_KEY"),
    }.get(provider)


def build_client(config: LLMConfig) -> LLMClient:
    """Construct a concrete client for the configured provider."""
    if config.provider == "anthropic":
        return _AnthropicClient(config)
    if config.provider in {"openai", "kimi", "moonshot"}:
        return _OpenAICompatibleClient(config)
    raise LLMUnavailable(f"Unknown LLM provider: {config.provider!r}")


class _AnthropicClient:
    def __init__(self, config: LLMConfig) -> None:
        try:
            import anthropic  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise LLMUnavailable(
                "Install cybergraph[llm] (anthropic) to use the Anthropic provider."
            ) from exc
        self._config = config
        kwargs = {"api_key": config.api_key}
        if config.base_url:
            kwargs["base_url"] = config.base_url
        self._client = anthropic.Anthropic(**kwargs)

    def complete(self, system: str, user: str) -> str:
        message = self._client.messages.create(
            model=self._config.model,
            max_tokens=self._config.max_tokens,
            temperature=self._config.temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(
            block.text for block in message.content if getattr(block, "type", "") == "text"
        )


class _OpenAICompatibleClient:
    def __init__(self, config: LLMConfig) -> None:
        try:
            import openai  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise LLMUnavailable(
                "Install cybergraph[llm] (openai) to use OpenAI/Kimi providers."
            ) from exc
        self._config = config
        kwargs = {"api_key": config.api_key}
        if config.base_url:
            kwargs["base_url"] = config.base_url
        self._client = openai.OpenAI(**kwargs)

    def complete(self, system: str, user: str) -> str:
        response = self._client.chat.completions.create(
            model=self._config.model,
            temperature=self._config.temperature,
            max_tokens=self._config.max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return response.choices[0].message.content or ""

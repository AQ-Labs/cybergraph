"""Optional LLM layer for CyberGraph.

The graph and retrieval layers work with no LLM at all. When a provider is
configured (env vars), an LLM can phrase a natural-language answer that is
strictly grounded in retrieved graph evidence. CyberGraph is local-only by
default: no provider is contacted unless the user opts in.
"""

from __future__ import annotations

from .client import (
    LLMClient,
    LLMConfig,
    LLMUnavailable,
    build_client,
    load_llm_config_from_env,
)

__all__ = [
    "LLMClient",
    "LLMConfig",
    "LLMUnavailable",
    "build_client",
    "load_llm_config_from_env",
]

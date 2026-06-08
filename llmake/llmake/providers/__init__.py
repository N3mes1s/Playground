"""
Provider registry.

Providers are looked up by name from a workflow's ``defaults.provider`` or a
target's ``provider`` field. Adding a backend is a one-line registration here.
"""

from __future__ import annotations

from .anthropic_chat import AnthropicChatProvider
from .base import InferenceRequest, InferenceResult, Provider
from .claude_agent import ClaudeAgentProvider
from .echo import EchoProvider

_REGISTRY: dict[str, type[Provider]] = {
    p.name: p
    for p in (EchoProvider, AnthropicChatProvider, ClaudeAgentProvider)
}


def get_provider(name: str) -> Provider:
    """Instantiate a provider by name. Raises ``KeyError`` if unknown."""
    try:
        cls = _REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY))
        raise KeyError(f"unknown provider {name!r}; available: {known}") from None
    return cls()


def register(provider_cls: type[Provider]) -> None:
    """Register a custom provider class (for out-of-tree extensions)."""
    _REGISTRY[provider_cls.name] = provider_cls


def list_providers() -> list[str]:
    return sorted(_REGISTRY)


__all__ = [
    "Provider",
    "InferenceRequest",
    "InferenceResult",
    "get_provider",
    "register",
    "list_providers",
]

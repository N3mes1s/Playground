"""Cross-provider session converters."""

from __future__ import annotations

from .base import SessionConverter
from .claude_to_codex import ClaudeToCodexConverter
from .codex_to_claude import CodexToClaudeConverter

_REGISTRY: dict[tuple[str, str], type[SessionConverter]] = {
    ("claude_code", "codex_cli"): ClaudeToCodexConverter,
    ("codex_cli", "claude_code"): CodexToClaudeConverter,
}


def get_converter(source_provider: str, target_provider: str) -> SessionConverter | None:
    """Look up a converter for the given provider pair. Returns None if unsupported."""
    cls = _REGISTRY.get((source_provider, target_provider))
    if cls is None:
        return None
    return cls()

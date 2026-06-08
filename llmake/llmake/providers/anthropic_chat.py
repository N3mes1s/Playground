"""
AnthropicChatProvider — a chat-model backend using the Anthropic API.

Optional: only usable if the ``anthropic`` package is installed and
``ANTHROPIC_API_KEY`` is set. It is imported lazily so the rest of llmake
works without the dependency.
"""

from __future__ import annotations

import os

from .base import InferenceRequest, InferenceResult, Provider

DEFAULT_MODEL = "claude-opus-4-8"


class AnthropicChatProvider(Provider):
    name = "anthropic"
    kinds = ("chat",)

    def available(self) -> tuple[bool, str]:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False, "the `anthropic` package is not installed (pip install anthropic)"
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False, "ANTHROPIC_API_KEY is not set"
        return True, ""

    def run(self, request: InferenceRequest) -> InferenceResult:
        import anthropic

        client = anthropic.Anthropic()
        model = request.model or DEFAULT_MODEL
        max_tokens = int(request.params.get("max_tokens", 4096))
        temperature = float(request.params.get("temperature", 1.0))

        msg = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": request.prompt}],
        )

        text = "".join(
            block.text for block in msg.content if getattr(block, "type", "") == "text"
        )

        return InferenceResult(
            text=text,
            provider=self.name,
            model=model,
            meta={
                "input_tokens": msg.usage.input_tokens,
                "output_tokens": msg.usage.output_tokens,
                "stop_reason": msg.stop_reason,
            },
        )

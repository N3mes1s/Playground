"""Policy backends: the model whose behavior we are continually improving.

Two backends, same interface (`generate(context, query, lessons) -> Message`):

  * MockLLM  -- a deterministic, fully offline "model". Crucially, it has NO
                knowledge of the environment's hidden preferences. Its only way
                to satisfy them is to *follow lessons it is given in context*.
                This is what makes the proof honest: any improvement is caused
                by the learning loop feeding back mined lessons, not by anything
                baked into the model.

  * OpenAILLM -- optional real-model backend (OpenAI-compatible HTTP). Runs the
                exact same loop with natural-language lessons in the system
                prompt. Requires OPENAI_API_KEY; the proof defaults to MockLLM
                so it reproduces with zero dependencies and zero cost.
"""

from __future__ import annotations

import os
import random
from typing import Iterable, Optional

from memory import Lesson
from schema import Message


class MockLLM:
    """A rule-following policy with no built-in knowledge of user preferences.

    `slip` injects realistic execution noise: even when told a rule, the model
    occasionally fails to apply it, so learning curves are not perfect steps.
    """

    def __init__(self, slip: float = 0.05, seed: int = 0):
        self.slip = slip
        self._rng = random.Random(seed)

    def generate(self, context: str, query: str,
                 lessons: Optional[Iterable[Lesson]] = None) -> Message:
        # Naive base behavior: produce a generic response with no special
        # features. (The model does not know what any domain wants.)
        produced: set[str] = set()

        # Apply each lesson that was retrieved into context, modulo slip.
        for lesson in (lessons or []):
            if self._rng.random() < self.slip:
                continue  # execution slip: knew the rule, failed to apply it
            produced.add(lesson.feature)

        content = self._render(context, query, sorted(produced))
        return Message(role="assistant", content=content, features=sorted(produced))

    @staticmethod
    def _render(context: str, query: str, features: list[str]) -> str:
        tag = ", ".join(features) if features else "(no learned features applied)"
        return f"[{context}] response to: {query!r} | applied: {tag}"


class OpenAILLM:
    """Optional real-model backend (OpenAI-compatible chat completions)."""

    def __init__(self, model: str = "gpt-4o-mini",
                 base_url: str = "https://api.openai.com/v1",
                 api_key_env: str = "OPENAI_API_KEY"):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = os.environ.get(api_key_env)
        if not self.api_key:
            raise RuntimeError(
                f"{api_key_env} not set. The offline MockLLM is the default "
                "backend for the reproducible proof; this backend is optional."
            )

    def generate(self, context: str, query: str,
                 lessons: Optional[Iterable[Lesson]] = None) -> Message:
        import json
        import urllib.request

        lesson_block = "\n".join(f"- {l.text}" for l in (lessons or []))
        system = "You are a helpful assistant."
        if lesson_block:
            system += (
                "\n\nLearned guidelines from past user corrections "
                "(follow them):\n" + lesson_block
            )
        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": f"[{context}] {query}"},
            ],
            "temperature": 0.2,
        }).encode()
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=body,
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        text = data["choices"][0]["message"]["content"]
        # Feature extraction from free text is handled by an LLM judge in a real
        # deployment; left to the caller's environment here.
        return Message(role="assistant", content=text, features=[])

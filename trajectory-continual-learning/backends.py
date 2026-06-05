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


class ClaudeCLIBackend:
    """Real-model backend that shells out to the `claude` CLI (`claude -p`).

    This uses the session's own auth -- no API key required -- and crucially each
    subprocess call is a FRESH model instance with none of our context, so it has
    no knowledge of the environment's hidden preferences. That makes it a fully
    uncontaminated policy model for the live proof in run_claude_real.py.
    """

    def __init__(self, model: str | None = None, exe: str | None = None,
                 timeout: int = 180):
        self.model = model
        self.exe = exe or os.environ.get("CLAUDE_CODE_EXECPATH") or "claude"
        self.timeout = timeout

    def generate(self, context: str, query: str,
                 lessons: Optional[Iterable[Lesson]] = None) -> Message:
        import subprocess

        lesson_block = "\n".join(f"- {l.text}" for l in (lessons or []))
        system = ("You are a writing assistant. Output ONLY the requested artifact "
                  "(the email or message itself) with no preamble, explanation, or "
                  "code fences.")
        if lesson_block:
            system += ("\n\nLearned guidelines from this user's past corrections "
                       "(follow them exactly):\n" + lesson_block)

        prompt = f"Write the following for the '{context}' context: {query}"
        cmd = [self.exe, "-p", prompt, "--append-system-prompt", system]
        if self.model:
            cmd += ["--model", self.model]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=self.timeout, cwd="/tmp")
        if proc.returncode != 0:
            raise RuntimeError(f"claude CLI failed ({proc.returncode}): "
                               f"{proc.stderr.strip()[:400]}")
        return Message(role="assistant", content=proc.stdout.strip(), features=[])


class AnthropicLLM:
    """Real-model backend using the Anthropic Messages API (Claude).

    Runs the identical continual-learning loop against a real Claude model:
    mined lessons are placed in the system prompt as learned guidelines, exactly
    as the non-parametric memory does for the offline backend. Requires
    ANTHROPIC_API_KEY. Returns free-text; feature extraction for scoring is done
    by the objective rule-checker in text_rules.py (no separate judge model).
    """

    def __init__(self, model: str = "claude-sonnet-4-6",
                 base_url: str | None = None,
                 api_key_env: str = "ANTHROPIC_API_KEY",
                 max_tokens: int = 1024):
        self.model = model
        self.base_url = (base_url or os.environ.get(
            "ANTHROPIC_BASE_URL", "https://api.anthropic.com")).rstrip("/")
        self.api_key = os.environ.get(api_key_env)
        self.max_tokens = max_tokens
        if not self.api_key:
            raise RuntimeError(
                f"{api_key_env} not set. Set it to run the loop against the real "
                "Claude API; the offline MockLLM remains the default for the "
                "zero-dependency proof."
            )

    def generate(self, context: str, query: str,
                 lessons: Optional[Iterable[Lesson]] = None) -> Message:
        import json
        import urllib.request

        lesson_block = "\n".join(f"- {l.text}" for l in (lessons or []))
        system = "You are a helpful writing assistant. Produce only the requested artifact, no preamble."
        if lesson_block:
            system += ("\n\nLearned guidelines from this user's past corrections "
                       "(follow them exactly):\n" + lesson_block)
        body = json.dumps({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": f"[{context}] {query}"}],
        }).encode()
        req = urllib.request.Request(
            f"{self.base_url}/v1/messages", data=body,
            headers={"x-api-key": self.api_key,
                     "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        text = "".join(b.get("text", "") for b in data.get("content", []))
        return Message(role="assistant", content=text, features=[])


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

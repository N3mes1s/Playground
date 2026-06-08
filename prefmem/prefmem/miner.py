"""Server-side preference inference: turn edits into reusable guidelines.

Given several (query, response, edited_text) examples for one (user, task), infer
the user's consistent preferences in natural language. We aggregate across edits
so recurring preferences surface and one-off noise washes out (CIPHER-style), and
we keep the prompts model-agnostic.

Backends implement a single `complete(prompt, system) -> str` method:
  * ClaudeCLIBackend  -- local dev, uses the `claude` CLI, no API key
  * AnthropicBackend  -- production, ANTHROPIC_API_KEY
  * OpenAIBackend     -- production, OPENAI_API_KEY
A dependency-free `heuristic_preferences()` is the no-LLM fallback.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Iterable, Optional, Protocol

from .schema import Trajectory


class Backend(Protocol):
    def complete(self, prompt: str, system: str = "") -> str: ...


# ---------------------------------------------------------------------------
_SYSTEM = (
    "You infer a user's CONSISTENT writing/output preferences for one task by "
    "comparing an assistant's responses (BEFORE) with the user's edited versions "
    "(AFTER). Examine sign-off/closing, greeting, length, formatting (bullets, "
    "headers), tone, required mentions/tags, names/dates/placeholders. Output ONLY "
    "the preferences that RECUR across multiple examples, as concrete, non-optional "
    "imperative guidelines, ONE per line, no numbering, no preamble. Include "
    "specific values (exact sign-off text, a word limit, the exact @tag)."
)


def _clean(line: str) -> str:
    return re.sub(r"^\s*(?:[-*•]|\d+[.)])\s*", "", line).strip().rstrip(".")


def infer_preferences(backend: Backend, task: str,
                      edits: Iterable[Trajectory], max_pref: int = 6) -> list[str]:
    blocks = []
    for i, t in enumerate(edits, 1):
        blocks.append(f"--- Example {i} (request: {t.query}) ---\n"
                      f"BEFORE:\n{t.response}\n\nAFTER (user edit):\n{t.edited_text}\n")
    if not blocks:
        return []
    raw = backend.complete(
        f"Task: {task}\n\n" + "\n".join(blocks) +
        "\nList the user's consistent preferences.", _SYSTEM)
    out, seen = [], set()
    for line in raw.splitlines():
        txt = _clean(line)
        if len(txt) >= 5 and txt.lower() not in seen:
            out.append(txt); seen.add(txt.lower())
        if len(out) >= max_pref:
            break
    return out


# --- no-LLM fallback: cheap structural heuristics --------------------------
_EMOJI = re.compile("[\U0001F300-\U0001FAFF\U00002600-\U000027BF]")


def heuristic_preferences(edits: list[Trajectory]) -> list[str]:
    """Detect a few obvious recurring edit patterns without an LLM."""
    def wc(s): return len(re.findall(r"\b[\w'-]+\b", s or ""))
    n = len(edits) or 1
    shorter = sum(1 for t in edits if wc(t.edited_text) < wc(t.response) * 0.8)
    added_bullets = sum(1 for t in edits
                        if t.edited_text and t.edited_text.count("\n- ") >= 2
                        and t.response.count("\n- ") < 2)
    added_emoji = sum(1 for t in edits
                      if t.edited_text and _EMOJI.search(t.edited_text)
                      and not _EMOJI.search(t.response))
    prefs = []
    if shorter > n / 2:
        prefs.append("Keep responses noticeably shorter and cut filler.")
    if added_bullets > n / 2:
        prefs.append("Format the response as a bulleted list.")
    if added_emoji > n / 2:
        prefs.append("Include an emoji where appropriate.")
    return prefs


# --- backends --------------------------------------------------------------
class ClaudeCLIBackend:
    """Uses the local `claude` CLI (no API key). Great for dev/self-host."""

    def __init__(self, model: Optional[str] = None):
        self.exe = os.environ.get("CLAUDE_CODE_EXECPATH") or "claude"
        self.model = model

    def complete(self, prompt: str, system: str = "") -> str:
        cmd = [self.exe, "-p", prompt]
        if system:
            cmd += ["--append-system-prompt", system]
        if self.model:
            cmd += ["--model", self.model]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd="/tmp")
        if p.returncode != 0:
            raise RuntimeError(f"claude CLI failed: {p.stderr[:300]}")
        return p.stdout.strip()


class AnthropicBackend:
    def __init__(self, model: str = "claude-sonnet-4-6"):
        self.model = model
        self.key = os.environ.get("ANTHROPIC_API_KEY")
        self.base = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        if not self.key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")

    def complete(self, prompt: str, system: str = "") -> str:
        import json
        import urllib.request
        body = json.dumps({"model": self.model, "max_tokens": 1024,
                           "system": system or "You are a helpful assistant.",
                           "messages": [{"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request(
            f"{self.base}/v1/messages", data=body,
            headers={"x-api-key": self.key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        return "".join(b.get("text", "") for b in data.get("content", []))


class OpenAIBackend:
    def __init__(self, model: str = "gpt-4o-mini",
                 base_url: str = "https://api.openai.com/v1"):
        self.model = model
        self.base = base_url.rstrip("/")
        self.key = os.environ.get("OPENAI_API_KEY")
        if not self.key:
            raise RuntimeError("OPENAI_API_KEY not set")

    def complete(self, prompt: str, system: str = "") -> str:
        import json
        import urllib.request
        body = json.dumps({"model": self.model, "temperature": 0.2,
                           "messages": [{"role": "system", "content": system or "You are helpful."},
                                        {"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request(
            f"{self.base}/chat/completions", data=body,
            headers={"Authorization": f"Bearer {self.key}",
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        return data["choices"][0]["message"]["content"]


def default_backend() -> Optional[Backend]:
    """Pick the best available backend, or None (-> heuristic fallback)."""
    for ctor in (lambda: AnthropicBackend() if os.environ.get("ANTHROPIC_API_KEY") else None,
                 lambda: OpenAIBackend() if os.environ.get("OPENAI_API_KEY") else None):
        try:
            b = ctor()
            if b:
                return b
        except Exception:
            pass
    # CLI backend if present
    try:
        if os.environ.get("CLAUDE_CODE_EXECPATH"):
            return ClaudeCLIBackend()
    except Exception:
        pass
    return None

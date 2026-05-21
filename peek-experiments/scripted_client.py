"""A scripted, offline LM client for driving PEEK without an API key.

PEEK's ``CachePolicy.update`` makes two LM calls per step: first the Distiller,
then the Cartographer. Each call is a single user message whose prompt embeds
the current context map. This client routes each call by inspecting the prompt
and returns pre-programmed JSON, so the *real* PEEK control flow (context-map
edits, scoring, the priority Evictor, and freezing) runs end to end and
deterministically. The README of the `peek` repo explicitly endorses "a local
stub" as a valid `LMClient`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from peek.core.types import Usage

# Distinct first-line markers from peek/prompts/{distiller,cartographer}.txt.
_CARTOGRAPHER_MARKER = "context map curator"

# Map items render as a single line: "[<slug>-NNNNN] <content>".
_ITEM_LINE = re.compile(r"\[([a-z]{2,4}-\d{5})\]\s*(.*)")

Response = dict | Callable[[str], dict]

_EMPTY_DISTILLER: dict = {"diagnosis": "", "item_tags": {}, "cache_candidates": []}
_EMPTY_CARTOGRAPHER: dict = {"reasoning": "no edits", "operations": []}


def map_ids(prompt: str) -> list[str]:
    """Ordered item IDs found in the context map embedded in a prompt."""
    return [m.group(1) for m in _ITEM_LINE.finditer(prompt)]


def id_of(prompt: str, needle: str) -> str | None:
    """ID of the first map item whose content contains ``needle``."""
    for m in _ITEM_LINE.finditer(prompt):
        if needle in m.group(2):
            return m.group(1)
    return None


def tags_for(prompt: str, rules: list[tuple[str, str]]) -> dict[str, str]:
    """Build an ``item_tags`` dict by matching content needles to tags."""
    tags: dict[str, str] = {}
    for needle, tag in rules:
        item_id = id_of(prompt, needle)
        if item_id is not None:
            tags[item_id] = tag
    return tags


class ScriptedLMClient:
    """An ``LMClient`` that replays pre-programmed Distiller/Cartographer JSON.

    Parameters
    ----------
    distiller_script, cartographer_script:
        Ordered responses. Each entry is either a ``dict`` (used as-is) or a
        ``callable`` that receives the prompt text and returns a ``dict`` --
        the callable form lets a response reference live, freshly-minted
        item IDs that are only known at run time.
    """

    def __init__(
        self,
        distiller_script: list[Response],
        cartographer_script: list[Response],
    ) -> None:
        self._distiller = list(distiller_script)
        self._cartographer = list(cartographer_script)
        self.transcript: list[tuple[str, dict]] = []
        self.calls = 0
        self._last = Usage()

    def completion(self, messages: list[dict]) -> str:
        prompt = messages[-1]["content"]
        is_cartographer = _CARTOGRAPHER_MARKER in prompt
        role = "cartographer" if is_cartographer else "distiller"
        queue = self._cartographer if is_cartographer else self._distiller

        if queue:
            entry = queue.pop(0)
        else:
            entry = _EMPTY_CARTOGRAPHER if is_cartographer else _EMPTY_DISTILLER

        payload = entry(prompt) if callable(entry) else entry
        text = json.dumps(payload)

        self.calls += 1
        # Rough usage accounting so CachePolicy.usage is non-zero and realistic.
        self._last = Usage(input_tokens=len(prompt) // 4, output_tokens=len(text) // 4)
        self.transcript.append((role, payload))
        return text

    def last_usage(self) -> Usage:
        return self._last

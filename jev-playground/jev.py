"""
jev.py -- a small, dependency-free client for TypeSafe AI's Jev "System One" model.

Jev is not a chat/LLM. You give it a *state* (any unstructured or structured
context) and one or more *questions*, and it returns typed, calibrated answers
directly -- a choice, a score on a spectrum, or a yes/no probability -- without
generating text token by token.

This module wraps the one public endpoint (`POST /v1/systemone`) using only the
Python standard library, so there is nothing to install. It aims to expose
*everything* the API can do:

  * choice  -- pick one of up to 255 labelled options   -> label + confidence + full distribution
  * score   -- position on an ordered 2..10 level scale  -> float + confidence + legend + distribution
  * noul    -- boolean-as-probability (0.0 .. 1.0)       -> probability

  * arbitrary state shapes: plain string, list of strings, or nested JSON object
  * any number of questions in a single request (batched, one round trip)
  * model pinning (e.g. "jev-1.13.0") or "jev-latest"
  * token usage reporting

Docs: https://typesafe.ai/  ·  API: https://api.typesafe.ai/v1/systemone

Verified request/response shapes (as of this experiment):

  request  { "model", "state", "questions": { name: <question>, ... } }
  choice   { "type":"choice", "instructions", "criteria": {label: description, ...} }
  score    { "type":"score",  "instructions", "criteria": [level0, level1, ...] }
  noul     { "type":"noul",   "instructions" }

  response { "model", "answers": { name: <answer> }, "usage": {input_tokens, output_tokens} }
  choice   -> { "choice": label, "confidence": float, "probabilities": {label: p} }
  score    -> { "score": float, "confidence": float, "legend": {i: level}, "probabilities": {i: p} }
  noul     -> { "noul": float }
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
DEFAULT_MODEL = "jev-latest"

State = Union[str, Sequence[str], Mapping[str, Any]]


# --------------------------------------------------------------------------- #
# Question primitives
# --------------------------------------------------------------------------- #
def choice(instructions: str, criteria: Mapping[str, str]) -> Dict[str, Any]:
    """Pick exactly one option. `criteria` maps a short label -> a description.

    Example:
        choice("Which team handles this",
               {"billing": "Payments & refunds", "technical": "Bugs & crashes"})
    """
    if not criteria:
        raise ValueError("choice() needs at least one option in `criteria`")
    if len(criteria) > 255:
        raise ValueError("choice() allows at most 255 options")
    return {"type": "choice", "instructions": instructions, "criteria": dict(criteria)}


def score(instructions: str, criteria: Sequence[str]) -> Dict[str, Any]:
    """Position on an ordered spectrum. `criteria` is a list of 2..10 level names,
    lowest first. The returned score is a float indexed into that list.

    Example:
        score("Customer frustration", ["Calm", "Annoyed", "Angry", "Furious"])
    """
    levels = list(criteria)
    if not 2 <= len(levels) <= 10:
        raise ValueError("score() needs between 2 and 10 ordered levels")
    return {"type": "score", "instructions": instructions, "criteria": levels}


def noul(instructions: str) -> Dict[str, Any]:
    """Yes/no as a probability in [0, 1]. State the proposition to evaluate.

    Example:
        noul("The customer is explicitly asking for a refund")
    """
    return {"type": "noul", "instructions": instructions}


# --------------------------------------------------------------------------- #
# Typed answers
# --------------------------------------------------------------------------- #
@dataclass
class Answer:
    """One typed answer for one question, plus the raw payload it came from."""

    name: str
    type: str
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)

    @property
    def value(self) -> Union[str, float]:
        """The headline answer: the chosen label, the score float, or the noul probability."""
        return self.raw.get(self.type)

    # convenience accessors -------------------------------------------------- #
    @property
    def choice(self) -> Optional[str]:
        return self.raw.get("choice")

    @property
    def score(self) -> Optional[float]:
        return self.raw.get("score")

    @property
    def noul(self) -> Optional[float]:
        return self.raw.get("noul")

    @property
    def confidence(self) -> Optional[float]:
        return self.raw.get("confidence")

    @property
    def probabilities(self) -> Dict[str, float]:
        return self.raw.get("probabilities", {})

    @property
    def legend(self) -> Dict[str, str]:
        return self.raw.get("legend", {})

    def label(self) -> Optional[str]:
        """For a score, the nearest level name; otherwise the choice label."""
        if self.type == "score" and self.legend:
            idx = str(int(round(self.score)))
            return self.legend.get(idx)
        return self.choice

    def is_yes(self, threshold: float = 0.5) -> bool:
        """For a noul, whether the probability clears `threshold`."""
        return (self.noul or 0.0) >= threshold


@dataclass
class Response:
    model: str
    answers: Dict[str, Answer]
    usage: Dict[str, int] = field(default_factory=dict)
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)
    latency_ms: Optional[float] = None

    def __getitem__(self, name: str) -> Answer:
        return self.answers[name]

    def __iter__(self):
        return iter(self.answers.values())


class JevError(RuntimeError):
    """Raised when the API returns a non-2xx response."""

    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"Jev API error {status}: {body}")


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #
class Jev:
    """Thin client for the Jev System One endpoint.

    The API key is read from `TYPESAFE_API_KEY` unless passed explicitly.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        self.api_key = api_key or os.environ.get("TYPESAFE_API_KEY")
        if not self.api_key:
            raise ValueError(
                "No API key. Pass api_key=... or set the TYPESAFE_API_KEY environment "
                "variable (see .env.example)."
            )
        self.model = model
        self.endpoint = endpoint
        self.timeout = timeout
        self.max_retries = max_retries

    def ask(
        self,
        state: State,
        questions: Mapping[str, Dict[str, Any]],
        model: Optional[str] = None,
    ) -> Response:
        """Send `state` + `questions` in one request and return typed answers.

        `questions` maps a name you choose -> a question built with
        choice()/score()/noul(). All questions are answered in a single round trip.
        """
        if not questions:
            raise ValueError("ask() needs at least one question")

        payload = {
            "model": model or self.model,
            "state": state,
            "questions": dict(questions),
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint,
            data=data,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )

        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries):
            start = time.time()
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read().decode("utf-8")
                latency_ms = (time.time() - start) * 1000
                return self._parse(json.loads(body), latency_ms)
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", "replace")
                # 4xx are client errors -- retrying won't help.
                if 400 <= e.code < 500 and e.code != 429:
                    raise JevError(e.code, body) from e
                last_err = JevError(e.code, body)
            except (urllib.error.URLError, TimeoutError) as e:
                last_err = e
            # exponential backoff: 1s, 2s, 4s ...
            if attempt < self.max_retries - 1:
                time.sleep(2 ** attempt)
        raise last_err  # type: ignore[misc]

    # single-question convenience wrappers ---------------------------------- #
    def choice(self, state: State, instructions: str, criteria: Mapping[str, str], **kw) -> Answer:
        return self.ask(state, {"_": choice(instructions, criteria)}, **kw)["_"]

    def score(self, state: State, instructions: str, criteria: Sequence[str], **kw) -> Answer:
        return self.ask(state, {"_": score(instructions, criteria)}, **kw)["_"]

    def noul(self, state: State, instructions: str, **kw) -> Answer:
        return self.ask(state, {"_": noul(instructions)}, **kw)["_"]

    # ---------------------------------------------------------------------- #
    @staticmethod
    def _parse(body: Dict[str, Any], latency_ms: float) -> Response:
        answers = {
            name: Answer(name=name, type=payload.get("type", ""), raw=payload)
            for name, payload in body.get("answers", {}).items()
        }
        return Response(
            model=body.get("model", ""),
            answers=answers,
            usage=body.get("usage", {}),
            raw=body,
            latency_ms=latency_ms,
        )


__all__ = ["Jev", "Response", "Answer", "JevError", "choice", "score", "noul"]

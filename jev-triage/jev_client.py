"""
Thin adapter around TypeSafe's Jev (System One) model.

Jev is a "System One" model: unstructured state in, *typed probabilistic
decisions* out. Instead of generating free-form strings, it answers a battery
of typed questions (Noul / Choice / Score) in a single call and returns
calibrated probabilities for each. That is a near-perfect fit for triaging
security-scanner findings, where we want a fast, cheap, calibrated "is this a
real, reachable vulnerability?" signal rather than another paragraph of prose.

This module prefers the official `typesafe-sdk` when it is installed, and
otherwise falls back to a raw HTTP call against the documented endpoint:

    POST https://api.typesafe.ai/v1/systemone
    Authorization: Bearer $TYPESAFE_API_KEY

Both paths are normalized to the same `SystemOneResponse` shape so the rest of
the codebase never has to care which transport was used.

Docs: https://docs.typesafe.ai/concepts/system-one
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

DEFAULT_MODEL = "jev-latest"
DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone"


# --------------------------------------------------------------------------- #
# Question primitives
# --------------------------------------------------------------------------- #
# These mirror Jev's three decision primitives. We keep our own lightweight
# dataclasses (rather than importing the SDK's) so that the raw-HTTP fallback
# works even when `typesafe-sdk` is not installed. When the SDK *is* present we
# translate these into the SDK's own Noul/Choice/Score objects.


@dataclass
class Noul:
    """A yes/no question. Answer is a single probability in [0, 1]."""

    instructions: str
    criteria: dict[str, str] | None = None  # optional {"true": ..., "false": ...}

    def to_wire(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": "noul", "instructions": self.instructions}
        if self.criteria:
            d["criteria"] = self.criteria
        return d


@dataclass
class Choice:
    """Pick exactly one option from `criteria` (option -> description)."""

    instructions: str
    criteria: dict[str, str]

    def to_wire(self) -> dict[str, Any]:
        return {
            "type": "choice",
            "instructions": self.instructions,
            "criteria": self.criteria,
        }


@dataclass
class Score:
    """Rate the state against an ordered list of descriptive levels."""

    instructions: str
    criteria: list[str]

    def to_wire(self) -> dict[str, Any]:
        return {
            "type": "score",
            "instructions": self.instructions,
            "criteria": list(self.criteria),
        }


Question = Noul | Choice | Score


# --------------------------------------------------------------------------- #
# Normalized response
# --------------------------------------------------------------------------- #


@dataclass
class Answer:
    """One typed answer, normalized across SDK and HTTP transports.

    Exactly one of `noul` / `choice` / `score` is populated depending on the
    question type. `probabilities` and `confidence` are populated for Choice
    and Score answers (Noul's single probability lives in `noul`).
    """

    kind: str  # "noul" | "choice" | "score"
    noul: float | None = None
    choice: str | None = None
    score: float | None = None
    probabilities: dict[str, float] = field(default_factory=dict)
    legend: dict[str, Any] = field(default_factory=dict)
    confidence: float | None = None

    @property
    def value(self) -> Any:
        """The primary answer value regardless of kind."""
        if self.kind == "noul":
            return self.noul
        if self.kind == "choice":
            return self.choice
        return self.score


@dataclass
class SystemOneResponse:
    answers: dict[str, Answer]
    model: str = DEFAULT_MODEL
    usage: dict[str, int] = field(default_factory=dict)

    def __getitem__(self, key: str) -> Answer:
        return self.answers[key]


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class JevError(RuntimeError):
    pass


class JevClient:
    """Calls Jev via the official SDK when available, else raw HTTP.

    Args:
        api_key: TypeSafe API key. Defaults to $TYPESAFE_API_KEY.
        model: Model id (default "jev-latest").
        endpoint: HTTP endpoint used only for the raw-HTTP fallback.
        prefer_sdk: If False, always use the raw-HTTP path (useful for tests).
        timeout: HTTP timeout in seconds for the fallback path.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        endpoint: str = DEFAULT_ENDPOINT,
        prefer_sdk: bool = True,
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("TYPESAFE_API_KEY")
        self.model = model
        self.endpoint = endpoint
        self.timeout = timeout
        self._sdk = self._load_sdk() if prefer_sdk else None

    # -- transport selection ------------------------------------------------ #

    @staticmethod
    def _load_sdk():
        try:
            import typesafe_sdk  # type: ignore

            return typesafe_sdk
        except Exception:
            return None

    def system_one(
        self, state: Any, questions: dict[str, Question]
    ) -> SystemOneResponse:
        """Ask Jev a battery of typed questions about `state` in one call."""
        if not self.api_key:
            raise JevError(
                "No TypeSafe API key found. Set TYPESAFE_API_KEY in the "
                "environment or pass api_key=... to JevClient."
            )
        if self._sdk is not None:
            try:
                return self._call_sdk(state, questions)
            except Exception as exc:  # pragma: no cover - SDK optional
                # Fall back to HTTP rather than hard-failing on SDK quirks.
                self._last_sdk_error = exc
        return self._call_http(state, questions)

    # -- SDK path ----------------------------------------------------------- #

    def _call_sdk(
        self, state: Any, questions: dict[str, Question]
    ) -> SystemOneResponse:
        sdk = self._sdk
        client = sdk.TypeSafeClient(api_key=self.api_key)

        sdk_questions: dict[str, Any] = {}
        for key, q in questions.items():
            if isinstance(q, Noul):
                sdk_questions[key] = sdk.Noul(
                    instructions=q.instructions, criteria=q.criteria
                ) if q.criteria else sdk.Noul(instructions=q.instructions)
            elif isinstance(q, Choice):
                sdk_questions[key] = sdk.Choice(
                    instructions=q.instructions, criteria=q.criteria
                )
            elif isinstance(q, Score):
                sdk_questions[key] = sdk.Score(
                    instructions=q.instructions, criteria=q.criteria
                )
            else:  # pragma: no cover - defensive
                raise JevError(f"Unknown question type: {type(q)!r}")

        resp = client.system_one(
            state=state, questions=sdk_questions, model=self.model
        )
        return self._normalize_sdk(resp, questions)

    @staticmethod
    def _normalize_sdk(
        resp: Any, questions: dict[str, Question]
    ) -> SystemOneResponse:
        answers: dict[str, Answer] = {}
        raw = getattr(resp, "answers", {})
        for key, q in questions.items():
            a = raw[key] if isinstance(raw, dict) else getattr(raw, key)
            if isinstance(q, Noul):
                answers[key] = Answer(kind="noul", noul=_getany(a, "noul"))
            elif isinstance(q, Choice):
                answers[key] = Answer(
                    kind="choice",
                    choice=_getany(a, "choice"),
                    probabilities=_getany(a, "probabilities") or {},
                    confidence=_getany(a, "confidence"),
                )
            else:
                answers[key] = Answer(
                    kind="score",
                    score=_getany(a, "score"),
                    legend=_getany(a, "legend") or {},
                    probabilities=_getany(a, "probabilities") or {},
                    confidence=_getany(a, "confidence"),
                )
        return SystemOneResponse(
            answers=answers,
            model=getattr(resp, "model", DEFAULT_MODEL),
            usage=getattr(resp, "usage", {}) or {},
        )

    # -- HTTP fallback ------------------------------------------------------ #

    def _call_http(
        self, state: Any, questions: dict[str, Question]
    ) -> SystemOneResponse:
        import requests

        body = {
            "model": self.model,
            "state": state,
            "questions": {k: q.to_wire() for k, q in questions.items()},
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        r = requests.post(
            self.endpoint, json=body, headers=headers, timeout=self.timeout
        )
        if r.status_code >= 400:
            raise JevError(f"Jev HTTP {r.status_code}: {r.text[:500]}")
        return self.normalize_http(r.json(), questions)

    @staticmethod
    def normalize_http(
        payload: dict[str, Any], questions: dict[str, Question]
    ) -> SystemOneResponse:
        """Normalize a raw HTTP JSON response. Exposed for offline testing."""
        answers: dict[str, Answer] = {}
        raw = payload.get("answers", {})
        for key, q in questions.items():
            a = raw.get(key, {})
            if isinstance(q, Noul):
                answers[key] = Answer(kind="noul", noul=a.get("noul"))
            elif isinstance(q, Choice):
                answers[key] = Answer(
                    kind="choice",
                    choice=a.get("choice"),
                    probabilities=a.get("probabilities") or {},
                    confidence=a.get("confidence"),
                )
            else:
                answers[key] = Answer(
                    kind="score",
                    score=a.get("score"),
                    legend=a.get("legend") or {},
                    probabilities=a.get("probabilities") or {},
                    confidence=a.get("confidence"),
                )
        return SystemOneResponse(
            answers=answers,
            model=payload.get("model", DEFAULT_MODEL),
            usage=payload.get("usage", {}) or {},
        )


def _getany(obj: Any, name: str) -> Any:
    """Read `name` from either a dict or an attribute-style object."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)

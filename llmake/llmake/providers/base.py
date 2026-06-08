"""
Provider interface — the seam that lets llmake treat *any* inference engine
the same way: a hosted chat model, a local model, or a full coding agent.

A "target" in a workflow is compiled by handing an :class:`InferenceRequest`
to a provider and storing the resulting :class:`InferenceResult` as a build
artifact. Everything else in llmake (the DAG, the cache, snapshots, export)
is provider-agnostic and only speaks these two dataclasses.

To add a new backend, subclass :class:`Provider`, implement ``run``, and
register it in ``providers/__init__.py``. Nothing else needs to change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class InferenceRequest:
    """A fully-materialized unit of work for a provider.

    By the time a request reaches a provider, all templating has already
    happened: ``prompt`` is the final text, with inputs / context / upstream
    artifacts already substituted in. Providers therefore stay dumb and
    interchangeable.
    """

    target: str                       # name of the target being built
    prompt: str                       # final, fully-rendered prompt text
    kind: str = "chat"                # "chat" | "agent"
    model: str = ""                   # model identifier (provider-specific)
    params: dict = field(default_factory=dict)  # temperature, max_tokens, ...
    workdir: Path = Path(".")         # workspace root (agents may read/write here)
    inputs: dict = field(default_factory=dict)  # path -> content, for provenance


@dataclass
class InferenceResult:
    """The compiled output of a target."""

    text: str                         # the artifact body (markdown by default)
    provider: str = ""                # provider name that produced it
    model: str = ""                   # model used
    meta: dict = field(default_factory=dict)  # tokens, cost, agent steps, ...


class Provider(ABC):
    """Base class for all inference backends.

    Subclasses must set :attr:`name` and implement :meth:`run`. Optionally
    override :meth:`available` to advertise whether the backend is usable in
    the current environment (e.g. an API key is set, a CLI is on PATH).
    """

    name: str = "base"

    #: which request kinds this provider can service
    kinds: tuple[str, ...] = ("chat",)

    def available(self) -> tuple[bool, str]:
        """Return ``(is_available, reason)``.

        ``reason`` explains *why* it's unavailable so the CLI can print a
        helpful message instead of a stack trace.
        """
        return True, ""

    @abstractmethod
    def run(self, request: InferenceRequest) -> InferenceResult:
        """Execute the request and return the compiled result."""
        raise NotImplementedError

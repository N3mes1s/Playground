"""
Workflow spec — load and validate ``llmake.yaml``.

This is llmake's equivalent of a Makefile / configure.ac: a declarative
manifest describing the prompt library and the DAG of inference targets.

Schema (all keys optional unless noted)::

    version: 1
    project: my-notes

    defaults:
      provider: echo            # default backend for targets
      model: claude-opus-4-8
      kind: chat                # chat | agent
      params: {temperature: 1.0}

    prompts:                    # the reusable, stored prompt library
      summarize: prompts/summarize.md     # path -> file
      critique: |                         # or inline text
        Critique the following:
        {{input}}

    inputs:                     # glob(s) of source material (markdown, etc.)
      - inputs/*.md
    context:                    # general-purpose context shared with steps
      - context/*.md

    targets:                    # the build graph; each produces one artifact
      summary:
        prompt: summarize       # library key, file path, or inline literal
        inputs: [inputs/notes.md]
      report:
        prompt: |
          Combine the summary and critique into a polished report.
          {{needs:summary}}
        needs: [summary]        # depends on other targets' artifacts
        provider: claude-agent  # per-target override
        kind: agent
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Defaults:
    provider: str = "dspy"            # DSPy is the canonical engine
    model: str = "openai/gpt-4o-mini"  # LiteLLM-format model id
    kind: str = "chat"
    params: dict = field(default_factory=dict)


@dataclass
class Target:
    name: str
    prompt: str = ""                       # library key | path | inline literal
    inputs: list = field(default_factory=list)
    needs: list = field(default_factory=list)
    foreach: str | None = None             # glob: fan out one instance per match
    provider: str | None = None
    model: str | None = None
    kind: str | None = None
    params: dict = field(default_factory=dict)
    output: str | None = None              # artifact path override


@dataclass
class Workflow:
    project: str
    root: Path                             # workspace root (dir of llmake.yaml)
    defaults: Defaults
    prompts: dict                          # name -> raw value (path or text)
    inputs: list                           # list of glob patterns
    context: list                          # list of glob patterns
    targets: dict                          # name -> Target
    build_dir: Path

    @property
    def cache_path(self) -> Path:
        return self.root / ".llmake" / "cache.json"


class SpecError(ValueError):
    """Raised when a workflow manifest is malformed."""


def load_workflow(path: str | Path) -> Workflow:
    """Parse and validate an ``llmake.yaml`` manifest.

    ``path`` may be the manifest file itself or a directory containing one.
    """
    p = Path(path).resolve()
    if p.is_dir():
        p = p / "llmake.yaml"
    if not p.is_file():
        raise SpecError(f"no workflow manifest found at {p}")

    raw = yaml.safe_load(p.read_text()) or {}
    if not isinstance(raw, dict):
        raise SpecError("top-level manifest must be a mapping")

    root = p.parent
    d = raw.get("defaults", {}) or {}
    # Resolution for the default provider/model, most-specific first:
    #   manifest defaults -> environment ($LLMAKE_PROVIDER / $LLMAKE_MODEL)
    #   -> built-in fallback. This keeps account-specific choices (e.g. a
    #   Fireworks Kimi model) in the environment, out of committed config.
    defaults = Defaults(
        provider=d.get("provider") or os.environ.get("LLMAKE_PROVIDER") or "dspy",
        model=d.get("model") or os.environ.get("LLMAKE_MODEL") or "openai/gpt-4o-mini",
        kind=d.get("kind", "chat"),
        params=d.get("params", {}) or {},
    )

    targets: dict[str, Target] = {}
    for name, t in (raw.get("targets", {}) or {}).items():
        t = t or {}
        targets[name] = Target(
            name=name,
            prompt=t.get("prompt", ""),
            inputs=list(t.get("inputs", []) or []),
            needs=list(t.get("needs", []) or []),
            foreach=t.get("foreach"),
            provider=t.get("provider"),
            model=t.get("model"),
            kind=t.get("kind"),
            params=t.get("params", {}) or {},
            output=t.get("output"),
        )

    wf = Workflow(
        project=raw.get("project", root.name),
        root=root,
        defaults=defaults,
        prompts=raw.get("prompts", {}) or {},
        inputs=list(raw.get("inputs", []) or []),
        context=list(raw.get("context", []) or []),
        targets=targets,
        build_dir=root / (raw.get("build_dir", "build")),
    )
    _validate(wf)
    return wf


def _validate(wf: Workflow) -> None:
    if not wf.targets:
        raise SpecError("workflow defines no targets")
    for name, t in wf.targets.items():
        for dep in t.needs:
            if dep not in wf.targets:
                raise SpecError(f"target {name!r} needs unknown target {dep!r}")
        if not t.prompt:
            raise SpecError(f"target {name!r} has no prompt")


def resolve_prompt(wf: Workflow, target: Target) -> str:
    """Resolve a target's prompt to literal text.

    Resolution order, most-specific first:
      1. a key in the prompt library  -> use that library entry
      2. a file path that exists      -> read it
      3. otherwise                    -> treat the value as inline literal text

    Library entries themselves may be either a path or inline text.
    """
    value = target.prompt

    if value in wf.prompts:
        value = wf.prompts[value]

    candidate = wf.root / str(value)
    if "\n" not in str(value) and candidate.is_file():
        return candidate.read_text()

    return str(value)

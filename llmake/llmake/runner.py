"""
Build engine — compile a workflow into artifacts, incrementally.

This is the orchestrator: it walks the target DAG in dependency order, renders
each prompt against the workspace material and upstream artifacts, decides
whether the target is up to date (cache), invokes the chosen provider for the
stale ones, and writes the compiled outputs to the build directory.

Everything it touches is a separate module — spec, graph, context, render,
cache, providers — so the engine itself stays small and the pieces are
swappable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import context as ctx
from .cache import Cache, Entry, compute_key
from .graph import build_plan
from .providers import InferenceRequest, get_provider
from .render import render
from .spec import Target, Workflow, resolve_prompt


@dataclass
class StepResult:
    target: str
    status: str          # "built" | "cached" | "skipped"
    artifact: Path
    provider: str = ""
    model: str = ""


class BuildError(RuntimeError):
    pass


def _artifact_path(wf: Workflow, target: Target) -> Path:
    if target.output:
        return wf.root / target.output
    return wf.build_dir / f"{target.name}.md"


def _materialize(wf: Workflow, target: Target, artifacts: dict) -> tuple[str, dict]:
    """Render a target's final prompt. Returns (prompt, inputs-used)."""
    template = resolve_prompt(wf, target)
    inputs = ctx.load_inputs(wf, target.inputs) if target.inputs else ctx.load_inputs(wf)
    context_files = ctx.load_context(wf)
    needs = {dep: artifacts[dep] for dep in target.needs}
    prompt = render(template, inputs=inputs, context=context_files, needs=needs)
    return prompt, inputs


def build(
    wf: Workflow,
    goals: list | None = None,
    *,
    force: bool = False,
    provider_override: str | None = None,
    dry_run: bool = False,
    log=print,
) -> list:
    """Build ``goals`` (or the whole workflow). Returns a list of StepResult."""
    deps = {name: t.needs for name, t in wf.targets.items()}
    plan = build_plan(deps, goals)

    cache = Cache(wf.cache_path)
    artifacts: dict[str, str] = {}   # target -> compiled text (for downstream)
    keys: dict[str, str] = {}        # target -> cache key (for downstream keys)
    results: list[StepResult] = []

    for name in plan:
        target = wf.targets[name]
        prompt, inputs = _materialize(wf, target, artifacts)

        provider_name = provider_override or target.provider or wf.defaults.provider
        model = target.model or wf.defaults.model
        kind = target.kind or wf.defaults.kind
        params = {**wf.defaults.params, **target.params}

        key = compute_key(
            prompt=prompt,
            provider=provider_name,
            model=model,
            kind=kind,
            params=params,
            upstream_keys=[keys[d] for d in target.needs],
        )
        keys[name] = key
        artifact_path = _artifact_path(wf, target)

        if not force and cache.is_fresh(name, key, wf.root):
            artifacts[name] = artifact_path.read_text()
            results.append(StepResult(name, "cached", artifact_path,
                                      provider_name, model))
            log(f"  [cached]  {name}  ({artifact_path.relative_to(wf.root)})")
            continue

        if dry_run:
            artifacts[name] = ""  # unknown until built
            results.append(StepResult(name, "skipped", artifact_path,
                                      provider_name, model))
            log(f"  [stale]   {name}  -> would build with {provider_name}")
            continue

        provider = get_provider(provider_name)
        ok, reason = provider.available()
        if not ok:
            raise BuildError(
                f"target {name!r} needs provider {provider_name!r} which is "
                f"unavailable: {reason}"
            )

        log(f"  [build]   {name}  via {provider_name}"
            + (f" ({model})" if model else ""))
        request = InferenceRequest(
            target=name,
            prompt=prompt,
            kind=kind,
            model=model,
            params=params,
            workdir=wf.root,
            inputs=inputs,
        )
        result = provider.run(request)

        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(result.text)
        artifacts[name] = result.text

        cache.put(name, Entry(
            key=key,
            artifact=artifact_path.relative_to(wf.root).as_posix(),
            provider=result.provider,
            model=result.model,
            kind=kind,
            created=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            inputs=list(inputs),
            needs=list(target.needs),
            meta=result.meta,
        ))
        results.append(StepResult(name, "built", artifact_path,
                                  result.provider, result.model))

    if not dry_run:
        cache.save()
    return results


def status(wf: Workflow, goals: list | None = None) -> list:
    """Report build state without running anything (dry run)."""
    return build(wf, goals, dry_run=True, log=lambda *_: None)

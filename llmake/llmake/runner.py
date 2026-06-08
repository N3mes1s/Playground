"""
Build engine — compile a workflow into artifacts, incrementally.

The orchestrator: it expands authored targets into concrete steps (fanning out
``foreach`` targets), walks the step DAG in dependency order, renders each
prompt against the workspace material and upstream artifacts, decides whether a
step is up to date (cache), invokes the chosen provider for the stale ones (with
retry/backoff), and writes the compiled outputs atomically.

Independent steps can be compiled concurrently (``jobs > 1``); the scheduler
only starts a step once all of its dependencies have completed, and shared state
is guarded by a lock. Everything it touches lives in a separate module — spec,
plan, graph, context, render, cache, providers — so the engine stays small and
the pieces are swappable.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import context as ctx
from .cache import Cache, Entry, compute_key
from .graph import build_plan
from .plan import Step, expand, resolve_goals
from .providers import InferenceRequest, get_provider
from .render import render
from .spec import Workflow, resolve_prompt

logger = logging.getLogger("llmake")

DEFAULT_ATTEMPTS = 3       # total tries per step (1 = no retry)
DEFAULT_BACKOFF = 2.0      # seconds; doubled each retry


@dataclass
class StepResult:
    target: str          # concrete step name (e.g. "summary" or "sum[a.md]")
    status: str          # "built" | "cached" | "skipped"
    artifact: Path
    provider: str = ""
    model: str = ""
    meta: dict = field(default_factory=dict)


class BuildError(RuntimeError):
    pass


def _artifact_path(wf: Workflow, step: Step) -> Path:
    if step.item_name is not None:                  # foreach instance
        name = step.item_name
        if not name.endswith(".md"):
            name += ".md"
        return wf.build_dir / step.group / name
    if step.target.output:
        return wf.root / step.target.output
    return wf.build_dir / f"{step.name}.md"


def _atomic_write(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically (temp file + os.replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def _materialize(wf: Workflow, step: Step, needs_text: dict) -> tuple[str, dict]:
    """Render a step's final prompt. Returns (prompt, inputs-used)."""
    template = resolve_prompt(wf, step.target)
    item_name = item_content = None

    if step.item_path is not None:                  # foreach: input is the match
        item_content = (wf.root / step.item_path).read_text(errors="replace")
        item_name = step.item_name
        inputs = {step.item_path: item_content}
    elif step.target.inputs:
        inputs = ctx.load_inputs(wf, step.target.inputs)
    else:
        inputs = ctx.load_inputs(wf)

    context_files = ctx.load_context(wf)
    prompt = render(
        template, inputs=inputs, context=context_files, needs=needs_text,
        item_name=item_name, item_content=item_content,
    )
    return prompt, inputs


def _run_with_retry(provider, request, *, attempts: int, backoff: float, log):
    """Invoke ``provider.run`` with exponential backoff on transient failure."""
    last_exc: Exception | None = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            return provider.run(request)
        except Exception as exc:  # noqa: BLE001 - provider errors are opaque
            last_exc = exc
            if attempt >= attempts:
                break
            delay = backoff * (2 ** (attempt - 1))
            log(f"  [retry]   {request.target} attempt {attempt}/{attempts} "
                f"failed: {exc}; retrying in {delay:g}s")
            logger.warning("step %s failed (attempt %d/%d): %s",
                           request.target, attempt, attempts, exc)
            time.sleep(delay)
    raise BuildError(f"step {request.target!r} failed after {attempts} "
                     f"attempt(s): {last_exc}")


def build(
    wf: Workflow,
    goals: list | None = None,
    *,
    force: bool = False,
    provider_override: str | None = None,
    model_override: str | None = None,
    dry_run: bool = False,
    jobs: int = 1,
    log=print,
) -> list:
    """Build ``goals`` (or the whole workflow). Returns a list of StepResult.

    ``jobs`` > 1 compiles independent steps concurrently.
    """
    steps, groups = expand(wf)
    deps = {name: step.deps for name, step in steps.items()}
    plan = build_plan(deps, resolve_goals(goals, groups))    # validates + cycles
    plan_index = {name: i for i, name in enumerate(plan)}

    cache = Cache(wf.cache_path)
    artifacts: dict[str, str] = {}          # step -> compiled text
    keys: dict[str, str] = {}               # step -> cache key
    lock = threading.Lock()
    results: list[StepResult] = []

    def process(name: str) -> StepResult:
        step = steps[name]
        with lock:
            needs_text = {
                g: "\n\n".join(
                    f"### {steps[m].item_name or m}\n\n{artifacts[m]}"
                    for m in groups[g]
                )
                for g in step.need_groups
            }
            up_keys = [keys[d] for d in step.deps]

        prompt, inputs = _materialize(wf, step, needs_text)
        provider_name = provider_override or step.target.provider or wf.defaults.provider
        model = model_override or step.target.model or wf.defaults.model
        kind = step.target.kind or wf.defaults.kind
        params = {**wf.defaults.params, **step.target.params}

        key = compute_key(
            prompt=prompt, provider=provider_name, model=model,
            kind=kind, params=params, upstream_keys=up_keys,
        )
        artifact_path = _artifact_path(wf, step)

        with lock:
            keys[name] = key
            fresh = (not force) and cache.is_fresh(name, key, wf.root)

        if fresh:
            text = artifact_path.read_text()
            with lock:
                artifacts[name] = text
            log(f"  [cached]  {name}  ({artifact_path.relative_to(wf.root)})")
            return StepResult(name, "cached", artifact_path, provider_name, model)

        if dry_run:
            with lock:
                artifacts[name] = ""
            log(f"  [stale]   {name}  -> would build with {provider_name}")
            return StepResult(name, "skipped", artifact_path, provider_name, model)

        provider = get_provider(provider_name)
        ok, reason = provider.available()
        if not ok:
            raise BuildError(
                f"step {name!r} needs provider {provider_name!r} which is "
                f"unavailable: {reason}"
            )

        log(f"  [build]   {name}  via {provider_name}" + (f" ({model})" if model else ""))
        request = InferenceRequest(
            target=name, prompt=prompt, kind=kind, model=model,
            params=params, workdir=wf.root, inputs=inputs,
        )
        attempts = int(params.get("retries", DEFAULT_ATTEMPTS))
        backoff = float(params.get("retry_backoff", DEFAULT_BACKOFF))
        result = _run_with_retry(provider, request,
                                 attempts=attempts, backoff=backoff, log=log)

        _atomic_write(artifact_path, result.text)
        entry = Entry(
            key=key,
            artifact=artifact_path.relative_to(wf.root).as_posix(),
            provider=result.provider, model=result.model, kind=kind,
            created=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            inputs=list(inputs), needs=list(step.deps), meta=result.meta,
        )
        with lock:
            artifacts[name] = result.text
            cache.put(name, entry)
        return StepResult(name, "built", artifact_path,
                          result.provider, result.model, result.meta)

    if dry_run or jobs <= 1:
        for name in plan:
            results.append(process(name))
    else:
        results = _run_parallel(plan, deps, process, jobs)

    if not dry_run:
        cache.save()

    results.sort(key=lambda r: plan_index[r.target])
    return results


def _run_parallel(plan, deps, process, jobs: int) -> list:
    """Dependency-aware concurrent scheduler: start a step only once all of its
    in-plan dependencies have completed."""
    in_plan = set(plan)
    remaining = {n: (set(deps[n]) & in_plan) for n in plan}
    done: set = set()
    results: list = []

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        inflight: dict = {}

        def launch() -> None:
            for n in plan:
                if n not in done and n not in inflight.values() \
                        and not (remaining[n] - done):
                    inflight[ex.submit(process, n)] = n

        launch()
        while inflight:
            finished, _ = wait(list(inflight), return_when=FIRST_COMPLETED)
            for fut in finished:
                n = inflight.pop(fut)
                results.append(fut.result())   # propagates BuildError
                done.add(n)
            launch()
    return results


def status(wf: Workflow, goals: list | None = None) -> list:
    """Report build state without running anything (dry run)."""
    return build(wf, goals, dry_run=True, log=lambda *_: None)

# Break the `Agent.respond` API: rename `user_message` to `prompt` and make it async

## What

Two coupled breaking changes to `mirofish_lab/agent.py`:

1. Rename the first positional/keyword arg of `Agent.respond` from
   `user_message` to `prompt`. No deprecation alias; old kwarg form
   raises `TypeError`.
2. Make `Agent.respond` async (`async def respond(...)`). All synchronous
   callers must migrate to `await` or wrap in `asyncio.run`. The
   simulation primitives (`parallel_run`, `debate`, `round_table`) are
   rewritten on top of `asyncio.gather`.

## Why

- Async unlocks proper concurrency for `parallel_run` instead of the
  current `ThreadPoolExecutor` hack, which doesn't scale beyond ~8
  agents and serialises poorly with the OpenAI client's connection pool.
- Renaming `user_message` → `prompt` matches everyone's mental model
  ("I'm passing a prompt to a model") and makes the call sites read
  more naturally.

## Scope

- `mirofish_lab/agent.py` — async signature, kwarg rename.
- `mirofish_lab/simulation.py` — rewrite all three primitives on
  `asyncio.gather`.
- `pr-review-rehearsal/cli.py`, `pre-flight-rehearsal/cli.py`,
  `adversarial-security-sim/cli.py`, `blast-radius-prediction/cli.py`,
  `rollout-rehearsal/cli.py` — each currently calls `parallel_run(...)`
  synchronously from `main()`; needs to wrap with `asyncio.run()`.
- Documentation in each experiment's README needs updating.

## Constraints

- **No backward compat shim**: this is a sandbox; we can break things.
  But all five experiments must be migrated in the same change so no
  experiment is broken at any commit.
- **Tests**: there are no unit tests today. The migration is verified
  by running each experiment end-to-end against an existing fixture
  and confirming the output report still gets produced.
- **Memory layer is unaffected** — `LocalMemory` stays sync because it
  is local file I/O.
- **CAMEL-AI fallback path** uses `agent.step(...)` which is sync;
  wrap it with `asyncio.to_thread`.

## Out of scope

- Switching to a streaming response API.
- Adding type-stubs or async typing improvements beyond what mypy
  needs to keep passing.

## Affected subsystems

- `mirofish_lab` (the change)
- All five experiments (`pr-review-rehearsal`, `pre-flight-rehearsal`,
  `adversarial-security-sim`, `blast-radius-prediction`,
  `rollout-rehearsal`)

## What success looks like

After the change, all five experiments still produce their usual
markdown reports against their committed fixtures, and a synthetic
benchmark of "fan out 16 agents in parallel against the same prompt"
shows wall-clock improvement over the previous ThreadPoolExecutor
implementation.

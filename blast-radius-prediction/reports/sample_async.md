# Blast-radius prediction — fixtures/sample_async.diff

> Repo root: /home/user/Playground · Changed symbols: 3 · Affected subsystems: 5 · Model: gpt-5.4-mini

_Generated 2026-04-29T16:18:30Z_

## Changed symbols

- `Agent.respond` in `mirofish_lab/agent.py`:90
- `DebateTurn` in `mirofish_lab/simulation.py`:20
- `parallel_run` in `mirofish_lab/simulation.py`:25

## Subsys[adversarial-security-sim]

Subsys[adversarial-security-sim]

What breaks in this subsystem
- `Agent.respond` becoming `async` breaks every synchronous call site in this package.
- In `adversarial-security-sim/cli.py`, the pipeline currently looks synchronous. If it calls `agent.respond(...)` directly anywhere, that will now return a coroutine instead of `AgentResponse`, and downstream code will fail when it tries to access response fields or stringify it.
- `parallel_run` now calls `asyncio.run(...)` internally. If this subsystem is invoked from an environment that already has an event loop running, that will raise `RuntimeError: asyncio.run() cannot be called from a running event loop`.
- If any code in this package imports or relies on `DebateTurn`/`parallel_run` as synchronous helpers, their behavior is now coupled to asyncio and may no longer fit into the current sync control flow.

What still works
- Pure parsing/markdown report generation logic in this subsystem should still work, as long as it does not depend on `Agent.respond` being synchronous.
- Any code paths that only construct `Finding` objects, read audit files, or format report text are unaffected.
- If `adversarial-security-sim` is used from a top-level script that is fully synchronous and does not already run an event loop, `parallel_run` can still function, assuming all other call sites are updated to await or otherwise consume async results correctly.

What I would need to check
- All uses of `Agent.respond` in `adversarial-security-sim/cli.py` and any helper functions: every call site must be updated to `await`.
- Whether `cli.py` is currently structured around synchronous functions. If so, the CLI entrypoint likely needs an async `main()` plus `asyncio.run(main())`.
- Any place that expects `parallel_run(...)` to be callable from inside existing async code. The new `asyncio.run()` wrapper will conflict there.
- Whether the imported `DebateTurn` type is used in a way that assumes synchronous debate execution; the dataclass itself is unchanged, but the orchestration around it may need to become async.
- Whether `mirofish_lab.debate` or other imported utilities exposed to this subsystem already manage concurrency. If they do, this change may cause nested event-loop issues unless the call path is adjusted.

Migration steps callers would need
- Update all `agent.respond(...)` call sites to `await agent.respond(...)`.
- Convert synchronous debate orchestration to async:
  - make the containing function `async def`
  - gather response coroutines with `await`
  - only use `asyncio.run()` at the outermost process boundary
- If `parallel_run` is called from async code, remove its internal `asyncio.run()` wrapper and let the caller await the async helper directly, or provide separate sync/async entrypoints.
- For the CLI, wrap the full pipeline in an async `main()` and call it once from the script entrypoint.

Net: this patch is a breaking API change for this subsystem unless `cli.py` and any debate orchestration are migrated to async end-to-end.

## Subsys[blast-radius-prediction]

### Subsys[blast-radius-prediction]

#### What breaks in this subsystem
- `Agent.respond` changing from sync to `async` breaks any code in this subsystem that calls it directly and expects an `AgentResponse` immediately.
- `parallel_run` changing to call `asyncio.run(...)` breaks any use from within an already-running event loop. In that case it will raise `RuntimeError: asyncio.run() cannot be called from a running event loop`.
- The `DebateTurn` symbol itself looks unchanged in shape from the diff shown, but if this subsystem uses it as part of synchronous orchestration, the surrounding control flow may now be mismatched with the async response path.

#### What still works
- Anything in this subsystem that only consumes already-produced `AgentResponse` objects, formats them, or assembles reports will still work.
- Code paths that do not call `Agent.respond` or `parallel_run` are unaffected.
- If this subsystem is run strictly from a sync top-level entrypoint and all callers are updated appropriately, `parallel_run` can still function.

#### What I would need to check
- Every call site of `agent.respond(...)` in this package: they must be `await`ed now.
- Whether any caller of `parallel_run(...)` is already inside async code. If yes, `asyncio.run()` inside `parallel_run` is a problem.
- Whether this package has a synchronous CLI or service entrypoint that calls these functions directly; if so, it needs an async `main()` and a single outer `asyncio.run(...)`.
- Whether any code uses `DebateTurn` as part of a synchronous pipeline that now expects coroutines instead of responses.

#### Migration steps callers would need
- Change `agent.respond(...)` call sites to `await agent.respond(...)`.
- Make any function that calls it `async def`.
- Ensure `asyncio.run()` is only used at the process boundary, not inside library helpers.
- If `parallel_run` is called from async code, switch it to an async helper and `await` it instead of wrapping it internally.

#### Net impact
This is a breaking API change for this subsystem unless all response-generation paths are migrated to async end-to-end.

## Subsys[mirofish_lab]

### Subsys[mirofish_lab]

#### What breaks in this subsystem
- `Agent.respond` changing from synchronous to `async def` breaks every call site in `mirofish_lab` that expects an immediate `AgentResponse`.
- In `simulation.parallel_run`, the current implementation calls `agent.respond(...)` directly from a thread pool and then consumes the returned objects as results. With `respond` now async, those submissions would produce coroutine objects unless the caller is updated to await them.
- `parallel_run` itself now wraps its work in `asyncio.run(...)`. That is a breaking change for any code in this subsystem that calls `parallel_run` from inside an already running event loop, because `asyncio.run()` will raise `RuntimeError` in that case.
- The new internal helper `_parallel_run_async` is async-only; any direct or indirect synchronous use of it would be invalid.
- `DebateTurn` itself is unchanged as a dataclass, so the symbol does not break structurally. What can break is any orchestration code that assumes debate steps can still be driven synchronously via `Agent.respond`.

#### What still works
- `DebateTurn` remains a plain dataclass with the same fields, so existing construction and field access still work.
- Code in this subsystem that only reads reports, formats markdown, or manipulates filesystem paths is unaffected by this change.
- The Camel agent bridge in `Agent.respond` still exists functionally; its `.step(...)` call is just moved behind `await asyncio.to_thread(...)`.
- If a caller is purely synchronous and invokes `parallel_run` only from a top-level script, the new wrapper can still work, provided there is no active event loop and the call sites do not depend on sync `respond` semantics.

#### What I would need to check
- Every direct call to `agent.respond(...)` anywhere in `mirofish_lab`, including in `simulation.py` and any other helpers, must be updated to `await`.
- Any code that uses `parallel_run(...)` from an async context must be identified, because the new `asyncio.run(...)` wrapper will fail there.
- Whether `simulation.py` is intended to be library code or CLI-facing code. If it is library code, `asyncio.run()` inside `parallel_run` is especially risky because it prevents composition.
- Whether any callers depend on `parallel_run` preserving the exact old execution model. The old version used a thread pool and returned ordered results; the new version still returns gathered results, but only after a full event-loop run.
- Whether any tests assert that `respond` is synchronous or monkeypatch it with a non-async stub; those tests will need to be rewritten.

#### Migration steps callers would need
- Update all `Agent.respond(...)` call sites to `await agent.respond(...)`.
- Make any function that calls `respond` async as well.
- For `parallel_run`, either:
  - call it only from synchronous outermost code, or
  - change it to expose an async API and have callers `await` the async helper directly.
- Ensure `asyncio.run()` is used only once at the process boundary, not inside reusable library helpers.
- If `DebateTurn` is used in a debate flow driven by `respond`, migrate the surrounding debate orchestration to async end-to-end.

#### Net effect for this subsystem
This is a breaking API change for `mirofish_lab` unless all response-producing paths are migrated to async. The dataclass `DebateTurn` itself is stable, but the orchestration around it is no longer compatible with synchronous callers.

## Subsys[pr-review-rehearsal]

### Subsys[pr-review-rehearsal]

#### What breaks in this subsystem
- `Agent.respond` becoming `async` breaks any synchronous call site in `pr-review-rehearsal` that expects an `AgentResponse` immediately.
- The CLI entrypoint in `cli.py` is currently structured synchronously at the top level. If it calls `agent.respond(...)` directly, those calls will now return coroutine objects unless they are awaited.
- `parallel_run` changing to call `asyncio.run(...)` internally is a breaking change if this subsystem is already running inside an event loop. In that case, `asyncio.run()` will raise `RuntimeError`.
- Any code in this subsystem that uses `DebateTurn` only as part of a synchronous debate pipeline is not structurally broken by the dataclass itself, but the surrounding orchestration may no longer work if it assumes sync agent calls.

#### What still works
- Pure CLI argument parsing and file/path handling in `cli.py` still work.
- Any report rendering or markdown formatting logic that only consumes already-built `AgentResponse` / `Report` objects is unaffected.
- `DebateTurn` itself remains a dataclass with the same shape, so construction and field access still work.
- If this subsystem is invoked from a fully synchronous top-level script and all response call sites are updated, `parallel_run` can still function as an outermost wrapper.

#### What I would need to check
- Every call site of `agent.respond(...)` in `pr-review-rehearsal/cli.py` and any helper code: these must be awaited now.
- Whether `cli.py` already has or needs an async `main()` wrapper. If it does any agent calls, the entrypoint likely needs `asyncio.run(main())`.
- Whether `parallel_run(...)` is called from any context that may already have an event loop. If yes, the new internal `asyncio.run()` is a problem.
- Whether any tests or scripts in this subsystem monkeypatch `Agent.respond` with a synchronous stub. Those tests will need to be updated to async semantics.
- Whether the imported `DebateTurn` is used in a way that assumes synchronous execution; the type itself is unchanged, but the flow around it may need to become async.

#### Migration steps callers would need
- Change all `agent.respond(...)` call sites to `await agent.respond(...)`.
- Make any function that calls `respond` async.
- Move the CLI pipeline into an `async def main(...)` and call it once from the process boundary with `asyncio.run(...)`.
- Do not call `parallel_run(...)` from inside another running event loop unless its implementation is changed to expose a pure async helper and the caller awaits that helper directly.
- Keep `asyncio.run()` only at the outermost boundary of the program.

#### Net effect for this subsystem
This is a breaking API change for `pr-review-rehearsal` unless the CLI pipeline and any review orchestration are migrated to async end-to-end.

## Subsys[pre-flight-rehearsal]

### Subsys[pre-flight-rehearsal]

#### What breaks in this subsystem
- `Agent.respond` becoming `async def` breaks any direct synchronous call sites in `pre-flight-rehearsal/cli.py` or any helpers it uses. If this package calls `agent.respond(...)` without `await`, it will get a coroutine object instead of `AgentResponse`.
- `parallel_run` now uses `asyncio.run(...)` internally. If `pre-flight-rehearsal` ever calls it from an environment with an already-running event loop, that will raise `RuntimeError: asyncio.run() cannot be called from a running event loop`.
- Any code in this subsystem that expects `parallel_run(...)` to be a plain synchronous library helper is now coupled to asyncio lifecycle management.
- `DebateTurn` itself is not structurally changed in the diff shown, so the dataclass shape should not break. What can break is orchestration that assumes synchronous agent execution.

#### What still works
- Pure prompt construction, issue formatting, report rendering, and file output logic in `pre-flight-rehearsal/cli.py` should still work, as long as they do not depend on synchronous `Agent.respond`.
- `DebateTurn` field access and construction remain valid if its definition is unchanged.
- If this subsystem is used only from a top-level synchronous script and all `respond` call sites are updated, `parallel_run` can still be used from the process boundary.

#### What I would need to check
- Every `agent.respond(...)` call site in `pre-flight-rehearsal/cli.py` and any helper imported by it. All of them must become `await agent.respond(...)`.
- Whether `cli.py` has a synchronous `main()` that orchestrates the agent pipeline. If so, it will need to become `async def main()` with a single outer `asyncio.run(main())`.
- Whether `parallel_run(...)` is called from any code path that may already be running inside asyncio. If yes, the internal `asyncio.run()` wrapper is incompatible.
- Whether any tests in this subsystem mock `Agent.respond` as a synchronous function. Those tests will need async-compatible mocks.
- Whether `DebateTurn` is used only as a data container or as part of synchronous debate orchestration. The type is stable, but the flow around it may need async migration.

#### Migration steps callers would need
- Change every `agent.respond(...)` call to `await agent.respond(...)`.
- Make any function that calls `respond` async.
- Move the main pipeline in `cli.py` into `async def main(...)`.
- Call `asyncio.run(main())` only once at the process boundary.
- Avoid calling `parallel_run(...)` from within existing async code unless its API is changed to expose a directly awaitable helper.

#### Net effect for this subsystem
This is a breaking API change for `pre-flight-rehearsal` unless its CLI pipeline and any agent orchestration are migrated to async end-to-end.

## Judge roll-up

## Ranked list

1. **mirofish_lab** — **high risk**
2. **pr-review-rehearsal** — **high risk**
3. **pre-flight-rehearsal** — **high risk**
4. **adversarial-security-sim** — **medium risk**
5. **blast-radius-prediction** — **medium risk**

## Winner

**mirofish_lab**

## Brief rationale per rank

### 1) mirofish_lab — winner
This is the source subsystem, so it has the clearest direct blast radius. The patch changes its API contract:
- `Agent.respond` becomes async: **“`async def respond(...)`”** and **“`BREAKING: respond is now async. All callers must `await` it.`”**
- `parallel_run` switches to `asyncio.run(...)`: **“`BREAKING: now requires running inside an asyncio event loop.`”** is actually misleading, because the code does `return asyncio.run(_parallel_run_async(agents, prompt))`, which requires *not already being in* an event loop.

This subsystem’s reaction is strongest because it correctly identifies both direct call-site breakage and nested-loop risk. It also correctly notes that `DebateTurn` itself is unchanged structurally: **“`DebateTurn itself is unchanged as a dataclass`”**.

### 2) pr-review-rehearsal
This reaction is mostly consistent with the actual change and is scoped to a CLI-style caller. It correctly flags synchronous call sites and event-loop concerns:
- **“`Agent.respond` becoming async breaks any synchronous call site`”**
- **“`parallel_run` changing to call `asyncio.run(...)` internally is a breaking change if this subsystem is already running inside an event loop.`”**

This is high risk if it directly invokes the agent pipeline, but the response is somewhat generic and lacks concrete evidence of specific files beyond `cli.py`.

### 3) pre-flight-rehearsal
Also high risk, but the response is again mostly templated and less evidence-backed. It correctly describes the two main failure modes:
- returning coroutine objects if not awaited
- `asyncio.run()` failing in a running loop

It’s a plausible impact analysis, but there’s no concrete sign it inspected actual call patterns.

### 4) adversarial-security-sim
This one is slightly less convincing because it makes a claim that may be too speculative: **“`If advesarial-security-sim is used from a top-level script that is fully synchronous...`”**. The risks identified are real in general, but the response appears broader and less anchored to the diff or to that subsystem’s actual architecture. Still, it correctly flags the main breakage modes.

### 5) blast-radius-prediction
This is the least specific response. It is correct at the conceptual level, but it stays generic:
- **“`Anything ... that only consumes already-produced AgentResponse objects ... will still work.`”**
- **“`Every call site of agent.respond(...) ... must be awaited now.`”**

It doesn’t add much beyond the obvious, and it doesn’t strongly distinguish whether the subsystem actually has direct breakage vs. only transitive risk.

## Per-subsystem risk and blocking issues

### mirofish_lab — **high**
**Blocking issues**
- Every synchronous caller of `Agent.respond` must be converted to async.
- `parallel_run` now uses `asyncio.run(...)`; any call from inside an existing loop will fail.
- Any tests that stub `respond` synchronously may break.

**Concrete evidence**
- **“`async def respond(...)`”**
- **“`result = await asyncio.to_thread(self._camel_agent.step, msg)`”**
- **“`return asyncio.run(_parallel_run_async(agents, prompt))`”**

### pr-review-rehearsal — **high**
**Blocking issues**
- If the CLI pipeline calls `agent.respond` directly, it will now get coroutine objects.
- If it invokes `parallel_run` from async-aware code, `asyncio.run()` becomes a hard error.
- Likely needs `async def main()` + outer `asyncio.run(main())`.

**Concrete evidence**
- **“`Change all agent.respond(...) call sites to await agent.respond(...)`”**
- **“`Move the CLI pipeline into an async def main(...) and call it once from the process boundary with asyncio.run(...)`”**

### pre-flight-rehearsal — **high**
**Blocking issues**
- Same as above: sync call sites become invalid.
- Any nested async context will conflict with `asyncio.run()` inside `parallel_run`.

**Concrete evidence**
- **“`If pre-flight-rehearsal ever calls it from an environment with an already-running event loop, that will raise RuntimeError`”**

### adversarial-security-sim — **medium**
**Blocking issues**
- Direct use of `respond` will now require await.
- Potential nested-loop issue if this subsystem is async already.

**Concrete evidence**
- **“`If this subsystem is invoked from an environment that already has an event loop running, that will raise RuntimeError`”**

### blast-radius-prediction — **medium**
**Blocking issues**
- Same API-level breakage if it calls `respond` or `parallel_run`.

**Concrete evidence**
- **“`Every call site of agent.respond(...) in this package: they must be awaited now.`”**

## What still works

Across the board, the consistent “still works” items are:
- pure parsing / formatting / report generation
- code paths that only consume existing `AgentResponse` objects
- `DebateTurn` as a dataclass, since it appears unchanged

The strongest explicit statement is from mirofish_lab:
- **“`DebateTurn remains a plain dataclass with the same fields`”**
- **“`Code ... that only reads reports, formats markdown, or manipulates filesystem paths is unaffected`”**

## Recommended migration order

1. **Update source package `mirofish_lab` first**
   - Make all internal call sites await `Agent.respond`.
   - Decide whether `parallel_run` should remain a sync wrapper or become a true async API.

2. **Patch CLI-facing subsystems next**
   - `pr-review-rehearsal`
   - `pre-flight-rehearsal`
   - `adversarial-security-sim` if it has a CLI pipeline

3. **Then update tests and mocks**
   - especially any synchronous stubs for `Agent.respond`

4. **Finally, audit all consumers for event-loop boundaries**
   - ensure `asyncio.run()` is only at the process entrypoint, not inside reusable library helpers

## Subsystems whose response sounds confused

### mirofish_lab
Mostly good, but there is one confusing line in its own summary:
- **“`parallel_run` now wraps its work in `asyncio.run(...)`. That is a breaking change for any code ... inside an already running event loop, because asyncio.run() will raise RuntimeError in that case.`”**
This is correct. No issue here.

### adversarial-security-sim
This one sounds the most speculative. It talks about a CLI pipeline and imported debate helpers without showing evidence that those are actual direct dependencies. It may need more context before merge.

### blast-radius-prediction
Feels generic and thin. Not wrong, but it doesn’t seem to have subsystem-specific grounding.

## Open questions

- Do any of these subsystems call `parallel_run` from within async code today?
- Is `parallel_run` intended to remain a library helper, or should it be split into:
  - `async def parallel_run_async(...)`
  - `def parallel_run(...)` as a top-level convenience wrapper
- Are there any tests that monkeypatch `Agent.respond` as a sync function?
- Do any CLIs already have async entrypoints, or will they need a new `async main()`?
- Is the return annotation of `Agent.respond` now incorrect? The diff shows `async def respond(...) -> AgentResponse`, but an async function returns an awaitable/coroutine, so type hints likely need adjustment.

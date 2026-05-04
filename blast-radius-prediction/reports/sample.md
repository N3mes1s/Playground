# Blast-radius prediction — fixtures/sample.diff

> Repo root: /home/user/Playground · Changed symbols: 1 · Affected subsystems: 5 · Model: gpt-5.4-mini

_Generated 2026-04-29T16:05:55Z_

## Changed symbols

- `Agent.respond` in `mirofish_lab/agent.py`:90

## Subsys[adversarial-security-sim]

Subsys[adversarial-security-sim]

### What breaks in this subsystem

My subsystem does **not** call `Agent.respond` directly in the shown code path, so the local `cli.py` entrypoint itself should still import and run as before.

However, anything in the security-sim pipeline that **instantiates/uses `mirofish_lab.Agent` and then calls `respond(..., user_message=...)` by keyword** will break immediately with a Python argument error, because the parameter name changed to `prompt` and the old keyword is no longer accepted.

Concretely, breakage would be:

- **Keyword callers using `user_message=`**: `TypeError: got an unexpected keyword argument 'user_message'`
- Any code that relied on the method signature for introspection or wrappers that forward kwargs by name.

### What still works

- Existing callers that invoke `respond("...")` positionally should still work.
- Passing `tags=` should still work unchanged.
- The `adversarial-security-sim/cli.py` file shown does not depend on the old `respond` signature directly, so its own top-level behavior is unchanged unless the underlying `mirofish_lab` debate implementation uses the renamed keyword internally.
- The non-streaming behavior is unchanged from this diff; `stream` is added but described as a no-op stub.

### What I would need to check

Within my subsystem, I would verify:

1. **All internal uses of `Agent.respond`** in the debate/agent orchestration path:
   - whether any call sites pass `user_message=` by name
   - whether any wrappers or decorators forward the old kwarg

2. **The debate machinery imported from `mirofish_lab`**:
   - if `debate(...)` or related helpers call `Agent.respond` with keyword arguments, they need to be updated too

3. **Any tests or fixtures** in the security-sim flow that assert on method signatures or error strings.

4. **Whether `stream=True` is intentionally inert**:
   - if callers in the security-sim subsystem start setting `stream=True`, they should not expect streaming output yet.

### Migration steps for callers

Callers in or around this subsystem should update from:

```python
agent.respond(user_message="text")
```

to:

```python
agent.respond("text")
```

or:

```python
agent.respond(prompt="text")
```

They should also:

- stop forwarding `user_message=` as a kwarg
- ignore `stream` for now unless the underlying implementation is later extended

If you want, I can also help enumerate the exact places in this subsystem that would need a signature update once the `mirofish_lab` debate code is inspected.

## Subsys[blast-radius-prediction]

### Subsys[blast-radius-prediction]

This subsystem is the one directly affected by the change, because it owns the diff-analysis / round-table prediction flow and imports `Agent` from `mirofish_lab`.

### What breaks in this subsystem

The main risk is any code path that calls:

```python
Agent.respond(user_message=...)
```

That will now fail with:

```python
TypeError: got an unexpected keyword argument 'user_message'
```

Because the method signature changed from:

```python
respond(self, user_message: str, *, tags=())
```

to:

```python
respond(self, prompt: str, *, tags=(), stream=False)
```

So in this subsystem, anything that forwards the old keyword name into agent personas or simulations would break immediately.

### What still works

- Positional calls like `agent.respond("text")` still work.
- `tags=` still works unchanged.
- The CLI entrypoint itself still imports and runs normally, unless its runtime path exercises the old keyword form.
- The new `stream` kwarg is accepted, but based on the diff it is currently a no-op stub, so behavior should remain non-streaming.

### What I would need to check

I would verify these specific things in the blast-radius-prediction flow:

1. **All `respond(...)` call sites**
   - ensure none use `user_message=`
   - ensure any wrapper/adapter code passes `prompt=` or positional text

2. **Any code that inspects the `respond` signature**
   - especially forwarding logic that relies on parameter names

3. **Simulation orchestration**
   - if the round-table agent loop assumes `user_message` in generated prompts or mock adapters, it needs to be updated

4. **Tests / fixtures**
   - any tests that assert on `TypeError` behavior or exact signature text will need adjustment

### Migration steps for callers

Update callers from:

```python
agent.respond(user_message="hello")
```

to either:

```python
agent.respond("hello")
```

or:

```python
agent.respond(prompt="hello")
```

If any caller is prepared to pass `stream=True`, it can do so safely, but should not expect streamed output yet.

If you want, I can next narrow this down to the exact blast-radius-prediction code paths that would need a touch based on the current repo layout.

## Subsys[mirofish_lab]

### Subsys[mirofish_lab]

This change is **inside my subsystem**, so I can be precise about the impact.

## What breaks in `mirofish_lab`

The only direct break is for any code that calls:

```python
agent.respond(user_message="...")
```

That will now fail with:

```python
TypeError: got an unexpected keyword argument 'user_message'
```

because `Agent.respond` has been renamed from:

```python
respond(self, user_message: str, *, tags=())
```

to:

```python
respond(self, prompt: str, *, tags=(), stream=False)
```

So the break is specifically:

- **old keyword argument name removed**
- **callers depending on `user_message=` by name will fail**
- **any wrapper/adapter forwarding kwargs unchanged may also fail**

## What still works

These usages should still work:

- `agent.respond("hello")` — positional call
- `agent.respond(prompt="hello")` — new keyword name
- `agent.respond("hello", tags=("x",))` — tags unchanged
- existing non-`respond` behavior in `mirofish_lab` remains unaffected by this diff

The new `stream` parameter is accepted, but per the diff it is currently a **no-op stub**, so it should not change output behavior yet.

## What I would need to check

Within `mirofish_lab`, I would check all call sites of `Agent.respond`, especially:

1. **Any direct keyword use**
   - search for `user_message=`
   - search for `respond(` wrappers that forward kwargs

2. **Simulation code**
   - `parallel_run()` in `mirofish_lab/simulation.py` calls:
     ```python
     agent.respond(prompt, tags=("parallel",))
     ```
     so this part is already compatible and should keep working.

3. **Any debate/round-table helpers**
   - if they call `respond` positionally, they are fine
   - if they pass the old kwarg name, they will break

4. **Tests and fixtures**
   - any test asserting the old signature, old error strings, or old parameter name

5. **Any external-facing API usage inside the package**
   - if `Agent.respond` is re-exported or wrapped, the wrapper signature may need updating too

## Migration steps for callers

Update callers from:

```python
agent.respond(user_message="text")
```

to either:

```python
agent.respond("text")
```

or:

```python
agent.respond(prompt="text")
```

If a caller currently forwards a dict of kwargs, it must rename the key:

```python
kwargs["prompt"] = kwargs.pop("user_message")
```

For `stream`:

- it can be passed safely now
- but callers should not expect streaming behavior yet, since the diff marks it as a no-op stub

## Bottom line

- **Broken:** any `user_message=` keyword call
- **Safe:** positional calls and `prompt=` calls
- **Needs check:** internal wrappers/forwarders and any tests relying on the old signature

## Subsys[pr-review-rehearsal]

### Subsys[pr-review-rehearsal]

This subsystem owns the top-level CLI shown in `cli.py`, and it imports `Agent` from `mirofish_lab`. The change to `Agent.respond` can affect it indirectly.

## What breaks in this subsystem

The CLI itself does not call `Agent.respond` in the snippet shown, so **`pr-review-rehearsal/cli.py` should still import and start normally**.

What would break is any code path in the review pipeline that calls `Agent.respond` with the old keyword:

```python
agent.respond(user_message="...")
```

That will now raise:

```python
TypeError: got an unexpected keyword argument 'user_message'
```

So if this subsystem’s reviewer / implementer / judge orchestration forwards the old kwarg name anywhere, that call path will fail.

## What still works

- `cli.py` still imports `Agent`, `Persona`, `Report`, `parallel_run`, etc. as before.
- Positional calls like `agent.respond("text")` still work.
- `agent.respond(prompt="text")` will work with the new signature.
- `tags=` still works unchanged.
- The new `stream` argument is accepted, but from the diff it is a **no-op stub**, so this subsystem should not expect streamed output yet.

## What I would need to check

I would check the parts of this subsystem that sit behind the CLI entrypoint:

1. **Any `Agent.respond(...)` call sites**
   - ensure none use `user_message=`
   - ensure wrappers do not forward the old kwarg name

2. **Any code that builds review prompts**
   - if it passes the user text into `respond` by keyword, it must be updated to `prompt=`

3. **Tests / fixtures for the CLI flow**
   - especially anything that mocks or asserts the `respond` signature

4. **Any code that relies on method introspection**
   - for example wrappers that read parameter names or forward kwargs unchanged

## Migration steps for callers

If this subsystem contains callers using the old form, update them from:

```python
agent.respond(user_message="text")
```

to either:

```python
agent.respond("text")
```

or:

```python
agent.respond(prompt="text")
```

If there are forwarding helpers, rename the key before passing it through:

```python
kwargs["prompt"] = kwargs.pop("user_message")
```

## Bottom line

- **Broken:** any `user_message=` keyword call inside the PR-review rehearsal pipeline
- **Still works:** positional calls, `prompt=`, `tags=`
- **Needs check:** internal orchestration and tests, not the CLI import path itself

## Subsys[pre-flight-rehearsal]

### Subsys[pre-flight-rehearsal]

This change affects my subsystem **if it calls or forwards `Agent.respond`** anywhere in the pre-flight rehearsal pipeline.

## What breaks in this subsystem

Any call using the old keyword name will break:

```python
agent.respond(user_message="...")
```

That will now raise:

```python
TypeError: got an unexpected keyword argument 'user_message'
```

because `Agent.respond` now takes:

```python
respond(self, prompt: str, *, tags=(), stream=False)
```

So the breaking cases are:

- direct `user_message=` calls
- wrappers that forward kwargs unchanged
- any test or helper that relies on the old parameter name

## What still works

These should continue to work:

- `agent.respond("text")`
- `agent.respond(prompt="text")`
- `agent.respond(..., tags=(...))`
- the added `stream=` parameter, but only as a no-op for now

For the top-level `pre-flight-rehearsal/cli.py` entrypoint specifically, the shown code does **not** call `Agent.respond` directly, so the CLI import/startup path itself should remain fine unless deeper `mirofish_lab` paths still use `user_message=`.

## What I would need to check

Inside `pre-flight-rehearsal`, I would verify:

1. **All `Agent.respond` call sites**
   - search for `user_message=`
   - search for forwarding helpers that pass kwargs through

2. **Any code that builds prompts for personas**
   - make sure it passes the message positionally or via `prompt=`

3. **Any tests/mocks**
   - update signature expectations and error assertions

4. **Any streaming assumptions**
   - if callers start using `stream=True`, confirm they do not expect real streaming behavior yet

## Migration steps for callers

Update code from:

```python
agent.respond(user_message=body)
```

to either:

```python
agent.respond(body)
```

or:

```python
agent.respond(prompt=body)
```

If you forward kwargs, rename the key:

```python
kwargs["prompt"] = kwargs.pop("user_message")
```

## Bottom line

- **Broken:** old `user_message=` keyword calls
- **Still works:** positional calls, `prompt=`, `tags=`
- **Needs check:** any internal pre-flight rehearsal wrappers or tests that forward/inspect `Agent.respond`

## Judge roll-up

## Ranked list of subsystem reactions

### 1) **Subsys[mirofish_lab]** — **High risk**
**Why this ranks first:** it is the only subsystem that clearly says the change is *inside my subsystem* and directly identifies the concrete break. It also gives the most accurate compatibility detail.

Concrete passage:
> “This change is **inside my subsystem**, so I can be precise about the impact.”  
> “The only direct break is for any code that calls: `agent.respond(user_message="...")`”  
> “`parallel_run()` in `mirofish_lab/simulation.py` calls: `agent.respond(prompt, tags=("parallel",))` so this part is already compatible”

**Brief rationale:**  
This is the highest-confidence assessment. It correctly distinguishes the broken keyword form from the still-working positional and `prompt=` forms, and it names an internal call site that remains safe. Risk is high because the API is directly changed in the owning package, so any internal keyword callers will fail immediately.

---

### 2) **Subsys[pr-review-rehearsal]** — **Medium risk**
Concrete passage:
> “The CLI itself does not call `Agent.respond` in the snippet shown, so `pr-review-rehearsal/cli.py` should still import and start normally.”  
> “What would break is any code path in the review pipeline that calls `Agent.respond` with the old keyword”

**Brief rationale:**  
This looks like a plausible indirect consumer. The response is sensible and cautious: startup likely survives, but deeper pipeline calls may break if they forward `user_message=`. It’s not as certain as `mirofish_lab` because it doesn’t identify specific call sites, but the migration guidance is correct.

---

### 3) **Subsys[pre-flight-rehearsal]** — **Medium risk**
Concrete passage:
> “This change affects my subsystem **if it calls or forwards `Agent.respond`** anywhere in the pre-flight rehearsal pipeline.”  
> “For the top-level `pre-flight-rehearsal/cli.py` entrypoint specifically, the shown code does **not** call `Agent.respond` directly”

**Brief rationale:**  
This is similar in quality to `pr-review-rehearsal`: it correctly isolates the risk to downstream call paths, not CLI startup. It’s slightly less specific than the previous one, but still coherent and actionable. Medium risk because the subsystem may have wrappers forwarding kwargs.

---

### 4) **Subsys[blast-radius-prediction]** — **Medium risk, but somewhat speculative**
Concrete passage:
> “This subsystem is the one directly affected by the change, because it owns the diff-analysis / round-table prediction flow and imports `Agent` from `mirofish_lab`.”  
> “The main risk is any code path that calls: `Agent.respond(user_message=...)`”

**Brief rationale:**  
The assessment is plausible, but the claim “directly affected” is not substantiated by concrete call sites in the provided snippet. It still correctly identifies the breaking signature change and compatible forms. It’s a bit more assertive than the evidence supports, so I’d rank it below the more grounded ownership-based answer.

---

### 5) **Subsys[adversarial-security-sim]** — **Low to medium risk**
Concrete passage:
> “My subsystem does **not** call `Agent.respond` directly in the shown code path, so the local `cli.py` entrypoint itself should still import and run as before.”  
> “However, anything in the security-sim pipeline that **instantiates/uses `mirofish_lab.Agent` and then calls `respond(..., user_message=...)` by keyword** will break immediately”

**Brief rationale:**  
This is mostly reasonable, but it is the most tentative. It explicitly says the shown code path is unaffected and only indirect pipeline usage is risky. That makes it lower risk than the others, unless hidden callers exist. Still, the incompatibility diagnosis is correct.

---

## Winner
**Subsys[mirofish_lab]**

## Brief rationale for the winner
It is the most grounded and specific: it acknowledges the change is in its own subsystem, quotes the exact breaking case, and identifies a safe internal call site:
> “`parallel_run()` … calls: `agent.respond(prompt, tags=("parallel",))` so this part is already compatible”

That combination of ownership, concrete breakage, and evidence-based safety makes it the strongest answer.

---

## Roll-up: per-subsystem risk

- **mirofish_lab** — **High**
- **blast-radius-prediction** — **Medium**
- **pr-review-rehearsal** — **Medium**
- **pre-flight-rehearsal** — **Medium**
- **adversarial-security-sim** — **Low/Medium**

---

## Blocking issues to watch
1. **Any `respond(user_message=...)` calls** will fail with:
   > `TypeError: got an unexpected keyword argument 'user_message'`

2. **Any wrappers forwarding kwargs unchanged** are likely to break unless they rename the key to `prompt`.

3. **Any tests asserting the old signature or old error text** will need updates.

4. **`stream=True` is not yet functional**  
   The diff says:
   > “New 'stream' kwarg added (currently a no-op stub).”
   So callers must not assume streaming behavior.

---

## Recommended migration order
1. **Update all direct `Agent.respond(user_message=...)` callers first**
2. **Then update wrapper/helper functions that forward kwargs**
3. **Then fix tests/fixtures that assert signature or error strings**
4. **Finally, review any code paths that may start using `stream=` and ensure they don’t expect real streaming**

---

## Subsystems whose response sounds confused
None are outright confused, but two are slightly overconfident about ownership:

- **blast-radius-prediction**:  
  > “This subsystem is the one directly affected”  
  This may be true, but it’s not proven from the provided evidence.

- **adversarial-security-sim**:  
  It is appropriately cautious, but if the hidden pipeline does use `Agent.respond`, its “local CLI unaffected” framing may understate the practical impact.

If you want, I can also produce a **merge-risk matrix** with “breaks now / breaks later / safe” columns for each subsystem.

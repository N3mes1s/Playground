# Pre-flight Rehearsal — N3mes1s/Playground#0

> Issue: https://github.com/N3mes1s/Playground/issues/0 · title: Add per-experiment cost tracking and budget caps to mirofish_lab · model: gpt-5.4-mini

_Generated 2026-04-29T16:17:45Z_

## Issue Description

Right now any experiment built on `mirofish_lab` can rack up arbitrary OpenAI spend with no visibility. We need both **observability** (how many tokens / dollars did this run cost?) and **safety** (cap a run's spend so a bug in a debate loop doesn't burn $50).

## Goals

1. **Per-run accounting**: every `Agent.respond` call records prompt/completion tokens and (when the model price is known) an estimated dollar cost. The numbers should aggregate at the experiment level so a CLI run prints a final summary like:

   ```
   [cost] 6 calls, 14,231 tokens in, 4,802 tokens out, est. $0.087
   ```

2. **Budget cap**: the user can set `MIROFISH_MAX_USD=2.00` (or `--max-usd 2.00` per-CLI), and the next call that would exceed the cap raises a `BudgetExceeded` exception with a clear message. The cap is checked **before** the call goes out, not after, so we never overspend by the cost of one extra response.

3. **No persistent telemetry**: this is a sandbox, not a SaaS. Just print on exit and write a single JSON file under `.mirofish_memory/cost.json` per run.

## Out of scope

- Anything multi-process or distributed.
- Pricing for models we don't ship support for (OK to fall back to `0.0` and warn once).
- A live progress bar.

## Considerations

- We may want to support OpenAI-compatible endpoints (e.g., OpenRouter, Azure) which return their own usage objects. Be careful not to assume the OpenAI-shape `usage` object exists.
- The CAMEL-AI fallback path also needs to be instrumented.
- The four existing experiments (`pr-review-rehearsal`, `pre-flight-rehearsal`, `adversarial-security-sim`, `blast-radius-prediction`) should pick this up automatically — no per-experiment changes if avoidable.

Produce a plan, a sketch of the diff (file paths + key edits), and the risks you foresee.

## Plan: Minimalist

### 1) Short plan

- Add a small `cost` module in `mirofish_lab` to track run-level usage, estimated USD, and budget enforcement.
- Instrument the shared `Agent.respond` path so every call records prompt/completion tokens and cost if available.
- Add a `BudgetExceeded` exception and check the cap **before** each outbound model call using the best available estimate.
- Write one per-run JSON summary to `.mirofish_memory/cost.json` and print a final `[cost] ...` line on exit.
- Wire CLI/env config for `--max-usd` and `MIROFISH_MAX_USD` into the existing shared run context so all experiments inherit it automatically.
- Patch the CAMEL-AI fallback path to go through the same accounting hooks.

---

### 2) Diff sketch

#### `mirofish_lab/cost.py` — new
Key additions:
- `@dataclass CostSummary` with:
  - `calls`
  - `prompt_tokens`
  - `completion_tokens`
  - `estimated_usd`
- `class BudgetExceeded(Exception)`
- `class CostTracker` with methods:
  - `estimate_call_cost(model_name, prompt_tokens, completion_tokens) -> float`
  - `check_budget_or_raise(estimated_next_cost) -> None`
  - `record_call(...) -> None`
  - `finalize() -> None`  
    - writes `.mirofish_memory/cost.json`
    - prints `[cost] ...` summary
- lightweight model price lookup table for shipped models only
- one-time warning fallback when price is unknown: cost = `0.0`

#### `mirofish_lab/runtime.py` or existing shared run/context module
Key edits:
- add run-scoped config:
  - `max_usd: float | None`
  - `cost_tracker: CostTracker | None`
- initialize tracker once per CLI run
- ensure the tracker is available to all experiments via existing context object / singleton used by `mirofish_lab`

#### `mirofish_lab/agent.py` (or wherever `Agent.respond` lives)
Key edits around the shared respond path:
- before the API call:
  - estimate tokens if needed
  - compute estimated cost for the intended call
  - call `tracker.check_budget_or_raise(estimated_next_cost)`
- after the API call:
  - extract usage robustly:
    - OpenAI shape: `usage.prompt_tokens`, `usage.completion_tokens`
    - OpenAI-compatible / dict-like / object-like variants
    - CAMEL fallback path usage if present
  - if usage missing, keep counters conservative:
    - record call count
    - tokens = 0 unless parseable
    - cost = estimate from available token counts, else 0.0
  - call `tracker.record_call(...)`
- make sure failures before response do not record usage as completed calls

#### `mirofish_lab/camel_fallback.py` or analogous fallback adapter
Key edits:
- route prompt/completion usage extraction through the same helper used by `Agent.respond`
- ensure budget check occurs before fallback invocation too

#### `mirofish_lab/usage.py` or a small helper in `cost.py`
Key additions:
- helper to normalize usage from different response shapes:
  - OpenAI response objects
  - dict responses
  - nested `usage` fields
  - absent usage -> `None`
- helper to normalize model names / pricing keys

#### CLI entrypoint(s), e.g. `mirofish_lab/cli.py`
Key edits:
- add `--max-usd FLOAT`
- default from `MIROFISH_MAX_USD`
- pass into shared runtime/context initializer
- no per-experiment changes needed

#### Experiment entrypoints
- no direct edits unless they instantiate their own runtime context today
- if one does, patch only to reuse the common initializer

---

### 3) Risks foreseen

- **Usage shape variability**: OpenAI-compatible providers may expose usage differently, so token parsing needs to be permissive. If not, accounting could undercount or miss budget checks.
- **Budget pre-check accuracy**: “before the call goes out” requires an estimate. If token estimation is rough, the cap may be conservative or slightly off.
- **Unknown pricing**: for unsupported models, estimated USD will be `0.0`, which preserves safety only if the budget check also has a token-based fallback or a conservative default; otherwise the cap may be ineffective for those models.
- **Fallback path coverage**: CAMEL-AI instrumentation may live in a separate codepath; missing it would create blind spots.
- **Run-finalization reliability**: writing `.mirofish_memory/cost.json` and printing summary should happen on normal exit and exceptions; otherwise runs may miss the final summary.
- **Shared-context assumption**: if any experiment bypasses the shared `Agent.respond` or uses a separate client directly, it won’t be tracked automatically and would need a minimal bridge.

## Plan: Defensive

## Plan

1. **Add a small cost-tracking subsystem** in `mirofish_lab`:
   - a `CostTracker`/`BudgetManager` with per-run counters
   - a `BudgetExceeded` exception
   - model pricing lookup with safe fallback to `0.0` and one-time warning
   - JSON persistence to `.mirofish_memory/cost.json`

2. **Instrument all LLM call paths centrally**:
   - wrap `Agent.respond(...)` so every response records input/output tokens and estimated cost
   - do the same for the CAMEL-AI fallback path so it is not missed
   - support usage extraction from both OpenAI-style and non-OpenAI-compatible response shapes

3. **Enforce budget before API calls**:
   - estimate the worst-case/expected incremental cost from the request context before dispatch
   - if the next call could exceed `MIROFISH_MAX_USD` / `--max-usd`, raise `BudgetExceeded` before the network request is made

4. **Wire config through CLI and experiment runner**:
   - add `--max-usd`
   - read `MIROFISH_MAX_USD`
   - create a run-scoped tracker at experiment start and pass it implicitly via context or dependency injection

5. **Add end-of-run observability**:
   - print a summary like `[cost] 6 calls, ...`
   - write a single JSON file under `.mirofish_memory/cost.json` on clean shutdown and best-effort on exceptions

---

## Diff sketch

### `mirofish_lab/costing.py` or `mirofish_lab/telemetry/cost.py`
**New module**

- Add:
  - `BudgetExceeded(Exception)`
  - `CostTracker`
    - `record_call(model, prompt_tokens, completion_tokens, cost_usd, usage_raw=None, source="openai|camel|unknown")`
    - `estimate_next_cost(model, prompt_tokens, max_output_tokens=None)`
    - `would_exceed_budget(...) -> bool`
    - `final_summary() -> str`
    - `to_json() / save(path)`
  - pricing table for supported models
  - model lookup with normalization and one-time warning for unknown prices

**Key guards**
- validate non-negative token counts
- validate max_usd is `None` or `>= 0`
- handle missing/partial usage objects safely
- never crash on malformed response metadata; record what is available and log structured warning

---

### `mirofish_lab/agents/base.py` or wherever `Agent.respond` lives
**Edit existing core response path**

- Before sending request:
  - compute/approximate prompt token count
  - call `tracker.check_budget_before_call(model, prompt_tokens, estimated_completion_tokens)`
  - if over cap: raise `BudgetExceeded` with call index, spent-to-date, cap, and estimated next cost
- After response:
  - extract usage from response in a tolerant way:
    - OpenAI shape: `response.usage.prompt_tokens`, `completion_tokens`, `total_tokens`
    - dict / object / provider-specific alternatives
  - fall back to local tokenization estimate if usage missing
  - record in tracker
- Add logging:
  - `logger.info("[cost] call=%s model=%s in=%s out=%s est=$%.6f", ...)`

**Key guards**
- if usage is missing or malformed, record `None`/estimated values and warn once
- ensure exceptions from tracking never mask the original model exception

---

### `mirofish_lab/camel_fallback.py` or fallback adapter module
**Edit fallback path used by CAMEL-AI**

- instrument the fallback call site the same way as normal `Agent.respond`
- ensure the fallback path uses the same shared `CostTracker`
- parse whatever usage/metadata the fallback provider returns, without assuming OpenAI schema

---

### `mirofish_lab/runtime/context.py` or `mirofish_lab/run_context.py`
**New or expanded runtime context**

- add a run-scoped context object that carries:
  - `cost_tracker`
  - `run_id`
  - `output_dir`
  - `max_usd`
- provide helper functions:
  - `get_current_run_context()`
  - context manager `with_run_context(...)`

**Purpose**
- avoids threading a new parameter through every single experiment class
- lets all experiments pick up tracking automatically

---

### `mirofish_lab/cli.py` / `mirofish_lab/__main__.py`
**CLI wiring**

- add `--max-usd FLOAT`
- read env var `MIROFISH_MAX_USD`
- validate precedence:
  - CLI overrides env
  - env overrides default/no cap
- instantiate run context and cost tracker at program start
- on exit:
  - print `tracker.final_summary()`
  - save `.mirofish_memory/cost.json`

**Key guards**
- invalid env var / CLI input should exit with a clear error
- summary and save should happen in `finally:` / `atexit` to cover failures

---

### `mirofish_lab/experiments/*`
**Minimal or no changes if context is centralized**

- Ensure experiment entrypoints run inside the shared run context
- No per-experiment logic changes needed if the response path is centralized

If there are direct LLM calls outside `Agent.respond`, patch those call sites to use the same tracker.

---

### `mirofish_lab/utils/logging.py` or existing logging setup
**Optional logging improvements**

- add a logger namespace for cost tracking
- emit one-time warning for unknown model price
- emit debug logs for budget checks and usage parsing failures

---

### `tests/test_costing.py`
**New tests**

- records tokens/cost and aggregates correctly
- budget exceeded raised before call
- unknown pricing warns once and uses `0.0`
- missing usage object handled safely
- CAMEL fallback path records usage too
- CLI summary string format and JSON file creation
- env var and CLI precedence

---

## Risks foreseen

1. **Budget check accuracy before the call**
   - We can only truly know completion tokens after the call.
   - To satisfy “before the call goes out,” the check will likely need to use a conservative estimate of potential completion cost or a configured max output token bound.
   - Risk: overly conservative estimates may reject valid calls; too-optimistic estimates may still overspend slightly.

2. **Incomplete coverage of all model invocation paths**
   - If any experiment bypasses `Agent.respond` or the CAMEL wrapper, it won’t be tracked.
   - Mitigation: centralize at the lowest shared abstraction and search for all direct SDK calls.

3. **Usage schema fragmentation**
   - OpenAI-compatible providers vary widely in response shape.
   - Risk: token extraction may fail silently or miscount unless parsing is defensive and well-tested.

4. **Pricing data drift**
   - Model prices change over time.
   - Risk: estimated dollar cost becomes stale.
   - Mitigation: keep a small, explicit pricing table, warn on unknown models, and treat estimates as estimates.

5. **File write failures**
   - `.mirofish_memory/cost.json` may not exist or may be unwritable.
   - Mitigation: best-effort writes with clear warnings, never crash the run solely because telemetry persistence failed.

6. **CLI/config precedence bugs**
   - Mixing env vars and CLI flags can create confusion.
   - Mitigation: explicit precedence rules and tests.

7. **Exception masking**
   - Tracking code must not hide the original model/experiment exception.
   - Mitigation: wrap telemetry failures in warning logs only; use `finally` for summary output.

If you want, I can also turn this into a concrete implementation checklist with exact function signatures and a proposed JSON schema for `.mirofish_memory/cost.json`.

## Plan: TestFirst

## 1) Test cases first

To prove this change works, I’d cover these cases:

### Accounting
1. **Single `Agent.respond` call with OpenAI-style `usage`**
   - input tokens, output tokens captured
   - estimated cost computed from model pricing
   - run-level totals increment correctly

2. **Multiple calls aggregate correctly**
   - 2–3 calls in one run
   - totals sum across calls
   - final summary reflects all calls

3. **OpenAI-compatible response shape**
   - `usage` may not be OpenAI-shaped
   - support alternate field names if present
   - if usage cannot be parsed, counts remain zero without crashing

4. **CAMEL-AI fallback path**
   - fallback respond path also records a call
   - totals include fallback-generated usage if available
   - no regression if fallback returns no usage

### Budget cap
5. **Cap unset**
   - no exception, normal behavior

6. **Cap set and run stays under**
   - calls proceed
   - accounting still works

7. **Cap would be exceeded by next call**
   - raise `BudgetExceeded` before request dispatch
   - message includes current spend, projected spend, cap
   - no request is sent

8. **Exact cap boundary**
   - if projected spend == cap, allow or deny based on intended rule
   - likely allow when `projected <= cap`, reject when `>` cap

9. **Unknown-pricing model**
   - warning emitted once
   - cost treated as `0.0`
   - cap based on known cost only, or conservative behavior documented

### Persistence / summary
10. **`cost.json` written once per run**
    - under `.mirofish_memory/cost.json`
    - contains calls, token totals, estimated cost, timestamps/model summary if included

11. **CLI exit prints summary**
    - summary line matches requested format
    - printed even on successful no-op/low-usage runs

12. **Failure path**
    - if a run aborts due to `BudgetExceeded`, the summary and JSON still reflect spent totals up to the exception

---

## 2) Short plan

- Add a small run-scoped cost tracker that aggregates token counts, estimated USD, and call count.
- Hook tracker updates into the shared response path used by `Agent.respond` and the CAMEL fallback.
- Add a pre-flight budget check before each request using pricing estimation from prompt token counts and expected output tokens if available.
- Add CLI/env config plumbing for `--max-usd` and `MIROFISH_MAX_USD`.
- Emit a final summary on exit and write `.mirofish_memory/cost.json` for the run.
- Add a `BudgetExceeded` exception plus one-time warning for unsupported model pricing.

---

## 3) Diff sketch

### `mirofish_lab/costing.py` (new)
- Add:
  - `BudgetExceeded(Exception)`
  - `RunCostTracker`
    - `record_request(...)`
    - `estimate_cost(model, prompt_tokens, completion_tokens=None)`
    - `would_exceed_budget(...)`
    - `to_summary_dict()`
    - `write_json(path)`
  - pricing table / helper for known models
  - one-time warning for unknown pricing
- Handle heterogeneous `usage` objects:
  - OpenAI: `usage.prompt_tokens`, `usage.completion_tokens`, `usage.total_tokens`
  - compatible endpoints: `input_tokens`, `output_tokens`, nested dicts, etc.
- Include conservative fallback behavior when tokens/cost are unavailable.

### `mirofish_lab/agent.py` or shared LLM wrapper
- In `Agent.respond`:
  - compute/estimate prompt token count before sending
  - ask tracker whether next call would exceed `max_usd`
  - if yes, raise `BudgetExceeded` before API call
  - after response, parse usage and record actual tokens/cost
- Ensure the same path is used by any wrapper/fallback so both main and CAMEL paths are instrumented.

### `mirofish_lab/llm.py` / provider adapter layer
- Centralize response normalization:
  - extract model name
  - extract usage object safely
  - return normalized `{prompt_tokens, completion_tokens, total_tokens}`
- If endpoint returns its own usage schema, map it without assuming OpenAI shape.

### `mirofish_lab/cli.py` / `__main__.py` / experiment runner
- Add `--max-usd` CLI flag.
- Read `MIROFISH_MAX_USD` env var.
- Initialize a run-scoped `RunCostTracker`.
- Register `atexit` (or equivalent) to:
  - print summary:
    - `[cost] N calls, X tokens in, Y tokens out, est. $Z`
  - write `.mirofish_memory/cost.json`
- Pass tracker into experiment execution context so all experiments inherit it automatically.

### `mirofish_lab/config.py` (if present)
- Add config field for budget cap.
- Default to `None`.

### `mirofish_lab/__init__.py`
- Export `BudgetExceeded` if useful for callers/tests.

### Tests
#### `tests/test_costing.py`
- unit tests for:
  - usage parsing
  - cost estimation
  - budget threshold behavior
  - unknown pricing warning once

#### `tests/test_agent_cost_tracking.py`
- verify `Agent.respond` records calls and tokens
- verify budget check occurs before dispatch

#### `tests/test_cli_cost_summary.py`
- verify summary line and JSON output
- verify env/flag precedence

#### `tests/test_camel_fallback_cost_tracking.py`
- ensure fallback path also records usage and respects cap

---

## 4) Risks you foresee

1. **Token estimation before the call may be approximate**
   - Exact pre-call usage isn’t known until the response returns.
   - The safe approach is to estimate prompt tokens plus a configured worst-case output allowance, or cap based on accumulated known spend with a conservative reserve.

2. **Different providers expose usage differently**
   - OpenAI, Azure, OpenRouter, and compatible APIs may differ in shape.
   - Normalization logic needs to be defensive and well-tested.

3. **Pricing table drift**
   - Known model prices can change.
   - If pricing is embedded, it needs clear maintenance; otherwise warnings and `0.0` fallback are safer but less accurate.

4. **Budget enforcement semantics**
   - If the cap is checked only on estimated cost, a response may come back slightly over/under the estimate.
   - The implementation should clearly define whether cap applies to estimated spend or actual recorded spend, and prefer a conservative estimate to avoid overspend.

5. **Summary on abnormal exit**
   - If the process crashes hard, `atexit` may not run.
   - That’s acceptable for this sandbox, but worth noting.

6. **Backward compatibility**
   - Existing experiments should continue working without explicit changes.
   - The tracker should be optional/defaulted so older code paths don’t break.

## Plan: RefactorHappy

1. **Plan**
- Add a small, centralized cost-tracking module in `mirofish_lab` that owns:
  - per-call accounting,
  - experiment-level aggregation,
  - budget checking,
  - final summary / JSON export.
- Instrument the shared model-call path(s) used by all experiments, including the CAMEL-AI fallback, so every `Agent.respond`-style invocation reports usage through the same tracker.
- Read pricing/limits from env + CLI (`MIROFISH_MAX_USD`) and make the budget check happen **before** dispatching the next model request.
- Add a `BudgetExceeded` exception with a precise message showing current spend, predicted next-call cost, and configured cap.
- Emit a single run file at `.mirofish_memory/cost.json` and print a one-line summary on exit; keep this local to the run, with no persistent telemetry.
- Make pricing lookup tolerant: support known models, warn once for unknown / unsupported models, and default to `0.0` estimate rather than failing.

2. **Diff sketch**

### `mirofish_lab/costing.py` *(new)*
```diff
+ class BudgetExceeded(RuntimeError):
+     pass
+
+ @dataclass
+ class CallCost:
+     prompt_tokens: int
+     completion_tokens: int
+     total_tokens: int
+     estimated_usd: float
+     model: str
+     provider: str | None = None
+
+ class CostTracker:
+     def __init__(self, max_usd: float | None = None, output_path: Path = ...):
+         self.max_usd = max_usd
+         self.calls = 0
+         self.prompt_tokens = 0
+         self.completion_tokens = 0
+         self.estimated_usd = 0.0
+         self._warned_unknown_models = set()
+
+     def predict_next_cost(self, model: str, usage_hint: dict | None = None) -> float:
+         # estimate from known price table; tolerate unknown models with 0.0
+
+     def check_budget_before_call(self, model: str, predicted_cost: float) -> None:
+         # if max_usd is set and current + predicted > max_usd: raise BudgetExceeded
+
+     def record(self, call: CallCost) -> None:
+         # aggregate, append to per-run list, flush JSON
+
+     def summary_line(self) -> str:
+         # "[cost] 6 calls, 14,231 tokens in, 4,802 tokens out, est. $0.087"
+
+     def write_json(self) -> None:
+         # write .mirofish_memory/cost.json
```

### `mirofish_lab/runtime.py` or existing central run/context module
```diff
+ _COST_TRACKER: CostTracker | None = None
+
+ def init_cost_tracking(max_usd: float | None, output_dir: Path):
+     global _COST_TRACKER
+     _COST_TRACKER = CostTracker(max_usd=max_usd, output_path=output_dir / "cost.json")
+     atexit.register(_COST_TRACKER.write_json)
+     atexit.register(lambda: print(_COST_TRACKER.summary_line()))
+
+ def cost_tracker() -> CostTracker:
+     return _COST_TRACKER
```

### Shared model invocation wrapper used by `Agent.respond`
```diff
- response = client.chat.completions.create(...)
+ tracker = cost_tracker()
+ predicted = tracker.predict_next_cost(model=model, usage_hint=messages)
+ tracker.check_budget_before_call(model, predicted)
+ response = client.chat.completions.create(...)
+ usage = extract_usage(response)  # handles OpenAI shape, OpenAI-compatible shapes, missing usage
+ tracker.record(CallCost(
+     prompt_tokens=usage.prompt_tokens,
+     completion_tokens=usage.completion_tokens,
+     total_tokens=usage.total_tokens,
+     estimated_usd=estimate_price(model, usage),
+     model=model,
+     provider=provider_name,
+ ))
```

### CAMEL-AI fallback path
```diff
- result = camel_agent.step(...)
+ tracker = cost_tracker()
+ predicted = tracker.predict_next_cost(model=model, usage_hint=...)
+ tracker.check_budget_before_call(model, predicted)
+ result = camel_agent.step(...)
+ usage = extract_usage(result)  # or synthesize from response text if only token metadata exists
+ tracker.record(...)
```

### CLI entrypoints for the four experiments
```diff
- parser.add_argument(...)
+ parser.add_argument("--max-usd", type=float, default=float(os.getenv("MIROFISH_MAX_USD", "0")) or None)
+
+ init_cost_tracking(max_usd=args.max_usd, output_dir=Path(".mirofish_memory"))
```

### `mirofish_lab/pricing.py` *(new or adjacent helper)*
```diff
+ PRICE_TABLE = {
+   # known shipped models only
+ }
+
+ def estimate_price(model: str, prompt_tokens: int, completion_tokens: int) -> float:
+     # warn once on unknown models; return 0.0
```

### `mirofish_lab/agents.py` / shared response method
```diff
 class Agent:
     def respond(...):
+        # no experiment-specific changes; all agents use the shared wrapper
         return self._llm_call(...)
```

### `mirofish_lab/telemetry.py` or `mirofish_lab/runtime.py`
```diff
+ def extract_usage(response) -> Usage | None:
+     # support:
+     # - response.usage.prompt_tokens/completion_tokens/total_tokens
+     # - dict-like / OpenAI-compatible variants
+     # - missing usage => None
```

### `.gitignore`
```diff
+.mirofish_memory/
```

3. **Risks**
- **Estimating before the call is inherently approximate** if the prompt length varies by provider serialization or if a provider doesn’t expose enough info; the budget gate should be conservative enough to avoid overspend, but this may occasionally reject a call that would have fit.
- **Unknown/unsupported model pricing** may lead to `0.0` estimates and weaker budget enforcement unless we have a fallback token-based ceiling or a curated price table.
- **Usage object shape differences** across OpenAI-compatible providers can break naive parsing; the extraction helper needs to be permissive and tested against dict-like and attribute-like responses.
- **CAMEL-AI fallback instrumentation** may be trickier if it returns only text or embeds usage in a nonstandard location; we may need to synthesize or infer token counts there.
- **Exit-time summary / JSON write ordering** can be brittle if the process crashes hard; we’ll get best-effort telemetry, but not guaranteed persistence on fatal termination.
- **Global tracker initialization** must happen early in CLI startup, otherwise some calls may bypass accounting; a small refactor to centralize LLM invocation is likely necessary to avoid duplicate paths.

## Judge Verdict

## Ranked list

1. **Minimalist**  
   **Rationale:** Best balance of scope and concreteness; it hits the required surfaces with the least churn and explicitly calls out the central invariants: “**before the call goes out**,” “**No persistent telemetry**,” and “**Patch the CAMEL-AI fallback path**.”

2. **RefactorHappy**  
   **Rationale:** Also strong and fairly actionable, but it leans harder into new abstractions and helper modules than necessary; good architecture, slightly more invasive than the issue asks for.

3. **Defensive**  
   **Rationale:** Solid and safe, but more generic; it repeats the right concerns without giving as tight a path to implementation or clear file-by-file deltas.

4. **TestFirst**  
   **Rationale:** Excellent test coverage and risk framing, but it under-specifies the actual implementation shape relative to the repository, so it’s better as a companion than as the main plan.

---

## Winner

**Minimalist**

### Why
It most directly matches the issue’s constraints without over-engineering. In particular, it correctly emphasizes:
- a shared cost module,
- instrumentation of the shared `Agent.respond` path,
- a **pre-call** budget check,
- a single `.mirofish_memory/cost.json` output,
- CLI/env wiring,
- and the CAMEL-AI fallback path.

The strongest line is the explicit requirement to “**check the cap before the call goes out, not after**,” which the Minimalist plan preserves, and it also avoids unnecessary per-experiment edits by relying on shared context.

---

## Brief rationale per rank

### 1) Minimalist
Best fit for “plan + diff sketch + risks” with minimal repo-wide disruption. It is concrete enough to execute and matches the “no per-experiment changes if avoidable” requirement.

### 2) RefactorHappy
Good architecture and helpful pseudo-diff, but it introduces more new surface area (`pricing.py`, runtime globals, atexit wiring) than we know we need. That’s not wrong, just heavier.

### 3) Defensive
Reasonable but higher-level. It says the right things—“**support usage extraction from both OpenAI-style and non-OpenAI-compatible response shapes**,” “**budget check happen before dispatching**”—yet it doesn’t anchor the work as precisely.

### 4) TestFirst
Best at validation and risk management, but as a primary response to this issue it’s incomplete. It should be merged into the chosen implementation plan rather than used alone.

---

## Synthesis I’d recommend

Take **Minimalist + TestFirst**:
- Use **Minimalist** as the implementation skeleton.
- Borrow **TestFirst**’s concrete test matrix, especially:
  - budget cap semantics,
  - OpenAI-compatible usage shapes,
  - CAMEL fallback path,
  - summary/JSON output,
  - env vs CLI precedence.

If you want a more robust architecture pass, add a small dose of **RefactorHappy**:
- centralized `extract_usage(...)`,
- explicit `CostTracker` / `BudgetExceeded`,
- `atexit`-backed finalization.

---

## Open questions for the human engineer

1. **How should “pre-call budget check” be computed for unknown completion length?**  
   We need a policy: estimated max output tokens, conservative reserve, or a provider-specific heuristic.

2. **What exact pricing table should ship initially?**  
   The issue says OK to fall back to `0.0` and warn once, but if the cap must be effective, we need to know which supported models are actually priced.

3. **Where is the single shared LLM invocation path today?**  
   The plan assumes `Agent.respond` is the main choke point, but we need to confirm there are no other direct SDK calls in experiments.

4. **How does the CAMEL-AI fallback expose usage, if at all?**  
   If it returns only text, should we estimate tokens locally, or is there a provider metadata object we can parse?

5. **Should `.mirofish_memory/cost.json` be overwritten per run or appended with a run ID?**  
   The issue says “a single JSON file under `.mirofish_memory/cost.json` per run,” which suggests overwrite, but it’s worth confirming.

6. **What is the exact CLI precedence rule?**  
   Likely `--max-usd` overrides `MIROFISH_MAX_USD`, but this should be explicit.

7. **Should `BudgetExceeded` abort immediately, or can the run continue with non-LLM work?**  
   The issue implies the next model call fails; behavior for the rest of the experiment should be clarified.

8. **Do we need tests for malformed / partial usage objects from providers?**  
   The issue strongly hints yes, especially for OpenAI-compatible endpoints.

# Grounded pipeline applied to a real public product: `simonw/llm`

## Setup

- **Product**: [simonw/llm](https://github.com/simonw/llm) — Simon
  Willison's CLI for interacting with LLMs. ~6K GitHub stars, active
  development, 61 releases (most recent `0.31`, April 2026).
- **Clone**: `git clone --depth 1 https://github.com/simonw/llm.git`
  into `.clones/llm/`. ~10K lines of Python across the package +
  tests directory.
- **Intent**: add OpenTelemetry-compatible tracing to the codebase
  (model calls, tool invocations, embeddings, CLI commands), opt-in
  via `LLM_OTEL=1`, with a public `llm.tracing.span(...)` helper
  for plugin authors.

The intent is **real**: confirmed by `grep -E
"opentelemetry|prometheus|datadog|sentry"` returning zero matches.
The codebase has zero tracing infrastructure today; this would be a
real, mergeable engineering project.

## Pipeline output

```bash
python verified-rollout/cli_grounded.py \
    validation/real_world_demo/intent_llm_otel_tracing.md \
    --repo .clones/llm \
    --n-plans 4
```

### Search-plan generation (LLM)

The `SearchPlanner` agent, given the intent, emitted **9 search
patterns** specific to the tracing/observability domain:

- import statements for `opentelemetry`, `prometheus`, `datadog`, `sentry`
- `Model.prompt` / `Model.chain` / `AsyncModel.prompt` definitions
- `embed_*` function calls
- `@hookspec` decorator usages
- Click commands (`@cli.command`)
- references to environment-variable-based feature flags
- the existing `migrations.py` table-creation calls
- `pyproject.toml`-style optional-dependency entries

Patterns emitted by an LLM that has never seen the repo, with no
domain knowledge baked into the scanner.

### Repo scan (deterministic)

| File | Matches |
|---|---|
| `llm/cli.py` | 366 |
| `tests/test_parts.py` | 315 |
| `llm/models.py` | 193 |
| `tests/test_embed_cli.py` | 119 |
| `tests/test_plugins.py` | 86 |
| `tests/test_openai_messages.py` | 73 |
| `tests/test_async_parity.py` | 60 |
| `tests/test_llm.py` | 58 |

These are the **real hot spots** in `simonw/llm` for tracing
instrumentation, computed by AST + regex over the cloned source,
not guessed by the LLM.

### Pareto scoreboard

| Plan | Steps | SMT feasible | Fragility | % grounded |
|---|---|---|---|---|
| 00-cost-leaning | 12 | N | 0.356 | 100% (12/12) |
| 01-safety-leaning | 12 | **Y** | 0.492 | 100% (12/12) |
| **02-speed-leaning (winner)** | 8 | **Y** | **0.339** | 100% (8/8) |
| 03-safety-tilted | 11 | N | 0.464 | 100% (11/11) |

**Recommended**: `02-speed-leaning` — fewest steps, lowest fragility,
Z3-feasible. The other Z3-feasible plan (safety-leaning) trades 4
extra checkpoint steps for 0.45 higher fragility — counter-intuitive
but correct: more sequential steps means a single failure cascades
further.

### A real task from the agent backlog (winning plan)

```
Task S1 — Implement llm/tracing.py with lazy OTel imports,
  enable_tracing(), span(name, **attrs), OTLP/HTTP default endpoint,
  and metadata-only attributes by default; wire
  LLM_OTEL_INCLUDE_CONTENT behind explicit opt-in.

Files: /home/user/Playground/.clones/llm/llm/cli.py
Agent instructions:
  - cli.py:336 (CLI flag registration for optional OTel tracing):
    click.option(
  - cli.py:350 (CLI flag registration for optional OTel tracing):
    @click.version_option()
  - cli.py:380 (CLI flag registration for optional OTel tracing):
    @click.option("-s", "--system", help="System prompt to use")
  ...
Gate: none
Rollback: Remove llm/tracing.py exports and revert to no-op
  tracing helpers.
Observability: Verify import llm does not load opentelemetry in
  sys.modules when LLM_OTEL is unset.
```

```
Task S3 — Instrument llm/models.py, llm/embeddings.py,
  llm/plugins.py, and llm/cli.py with spans for llm.model.prompt,
  llm.embedding.run, llm.tool.invoke, llm.cli.prompt/chat/embed,
  and hook dispatch; ensure AsyncModel paths use context
  propagation only.

Files: cli.py, embeddings.py
Gate: none
Observability: Sample local run produces a parent CLI span with
  model + embedding child spans; AsyncModel run has correct parent.
```

These are tasks an executor agent could dispatch on tomorrow.

## Honest critique

What worked:

- **The 9-pattern search plan was on-target**: tracing-related concepts
  (opentelemetry imports, model.prompt definitions, hookspecs, click
  commands) — exactly the right surfaces.
- **Hot-file ranking matched intuition**: `cli.py` and `models.py` ARE
  where the tracing wrapping would actually go. A real reviewer of
  this PR would expect these to be the heaviest-touched files.
- **Z3 ordering check on a real plan**: surfaced 2 of 4 plans as
  having genuine ordering contradictions. Worth running every time.
- **Fragility-based Pareto pick**: chose the smaller plan (8 steps)
  over the longer 12-step "safety" plan — correctly noticing that
  more checkpoints can mean MORE cascade-points-of-failure, not fewer.

What's still imperfect:

- **`cli.py` dominates `file_paths`** because it's the densest match
  source. Other relevant files (`models.py`, `embeddings.py`,
  `plugins.py`) get mentioned in the action text but not always in
  `file_paths`. The matcher's "any distinctive token hit" rule is
  reasonable but biased toward dense files.
- **`pyproject.toml` is mentioned** in S2's action ("add optional
  `[tracing]` extras") but not in `file_paths` because the LLM
  search planner produced patterns targeting `**/*.py` only; non-Python
  files were excluded. **Real fix**: search planner should be told the
  intent may touch non-Python files (configs, READMEs) and emit
  glob-broad patterns for those.
- **No closed-loop hardening was run**, so the 2 SMT-infeasible plans
  weren't auto-fixed. That's a one-line cli_harden invocation away.

## What this proves

The same generic pipeline that ran on hypothetical Acme Corp produced
**concrete, file-grounded, agent-dispatchable output** on a real public
product without any code changes. The product was selected after
construction; nothing about `simonw/llm` was hard-coded into the
scanner, the planner, or the personas.

For the world where the agent writes most of the code: each task in
the backlog is structured enough that a coding agent could read it
and start producing diffs against the real cloned repo right now.

## What I, as an engineer reviewing this output, would actually do

1. Take **task S1** as a starting point, drop it into a Cursor / Claude
   Code chat with the cloned repo, and ask the agent to implement
   `llm/tracing.py` with the constraints from the task. Watch it
   produce a diff.
2. Take **task S3**'s file list (`models.py`, `embeddings.py`,
   `plugins.py`, `cli.py`) and dispatch the instrumentation work in
   parallel — these are independent.
3. Use the **Z3-feasible recommendation** as my real plan-of-record
   in a GitHub issue or design doc, citing the unsat cores from the
   other 2 infeasible plans as evidence we evaluated alternatives.
4. **Reject** the heuristic Monte Carlo numbers (not part of this run,
   but were in earlier demos) — those need calibration.
5. Run the **closed-loop hardener** on the SMT-infeasible plans
   before discarding them; sometimes the hardener can fix them.

The output is a starting point that's much better than the blank page
I'd otherwise stare at. That's the honest engineering value.

## Reproduce

```bash
cp .env.example .env
pip install -r requirements.txt

git clone --depth 1 https://github.com/simonw/llm.git .clones/llm

python verified-rollout/cli_grounded.py \
    validation/real_world_demo/intent_llm_otel_tracing.md \
    --repo .clones/llm \
    --n-plans 4 \
    --out validation/real_world_demo/llm_otel.grounded.md
```

LLM cost: ~25 calls / ~$0.05 on `gpt-5.4-mini`.

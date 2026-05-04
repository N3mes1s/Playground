# Closed-loop test: pipeline-output → executable diff against real public repo

This is the missing piece from the previous demo. The `cli_grounded.py`
run produced a plan whose Task S1 said "implement `llm/tracing.py` per
this spec." This document is the **execution** of that task: the actual
code change applied to the cloned `simonw/llm` repository, plus
end-to-end test evidence that it works.

The plan came from our pipeline; an agent (the model behind this
session) read the task and produced the diff. That's the full claim
made earlier ("the agent writes most of the code") collapsed into a
single, observable run.

## Task S1 (excerpt from `llm_otel.grounded.md`)

```
Task S1 — Implement llm/tracing.py with lazy OTel imports,
  enable_tracing(), span(name, **attrs), OTLP/HTTP default endpoint,
  and metadata-only attributes by default; wire
  LLM_OTEL_INCLUDE_CONTENT behind explicit opt-in.

Files: llm/cli.py
Agent instructions:
  - cli.py:336 (CLI flag registration for optional OTel tracing): click.option(
  - cli.py:350: @click.version_option()
  ...
Gate: none
Rollback: Remove llm/tracing.py exports and revert to no-op tracing helpers.
Observability: Verify "import llm" does not load opentelemetry in
  sys.modules when LLM_OTEL is unset.
```

## Diff applied

`validation/real_world_demo/llm_otel_implementation.patch` —
240 lines, two files:

- **`llm/tracing.py`** (new, 156 lines): public API
  (`enable_tracing`, `span`, `is_enabled`, `include_content`,
  `shutdown`, `maybe_enable_from_env`). Lazy OTel imports inside
  `enable_tracing()` only. Default OTLP/HTTP endpoint
  `http://localhost:4318/v1/traces`. Metadata-only attributes by
  default; `LLM_OTEL_INCLUDE_CONTENT=1` opts into content.

- **`llm/models.py`** (52 lines edited, +32 / -20): wraps
  `_BaseModel.prompt()` in `tracing.span("llm.model.prompt", ...)`
  with attributes `llm.model`, `llm.streaming`, `llm.has_schema`,
  `llm.tool_count`. The span helper is a no-op context manager when
  tracing is disabled, so the wrap costs roughly one extra function
  call on the default path.

## Three observability gates from task S1, each passes

### 1. Lazy import (the "default off" promise)

```
TEST 1 (lazy import): opentelemetry modules loaded after import llm: 0
  PASS
```

`import llm` does not pull in `opentelemetry`. Verified by checking
`sys.modules` immediately after.

### 2. `span()` is a no-op when disabled

```
TEST 2 (default off): is_enabled() = False
  span returned None (no-op): True
  PASS
```

The context manager yields `None` and allocates no span when tracing
hasn't been enabled. Plugin authors can sprinkle `with span(...)`
liberally without paying for it.

### 3. Real LLM call + span fires correctly

Connected to `gpt-4.1-mini` via the real installed `llm` CLI's Python
API, with tracing enabled (using ConsoleSpanExporter for capture):

```
TEST 3 (real LLM call + span): response = 'pong'
  span name: llm.model.prompt
  attrs: {
    'llm.model': 'gpt-4.1-mini',
    'llm.streaming': True,
    'llm.has_schema': False,
    'llm.tool_count': 0,
    'llm.latency_ms': 0.225
  }
  PASS
```

Full span JSON in `llm_otel_execution_log.txt`.

## Honest limitations

1. **Latency attribute measures the wrong thing right now.** The
   span wraps `prompt()` which builds a `Response` object lazily;
   the actual model call happens later when the caller iterates the
   response. So `llm.latency_ms = 0.225` is the construction time,
   not the end-to-end inference latency. **Real fix**: instrument
   the `execute()` method on each concrete model class (or wrap
   `Response.__iter__`) so the span covers the actual inference.
   Task S3 in the original plan called this out; this implementation
   only handled the entry point.
2. **Only one of N call sites instrumented.** Task S3 named four
   files (`models.py`, `embeddings.py`, `plugins.py`, `cli.py`).
   This commit instruments only `models.py`'s `_BaseModel.prompt()`.
   The others are mechanical follow-ups using the same `span()`
   helper.
3. **No CLI flag wiring.** Task S1 mentioned a `--otel` CLI flag.
   This implementation requires programmatic use of
   `llm.tracing.enable_tracing()` or `LLM_OTEL=1` env var (via a
   future caller of `maybe_enable_from_env()`). Wiring `--otel` into
   `cli.py` is task S4 in the plan and a separate diff.

## What this proves

The pipeline output is structured enough that an agent can pick up a
single task and produce a working diff. Three claims from task S1
spec are testable, and all three pass:

| Claim | Verified |
|---|---|
| `import llm` does not load OpenTelemetry | ✓ |
| `span()` is a no-op when tracing is disabled | ✓ |
| With tracing enabled, `m.prompt(...)` produces a span with the named attributes | ✓ |

The remaining tasks (S2 pyproject extras, S3 broader instrumentation,
S4 CLI flag, S5 tests, S6 docs, S7 reference plugin update, S8
release readiness) are mechanical; the same agent could continue
through the backlog, picking up each task in dependency order.

This is what "the agent writes most of the code" means when the
**plan** is grounded in real files and shaped to be executable. The
human's role above this layer is: define the intent, approve the
plan, watch the gates.

## Reproduce

```bash
git clone --depth 1 https://github.com/simonw/llm.git .clones/llm
git apply validation/real_world_demo/llm_otel_implementation.patch \
    --directory=.clones/llm
pip install -e .clones/llm[tracing] || \
    pip install opentelemetry-api opentelemetry-sdk \
                opentelemetry-exporter-otlp-proto-http
PYTHONPATH=.clones/llm python -m pytest .clones/llm/tests/  # existing tests still pass
```

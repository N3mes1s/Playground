# Add OpenTelemetry-compatible tracing to `simonw/llm`

## What

`simonw/llm` (the CLI tool for interacting with LLMs) currently has no
observability layer beyond `print` statements and SQLite log writes.
We are adding **OpenTelemetry**-compatible tracing so every model call,
tool invocation, prompt/response cycle, and embedding lookup is
captured as a span, with optional export to OTLP endpoints.

Concretely:

- Wrap each model `prompt()` / `chain()` call in a span named
  `llm.model.prompt` with attributes `model`, `provider`,
  `prompt_tokens`, `completion_tokens`, `latency_ms`, `tool_calls`.
- Wrap each tool invocation in `llm.tool.invoke` with `tool_name`,
  `tool_call_id`, `latency_ms`, `error_class`.
- Wrap each embedding call in `llm.embedding.run`.
- Make tracing **opt-in** via env var `LLM_OTEL=1` and CLI flag
  `--otel`. Default off — the CLI's offline-first vibe must not be
  broken.
- When enabled, default to OTLP/HTTP export at
  `http://localhost:4318/v1/traces` (the Jaeger / Tempo / DD-agent
  default). Allow override via `OTEL_EXPORTER_OTLP_ENDPOINT`.
- Plugin authors get a public helper `llm.tracing.span(name, **attrs)`
  context manager so plugins can add their own spans without
  importing OpenTelemetry directly.

## Why

- **SRE / production debugging**: when a tool-calling chain takes 90
  seconds, today's logs say "it took 90 seconds" and not "it took 90
  seconds because the third tool's external API stalled at 87s." A
  span tree fixes that.
- **Cost attribution**: span attributes capturing token counts let
  organisations aggregate spend per model / per user / per task type
  via standard tracing-platform features (Jaeger, Tempo, Datadog
  APM, Honeycomb).
- **Plugin ecosystem**: at least 30 plugins are published; without a
  common tracing surface, each one rolls its own observability or
  has none. Providing a public helper standardises this.

## Scope

- New `llm/tracing.py` module with the public API (`span`,
  `enable_tracing`, internal helpers).
- Wrap the call sites in:
  - `llm/models.py` — every `Model.prompt()` / `Model.chain()` /
    `AsyncModel.prompt()` path.
  - `llm/embeddings.py` — every embedding call.
  - `llm/cli.py` — top-level command spans for `llm prompt`,
    `llm chat`, `llm embed`.
  - `llm/plugins.py` — span around the hook dispatch so plugin
    overhead is visible.
- Wrap tool invocations wherever they are dispatched.
- New optional dependency: `opentelemetry-api`,
  `opentelemetry-sdk`, `opentelemetry-exporter-otlp-proto-http`. Only
  imported lazily when tracing is enabled, so the cold-import cost
  is not paid by users who don't enable it.
- Update `llm/cli.py` to register the `--otel` flag.
- Update `pyproject.toml` to declare the new optional `[tracing]`
  extras group.
- Update docs (README + dedicated `docs/tracing.md`).

## Constraints

- **Backwards compatibility**: existing CLI behaviour and exit codes
  MUST be byte-identical when tracing is disabled (the default).
- **No PII leakage by default**: span attributes capture metadata
  (model, latency, token counts) but NOT prompt or response content.
  Add a separate opt-in `LLM_OTEL_INCLUDE_CONTENT=1` for users who
  want full content in spans.
- **Plugin compatibility**: existing 30+ plugins must continue to
  work without modification. The public helper is additive.
- **Lazy import**: importing `llm` should not import the OTel SDK
  unless tracing is explicitly enabled. Verified by inspecting
  `sys.modules` after `import llm` with `LLM_OTEL` unset.
- **Async support**: `AsyncModel` paths must produce spans correctly
  (using `OpenTelemetry`'s context propagation — no manual span
  parenting).
- **Sampling**: by default sample 100% of spans (since most users will
  be running locally), but document `OTEL_TRACES_SAMPLER=parentbased_traceidratio`
  for high-traffic deployments.

## Out of scope

- Metrics (counters / histograms). Spans only this round.
- Logs in the OTel-logs sense (we keep the SQLite logs).
- Built-in dashboards / saved Datadog views.

## Affected stakeholders

- **Backend / core team**: owns the change.
- **SRE / observability**: defines the span schema and OTLP target.
- **Security**: validates default-off PII leakage policy + content
  opt-in.
- **Plugin authors** (~30 plugins): consume the public tracing helper.
- **CLI users**: experience the new `--otel` flag; must not see
  perf regression when disabled.
- **Product / docs**: announces the feature, migration guide for
  plugin authors, opt-in instructions.

## What success looks like

- `LLM_OTEL=1 llm 'hello'` produces a parent span `llm.cli.prompt`
  with a child span `llm.model.prompt` carrying `model`, `latency_ms`,
  and token-count attributes, exported to OTLP/HTTP at the default
  Jaeger endpoint.
- Default (`LLM_OTEL` unset): zero behavioural change vs current
  behaviour. Cold-import benchmark: `import llm` does not import
  `opentelemetry`.
- One reference plugin (e.g. `llm-anthropic`) updated to use
  `llm.tracing.span(...)` showing the public helper works.
- Documentation page describing how to set up Jaeger / Tempo /
  Honeycomb / Datadog as the OTLP target.

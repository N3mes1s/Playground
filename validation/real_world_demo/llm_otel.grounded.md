# Grounded Rollout — intent_llm_otel_tracing

> Intent: validation/real_world_demo/intent_llm_otel_tracing.md · Repo: /home/user/Playground/.clones/llm · Search patterns: 10 · Files scanned: 79 · Matches: 1806 · Plans generated: 4 · Recommended: 02-speed-leaning · Model: gpt-5.4-mini

_Generated 2026-04-30T03:50:00Z_

## Recommendation

**02-speed-leaning** (smt_feasible=True, fragility=0.339, 8 of 8 steps grounded to real files).

## Codebase findings

## Codebase findings

- Scanned 79 files at `/home/user/Playground/.clones/llm`.
- 1806 total matches across 7 patterns.

**Hot files (most matches):**
- `/home/user/Playground/.clones/llm/llm/cli.py` — 366
- `/home/user/Playground/.clones/llm/tests/test_parts.py` — 315
- `/home/user/Playground/.clones/llm/llm/models.py` — 193
- `/home/user/Playground/.clones/llm/tests/test_embed_cli.py` — 119
- `/home/user/Playground/.clones/llm/tests/test_plugins.py` — 86
- `/home/user/Playground/.clones/llm/tests/test_openai_messages.py` — 73
- `/home/user/Playground/.clones/llm/tests/test_async_parity.py` — 60
- `/home/user/Playground/.clones/llm/tests/test_llm.py` — 58

**Matches by pattern:**

- **CLI flag registration for optional OTel tracing** (170 matches):
    - `/home/user/Playground/.clones/llm/llm/cli.py:350` — @click.version_option()
    - `/home/user/Playground/.clones/llm/llm/cli.py:380` — @click.option("-s", "--system", help="System prompt to use")
    - `/home/user/Playground/.clones/llm/llm/cli.py:381` — @click.option("model_id", "-m", "--model", help="Model to use", envvar="LLM_MODE
    - `/home/user/Playground/.clones/llm/llm/cli.py:382` — @click.option(
    - `/home/user/Playground/.clones/llm/llm/cli.py:388` — @click.option(
    - `/home/user/Playground/.clones/llm/llm/cli.py:395` — @click.option(
    - _... and 164 more._
- **Public tracing helper API in llm.tracing** (1 matches):
    - `/home/user/Playground/.clones/llm/tests/test_utils.py:342` — "<div><p>Test</p><span>Test</span><a>Test</a><b>Test</b><i>Test</i><u>Test</u>",
- **Model prompt or chain call sites to wrap with spans** (235 matches):
    - `/home/user/Playground/.clones/llm/llm/models.py:2397` — def _chain_for_tool_results(prior_response, tool_results, attachments) -> List[A
    - `/home/user/Playground/.clones/llm/llm/models.py:395` — def prompt(self):
    - `/home/user/Playground/.clones/llm/llm/models.py:501` — def _build_full_chain(
    - `/home/user/Playground/.clones/llm/llm/models.py:572` — def prompt(
    - `/home/user/Playground/.clones/llm/llm/models.py:616` — def chain(
    - `/home/user/Playground/.clones/llm/llm/models.py:690` — def chain(
    - _... and 229 more._
- **Async model prompt call sites to wrap with spans** (43 matches):
    - `/home/user/Playground/.clones/llm/llm/models.py:395` — def prompt(self):
    - `/home/user/Playground/.clones/llm/llm/models.py:572` — def prompt(
    - `/home/user/Playground/.clones/llm/llm/models.py:739` — def prompt(
    - `/home/user/Playground/.clones/llm/llm/models.py:2729` — def prompt(
    - `/home/user/Playground/.clones/llm/llm/models.py:2842` — def prompt(
    - `/home/user/Playground/.clones/llm/llm/cli.py:515` — def prompt(
    - _... and 37 more._
- **Embedding execution call sites to wrap with spans** (216 matches):
    - `/home/user/Playground/.clones/llm/llm/embeddings.py:55` — embeddings_migrations.apply(self.db)
    - `/home/user/Playground/.clones/llm/llm/embeddings.py:138` — embedding = self.model().embed(value)
    - `/home/user/Playground/.clones/llm/llm/embeddings.py:167` — self.embed_multi_with_metadata(
    - `/home/user/Playground/.clones/llm/llm/embeddings.py:340` — comparison_vector = self.model().embed(value)
    - `/home/user/Playground/.clones/llm/llm/embeddings.py:93` — self._model = llm.get_embedding_model(self.model_id)
    - `/home/user/Playground/.clones/llm/llm/embeddings.py:212` — self.model().embed_multi(item[1] for item in filtered_batch)
    - _... and 210 more._
- _(truncated; see findings.json for full list)_

## Pareto scoreboard

| Plan | Steps | SMT feasible | Fragility | % grounded |
|---|---|---|---|---|
| 00-cost-leaning | 12 | N | 0.356 | 100% (12/12) |
| 01-safety-leaning | 12 | Y | 0.492 | 100% (12/12) |
| 02-speed-leaning | 8 | Y | 0.339 | 100% (8/8) |
| 03-safety-tilted | 11 | N | 0.464 | 100% (11/11) |

## Plan: 00-cost-leaning

### Plan `00-cost-leaning`

| # | Action | Owner | Files | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Design the tracing schema and implementation in llm/tracing.py: add enable_traci | BackendOwner | `/home/user/Playground/.clones/llm/docs/plugins/llm-markov/llm_markov.py`, `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/tests/test_llm.py` | `approval:Security review` | Remove llm/tracing.py content-attribute emission a |
| S2 | Update pyproject.toml to add the optional [tracing] extras group for opentelemet | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py` | `wait_for:package_release_contains_tracing_extras` | Revert the extras declaration so tracing code neve |
| S3 | Add CLI wiring in llm/cli.py for --otel and keep default command behavior byte-i | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/llm/default_plugins/openai_models.py`, `/home/user/Playground/.clones/llm/llm/hookspecs.py` | `none` | Remove --otel plumbing and tracing initialization  |
| S4 | Instrument llm/models.py prompt/chain/AsyncModel.prompt paths with llm.model.pro | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/tests/test_async.py` | `approval:release-manager` | Disable model-call span wrappers in llm/models.py  |
| S5 | Instrument llm/embeddings.py embedding execution paths with llm.embedding.run sp | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/llm/embeddings.py`, `/home/user/Playground/.clones/llm/tests/test_embed_cli.py` | `approval:Security review` | Remove embedding span emission from llm/embeddings |
| S6 | Wrap plugin hook dispatch in llm/plugins.py with a span so plugin overhead is vi | BackendOwner | `/home/user/Playground/.clones/llm/llm/__init__.py`, `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/tests/test_parts.py` | `none` | Remove hook-dispatch span wrappers from llm/plugin |
| S7 | Instrument tool invocation dispatch sites wherever tools are executed so each ca | BackendOwner | `/home/user/Playground/.clones/llm/tests/test_chat_templates.py`, `/home/user/Playground/.clones/llm/tests/test_embed_cli.py` | `monitor:replication_lag<2s` | Disable tool-invocation span emission and redeploy |
| S8 | Add the public llm.tracing.span(name, **attrs) context manager export and update | BackendOwner | `/home/user/Playground/.clones/llm/llm/__init__.py`, `/home/user/Playground/.clones/llm/tests/test_parts.py`, `/home/user/Playground/.clones/llm/tests/test_utils.py` | `wait_for:reference_plugin_updated_and_released` | Remove helper imports from plugins and redeploy_pr |
| S9 | Add tests for llm/cli.py, llm/models.py, llm/embeddings.py, lazy import behavior | ConsumerSubsystem | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/llm/embeddings.py` | `approval:QA` | Remove tracing test expectations and redeploy_prev |
| S10 | Draft README and docs/tracing.md covering opt-in usage, OTLP/HTTP default endpoi | ProductPM | `/home/user/Playground/.clones/llm/llm/cli.py` | `wait_for:approved customer-facing docs` | Remove tracing docs/flag text from release notes a |
| S11 | Send plugin-author migration notice and support briefing, then publish the refer | ProductPM | `/home/user/Playground/.clones/llm/llm/__init__.py`, `/home/user/Playground/.clones/llm/tests/test_utils.py` | `approval:support lead` | Revert support runbook to pre-tracing state and po |
| S12 | Schedule the release behind opt-in flags only, confirm default-off baseline regr | SRE | `/home/user/Playground/.clones/llm/llm/cli.py` | `window:outside incident-and-freeze` | Set LLM_OTEL=0, stop passing --otel, and redeploy_ |

## Plan: 01-safety-leaning

### Plan `01-safety-leaning`

| # | Action | Owner | Files | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Draft tracing schema and lazy-init design in llm/tracing.py for span names, attr | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py` | `approval:Security review` | Delete llm/tracing.py design changes and revert to |
| S2 | Add pyproject.toml [tracing] optional dependencies for opentelemetry-api, opente | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py` | `wait_for:package_release_contains_tracing_extras` | Remove [tracing] extras and keep tracing module un |
| S3 | Implement llm/tracing.py with enable_tracing(), span(), OTLP/HTTP exporter setup | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py` | `approval:release-manager` | Remove llm/tracing.py OTel initialization and rest |
| S4 | Instrument llm/models.py around Model.prompt(), Model.chain(), AsyncModel.prompt | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/tests/test_tools.py` | `monitor:replication_lag<2s` | Remove model span wrappers and redeploy_previous |
| S5 | Instrument llm/embeddings.py with llm.embedding.run spans around every embedding | BackendOwner | `/home/user/Playground/.clones/llm/llm/default_plugins/openai_models.py`, `/home/user/Playground/.clones/llm/llm/embeddings.py` | `monitor:replication_lag<2s` | Remove embedding span wrappers and redeploy_previo |
| S6 | Wrap llm/plugins.py hook dispatch and tool invocation dispatch sites with llm.to | BackendOwner | `/home/user/Playground/.clones/llm/llm/__init__.py`, `/home/user/Playground/.clones/llm/tests/test_plugins.py` | `approval:release-manager` | Remove plugin/tool dispatch span wrappers and rede |
| S7 | Update llm/cli.py to add --otel, keep default behavior byte-identical when disab | BackendOwner | `/home/user/Playground/.clones/llm/llm/default_plugins/openai_models.py`, `/home/user/Playground/.clones/llm/tests/test_parts.py`, `/home/user/Playground/.clones/llm/tests/test_tools.py` | `monitor:import_or_cli_regression=0` | Disable --otel wiring and restore previous CLI pat |
| S8 | Add tests in tests/test_llm.py, tests/test_async_parity.py, tests/test_embed_cli | ConsumerSubsystem | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/tests/test_async_parity.py`, `/home/user/Playground/.clones/llm/tests/test_embed_cli.py` | `approval:QA` | Remove new tracing expectations from tests and res |
| S9 | Update README and docs/tracing.md with OTLP endpoint defaults, Jaeger/Tempo/Hone | ProductPM | `/home/user/Playground/.clones/llm/llm/cli.py` | `wait_for:approved customer-facing docs` | Remove tracing docs and flag text from release mat |
| S10 | Send plugin-author migration notice and update one reference plugin (e.g. llm-an | ProductPM | `/home/user/Playground/.clones/llm/llm/__init__.py` | `wait_for:plugin-author announcement sent` | Revert plugin change and remove helper usage from  |
| S11 | Release core changes and enable opt-in tracing only after outside-incident/freez | SRE | `/home/user/Playground/.clones/llm/llm/cli.py` | `window:outside-incident-and-freeze` | Set LLM_OTEL=0, stop passing --otel, and redeploy_ |
| S12 | Soak on default OTLP export at http://localhost:4318/v1/traces with 100% samplin | SRE | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/llm/models.py`, `/home/user/Playground/.clones/llm/tests/conftest.py` | `monitor:export_error_rate<0.1% for 24h` | Disable tracing export and revert to no-op helper |

## Plan: 02-speed-leaning

### Plan `02-speed-leaning`

| # | Action | Owner | Files | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Implement llm/tracing.py with lazy OTel imports, enable_tracing(), span(name, ** | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py` | `none` | Remove llm/tracing.py exports and revert to no-op  |
| S2 | Update pyproject.toml to add optional [tracing] extras for opentelemetry-api, op | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py` | `none` | Remove the [tracing] extras group from pyproject.t |
| S3 | Instrument llm/models.py, llm/embeddings.py, llm/plugins.py, and llm/cli.py with | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/llm/embeddings.py` | `none` | Disable tracing wrappers and redeploy_previous. |
| S4 | Add the --otel flag wiring in llm/cli.py and keep default behavior byte-identica | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/llm/default_plugins/openai_models.py`, `/home/user/Playground/.clones/llm/llm/models.py` | `none` | Remove --otel enablement and disable tracing initi |
| S5 | Add tests in tests/test_llm.py, tests/test_async_parity.py, tests/test_embed_cli | ConsumerSubsystem | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/llm/models.py`, `/home/user/Playground/.clones/llm/tests/test_async_parity.py` | `approval:QA` | Remove tracing test expectations and revert the ne |
| S6 | Document the tracing surface in README and docs/tracing.md, including LLM_OTEL,  | ProductPM | `/home/user/Playground/.clones/llm/llm/cli.py` | `wait_for:approved customer-facing docs` | Remove tracing docs and release-note references. |
| S7 | Publish a plugin migration note and update one reference plugin to use llm.traci | ProductPM | `/home/user/Playground/.clones/llm/llm/__init__.py`, `/home/user/Playground/.clones/llm/tests/test_parts.py` | `wait_for:plugin-author announcement sent` | Undo the reference plugin change and keep the help |
| S8 | Run release readiness checks for default-off behavior, export health, and no imp | SRE | `/home/user/Playground/.clones/llm/llm/cli.py` | `monitor:export_error_rate<0.1% for 24h` | Disable tracing export and revert to the no-op hel |

## Agent backlog (winning plan)

### Agent backlog (plan: `02-speed-leaning`)

#### Task S1 — Implement llm/tracing.py with lazy OTel imports, enable_tracing(), span(name, **attrs), OTLP/HTTP default endpoint, and metadata-only attributes by default; wire LLM_OTEL_INCLUDE_CONTENT behind explicit opt-in.

**Files**: `/home/user/Playground/.clones/llm/llm/cli.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/.clones/llm/llm/cli.py.
  - `/home/user/Playground/.clones/llm/llm/cli.py:336` (CLI flag registration for optional OTel tracing): click.option(
  - `/home/user/Playground/.clones/llm/llm/cli.py:350` (CLI flag registration for optional OTel tracing): @click.version_option()
  - `/home/user/Playground/.clones/llm/llm/cli.py:380` (CLI flag registration for optional OTel tracing): @click.option("-s", "--system", help="System prompt to use")
  - `/home/user/Playground/.clones/llm/llm/cli.py:381` (CLI flag registration for optional OTel tracing): @click.option("model_id", "-m", "--model", help="Model to use", envvar="LLM_MODEL")
  - `/home/user/Playground/.clones/llm/llm/cli.py:382` (CLI flag registration for optional OTel tracing): @click.option(
```

**Gate**: `none`
**Rollback**: Remove llm/tracing.py exports and revert to no-op tracing helpers.
**Observability**: Verify import llm does not load opentelemetry in sys.modules when LLM_OTEL is unset.

#### Task S2 — Update pyproject.toml to add optional [tracing] extras for opentelemetry-api, opentelemetry-sdk, and opentelemetry-exporter-otlp-proto-http.

**Files**: `/home/user/Playground/.clones/llm/llm/cli.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/.clones/llm/llm/cli.py.
  - `/home/user/Playground/.clones/llm/llm/cli.py:336` (CLI flag registration for optional OTel tracing): click.option(
  - `/home/user/Playground/.clones/llm/llm/cli.py:350` (CLI flag registration for optional OTel tracing): @click.version_option()
  - `/home/user/Playground/.clones/llm/llm/cli.py:380` (CLI flag registration for optional OTel tracing): @click.option("-s", "--system", help="System prompt to use")
  - `/home/user/Playground/.clones/llm/llm/cli.py:381` (CLI flag registration for optional OTel tracing): @click.option("model_id", "-m", "--model", help="Model to use", envvar="LLM_MODEL")
  - `/home/user/Playground/.clones/llm/llm/cli.py:382` (CLI flag registration for optional OTel tracing): @click.option(
```

**Gate**: `none`
**Rollback**: Remove the [tracing] extras group from pyproject.toml.
**Observability**: Confirm package metadata exposes the tracing extra without changing default install dependencies.

#### Task S3 — Instrument llm/models.py, llm/embeddings.py, llm/plugins.py, and llm/cli.py with spans for llm.model.prompt, llm.embedding.run, llm.tool.invoke, llm.cli.prompt/chat/embed, and hook dispatch; ensure AsyncModel paths use context propagation only.

**Files**: `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/llm/embeddings.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/.clones/llm/llm/cli.py, /home/user/Playground/.clones/llm/llm/embeddings.py.
  - `/home/user/Playground/.clones/llm/llm/cli.py:3189` (CLI top-level commands for prompt, chat, and embed): embedding = collection_obj.embed(id, content, metadata=metadata, store=store)
  - `/home/user/Playground/.clones/llm/llm/cli.py:3191` (CLI top-level commands for prompt, chat, and embed): embedding = model_obj.embed(content)
  - `/home/user/Playground/.clones/llm/llm/embeddings.py:138` (CLI top-level commands for prompt, chat, and embed): embedding = self.model().embed(value)
  - `/home/user/Playground/.clones/llm/llm/cli.py:3109` (CLI top-level commands for prompt, chat, and embed): help="Content to embed",
  - `/home/user/Playground/.clones/llm/llm/cli.py:3295` (CLI top-level commands for prompt, chat, and embed): llm embed-multi docs --attach blog blog.db --sql "SELECT id, content FROM blog.posts"
```

**Gate**: `none`
**Rollback**: Disable tracing wrappers and redeploy_previous.
**Observability**: Watch span trees for parent/child structure, latency_ms, token counts, tool_calls, and error_class without prompt content.
**Depends on**: S1

#### Task S4 — Add the --otel flag wiring in llm/cli.py and keep default behavior byte-identical when LLM_OTEL is unset; preserve offline-first startup and exit codes.

**Files**: `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/llm/default_plugins/openai_models.py`, `/home/user/Playground/.clones/llm/llm/models.py`, `/home/user/Playground/.clones/llm/tests/conftest.py`, `/home/user/Playground/.clones/llm/tests/test_chat.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/.clones/llm/llm/cli.py, /home/user/Playground/.clones/llm/llm/default_plugins/openai_models.py, /home/user/Playground/.clones/llm/llm/models.py, /home/user/Playground/.clones/llm/tests/conftest.py, /home/user/Playground/.clones/llm/tests/test_chat.py.
  - `/home/user/Playground/.clones/llm/llm/cli.py:1277` (CLI top-level commands for prompt, chat, and embed): # System prompt and system fragments only sent for the first message
  - `/home/user/Playground/.clones/llm/llm/default_plugins/openai_models.py:892` (CLI top-level commands for prompt, chat, and embed): "json_schema": {"name": "output", "schema": prompt.schema},
  - `/home/user/Playground/.clones/llm/llm/models.py:512` (CLI top-level commands for prompt, chat, and embed): first, or synthesized from prompt/attachments/tool_results).
  - `/home/user/Playground/.clones/llm/llm/models.py:637` (CLI top-level commands for prompt, chat, and embed): # response.prompt.messages is authoritative for the first turn
  - `/home/user/Playground/.clones/llm/llm/models.py:1653` (CLI top-level commands for prompt, chat, and embed): (``response.prompt.messages``), the structured assistant output
```

**Gate**: `none`
**Rollback**: Remove --otel enablement and disable tracing initialization.
**Observability**: Compare prompt/chat/embed output and exit codes with tracing disabled.
**Depends on**: S1, S3

#### Task S5 — Add tests in tests/test_llm.py, tests/test_async_parity.py, tests/test_embed_cli.py, tests/test_plugins.py, and targeted CLI/import tests for --otel, lazy import, default-off parity, async propagation, and content opt-in behavior.

**Files**: `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/llm/models.py`, `/home/user/Playground/.clones/llm/tests/test_async_parity.py`, `/home/user/Playground/.clones/llm/tests/test_embed_cli.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/.clones/llm/llm/cli.py, /home/user/Playground/.clones/llm/llm/models.py, /home/user/Playground/.clones/llm/tests/test_async_parity.py, /home/user/Playground/.clones/llm/tests/test_embed_cli.py.
  - `/home/user/Playground/.clones/llm/llm/cli.py:505` (CLI flag registration for optional OTel tracing): @click.option("async_", "--async", is_flag=True, help="Run prompt asynchronously")
  - `/home/user/Playground/.clones/llm/llm/cli.py:2280` (CLI flag registration for optional OTel tracing): @click.option("async_", "--async", is_flag=True, help="List async models")
  - `/home/user/Playground/.clones/llm/llm/cli.py:3436` (CLI flag registration for optional OTel tracing): @click.option("-c", "--content", help="Content to embed for comparison")
  - `/home/user/Playground/.clones/llm/llm/models.py:636` (CLI top-level commands for prompt, chat, and embed): # Parity with Conversation.prompt: pre-bake the full chain so
  - `/home/user/Playground/.clones/llm/tests/test_async_parity.py:60` (CLI top-level commands for prompt, chat, and embed): # prompt.messages (the chain that was sent) preserved
```

**Gate**: `approval:QA`
**Rollback**: Remove tracing test expectations and revert the new test cases.
**Observability**: Validate sys.modules stays free of opentelemetry after import llm and that async spans appear in the expected parent chain.
**Depends on**: S1, S3, S4

#### Task S6 — Document the tracing surface in README and docs/tracing.md, including LLM_OTEL, --otel, OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_TRACES_SAMPLER guidance, and default-off/privacy behavior.

**Files**: `/home/user/Playground/.clones/llm/llm/cli.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/.clones/llm/llm/cli.py.
  - `/home/user/Playground/.clones/llm/llm/cli.py:3436` (CLI flag registration for optional OTel tracing): @click.option("-c", "--content", help="Content to embed for comparison")
  - `/home/user/Playground/.clones/llm/llm/cli.py:336` (CLI flag registration for optional OTel tracing): click.option(
  - `/home/user/Playground/.clones/llm/llm/cli.py:350` (CLI flag registration for optional OTel tracing): @click.version_option()
  - `/home/user/Playground/.clones/llm/llm/cli.py:380` (CLI flag registration for optional OTel tracing): @click.option("-s", "--system", help="System prompt to use")
  - `/home/user/Playground/.clones/llm/llm/cli.py:381` (CLI flag registration for optional OTel tracing): @click.option("model_id", "-m", "--model", help="Model to use", envvar="LLM_MODEL")
```

**Gate**: `wait_for:approved customer-facing docs`
**Rollback**: Remove tracing docs and release-note references.
**Observability**: Check docs cover Jaeger, Tempo, Honeycomb, and Datadog OTLP/HTTP setup plus opt-in content guidance.
**Depends on**: S1, S4

#### Task S7 — Publish a plugin migration note and update one reference plugin to use llm.tracing.span(...) without importing OpenTelemetry directly.

**Files**: `/home/user/Playground/.clones/llm/llm/__init__.py`, `/home/user/Playground/.clones/llm/tests/test_parts.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/.clones/llm/llm/__init__.py, /home/user/Playground/.clones/llm/tests/test_parts.py.
  - `/home/user/Playground/.clones/llm/tests/test_parts.py:279` (Plugin hook dispatch that should be span-wrapped): # Backward compat for plain-str plugins: iterating a Response still
  - `/home/user/Playground/.clones/llm/llm/__init__.py:39` (Plugin hook dispatch that should be span-wrapped): from .plugins import pm, load_plugins
  - `/home/user/Playground/.clones/llm/llm/__init__.py:88` (Plugin hook dispatch that should be span-wrapped): plugins = []
  - `/home/user/Playground/.clones/llm/llm/__init__.py:103` (Plugin hook dispatch that should be span-wrapped): plugins.append(plugin_info)
  - `/home/user/Playground/.clones/llm/llm/__init__.py:104` (Plugin hook dispatch that should be span-wrapped): return plugins
```

**Gate**: `wait_for:plugin-author announcement sent`
**Rollback**: Undo the reference plugin change and keep the helper undocumented in plugins.
**Observability**: Confirm the reference plugin still runs and emits its custom span under llm.tracing.span.
**Depends on**: S1, S3, S6

#### Task S8 — Run release readiness checks for default-off behavior, export health, and no import regression with tracing enabled only via LLM_OTEL=1 or --otel.

**Files**: `/home/user/Playground/.clones/llm/llm/cli.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/.clones/llm/llm/cli.py.
  - `/home/user/Playground/.clones/llm/llm/cli.py:336` (CLI flag registration for optional OTel tracing): click.option(
  - `/home/user/Playground/.clones/llm/llm/cli.py:350` (CLI flag registration for optional OTel tracing): @click.version_option()
  - `/home/user/Playground/.clones/llm/llm/cli.py:380` (CLI flag registration for optional OTel tracing): @click.option("-s", "--system", help="System prompt to use")
  - `/home/user/Playground/.clones/llm/llm/cli.py:381` (CLI flag registration for optional OTel tracing): @click.option("model_id", "-m", "--model", help="Model to use", envvar="LLM_MODEL")
  - `/home/user/Playground/.clones/llm/llm/cli.py:382` (CLI flag registration for optional OTel tracing): @click.option(
```

**Gate**: `monitor:export_error_rate<0.1% for 24h`
**Rollback**: Disable tracing export and revert to the no-op helper.
**Observability**: Monitor OTLP/HTTP success rate, import_or_cli_regression=0, and zero behavior change when tracing is disabled.
**Depends on**: S5, S6, S7

## Plan: 03-safety-tilted

### Plan `03-safety-tilted`

| # | Action | Owner | Files | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Implement llm/tracing.py with lazy OpenTelemetry imports, enable_tracing(), span | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/llm/models.py`, `/home/user/Playground/.clones/llm/tests/test_embed.py` | `none` | Remove llm/tracing.py and disable tracing initiali |
| S2 | Add the [tracing] optional extras in pyproject.toml for opentelemetry-api, opent | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py` | `wait_for:package_release_contains_tracing_extras` | Revert pyproject.toml extras to the prior state an |
| S3 | Instrument llm/models.py around Model.prompt(), Model.chain(), and AsyncModel.pr | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/tests/test_async.py`, `/home/user/Playground/.clones/llm/tests/test_tools.py` | `none` | Remove the span wrappers from llm/models.py and re |
| S4 | Instrument llm/embeddings.py so every embedding execution emits llm.embedding.ru | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/llm/embeddings.py`, `/home/user/Playground/.clones/llm/tests/test_embed_cli.py` | `none` | Remove embedding span wrappers and redeploy_previo |
| S5 | Wrap llm/plugins.py hook dispatch and tool invocation dispatch sites with llm.to | BackendOwner | `/home/user/Playground/.clones/llm/llm/__init__.py`, `/home/user/Playground/.clones/llm/tests/test_plugins.py` | `none` | Remove the plugin/tool dispatch span wrappers and  |
| S6 | Update llm/cli.py to add the --otel flag and top-level llm.cli.prompt/chat/embed | BackendOwner | `/home/user/Playground/.clones/llm/llm/cli.py`, `/home/user/Playground/.clones/llm/llm/default_plugins/openai_models.py`, `/home/user/Playground/.clones/llm/llm/models.py` | `none` | Remove --otel wiring and CLI span creation, then r |
| S7 | Add tests for llm/cli.py, llm/models.py, llm/embeddings.py, and llm/tracing.py c | ConsumerSubsystem | `/home/user/Playground/.clones/llm/llm/cli.py` | `approval:QA` | Remove the new tracing test expectations and redep |
| S8 | Add docs/tracing.md and README updates documenting LLM_OTEL, --otel, OTEL_EXPORT | ProductPM | `/home/user/Playground/.clones/llm/llm/cli.py` | `wait_for:approved customer-facing docs` | Remove the tracing docs and release-note reference |
| S9 | Add a reference plugin update (for example llm-anthropic) to use llm.tracing.spa | ProductPM | `/home/user/Playground/.clones/llm/llm/models.py`, `/home/user/Playground/.clones/llm/tests/test_async_parity.py`, `/home/user/Playground/.clones/llm/tests/test_embed_cli.py` | `wait_for:plugin-author announcement sent` | Revert the reference plugin to its prior state and |
| S10 | Enable an internal staging soak with LLM_OTEL=1 on llm prompt/chat/embed flows a | SRE | `/home/user/Playground/.clones/llm/docs/plugins/llm-markov/llm_markov.py`, `/home/user/Playground/.clones/llm/llm/__init__.py`, `/home/user/Playground/.clones/llm/tests/test_parts.py` | `monitor:export_error_rate<0.1% for 24h` | Disable tracing export and revert to the no-op hel |
| S11 | After the reference plugin ships and tracing has soaked, release the feature pub | SRE | `/home/user/Playground/.clones/llm/llm/models.py`, `/home/user/Playground/.clones/llm/tests/test_async_parity.py`, `/home/user/Playground/.clones/llm/tests/test_embed_cli.py` | `approval:release-manager` | Redeploy the prior release and remove the recommen |

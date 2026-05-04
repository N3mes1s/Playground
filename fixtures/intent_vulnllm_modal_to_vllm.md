# Switch `vulnllm-analyzer` from raw Modal endpoints to a vLLM-served OpenAI-compatible API on Modal

## What

Replace the bespoke `modal_service.py` that exposes `/health`, `/analyze`,
`/analyze/batch` over a Modal web endpoint with a Modal app that runs
**vLLM's OpenAI-compatible server** for VulnLLM-R-7B. `analyzer.py` then
talks to it through the standard `openai` Python client pointed at the
Modal-backed URL.

## Why

- We want to swap models (e.g. quantised variants, alternative VulnLLM
  forks) without redeploying the analyzer, just by changing
  `LLM_MODEL_NAME`.
- A standardised wire format makes `vulnllm-analyzer` slot into the same
  OpenAI-compatible plumbing the rest of `mirofish_lab` already uses
  (`OPENAI_API_KEY`, `OPENAI_BASE_URL`, `MODEL`).
- Batched scoring through vLLM's continuous batching is meaningfully
  faster than our hand-rolled `/analyze/batch` + manual padding.

## Scope

- New `vulnllm-analyzer/modal_vllm_service.py` deploying vLLM with
  VulnLLM-R-7B on A10G.
- `vulnllm-analyzer/analyzer.py`: replace direct HTTP calls with an
  `openai.OpenAI(base_url=..., api_key=...)` client.
- `vulnllm-analyzer/proxy_patch.py` and `repo_fetcher.py` unchanged.
- Benchmark scripts (`benchmark_advisories.py`, `scan_*.py`) updated to
  the new client shape.

## Constraints

- **Live workloads** must continue: `scan_sliver_latest.py` and
  `scan_bottle.py` are run regularly; their outputs must remain
  byte-identical (or as close as the new tokenizer allows).
- **GPU cold-start budget**: vLLM startup is ~30 s on A10G; the Modal
  idle timeout must be tuned so common scans don't pay cold start.
- **Cost**: must stay in the ~$0.10–0.50 per 100-file repo envelope
  documented in the existing README.
- **No silent fallbacks**: if vLLM returns a malformed response,
  surface the error rather than substituting a default verdict.

## Out of scope

- Adding new languages beyond what VulnLLM-R-7B already supports.
- Switching to a different base model.
- Streaming responses.

## Affected stakeholders

- `vulnllm-analyzer` (the change)
- Anyone running the existing `scan_*.py` scripts
- Modal billing / GPU quota owner
- Downstream consumers of the JSON verdict format

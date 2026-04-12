# Latent Briefing

Replication scaffold for Ramp Labs' **["Latent Briefing: Efficient Memory Sharing for Multi-Agent Systems via KV Cache Compaction"](https://x.com/RampLabs/status/2042660310851449223)** (Apr 2026), which builds on the underlying **Attention Matching (AM)** algorithm from Zweiger et al., *["Fast KV Compaction via Attention Matching"](https://arxiv.org/abs/2602.16284)* ([code](https://github.com/adamzweiger/compaction)).

## TL;DR

Multi-agent systems are powerful but token-inefficient: an orchestrator repeatedly re-sends long shared context to worker agents. Latent Briefing avoids that by sharing memory **directly in the model's KV-cache latent space** via Attention Matching, instead of re-serializing context into tokens.

Reported results:

- Evaluated on 126 questions from LongBench v2 (0-100k tokens).
- Comparable or improved accuracy vs. the uncompacted baseline.
- Up to **49% median token savings** on medium-length (32k-100k token) documents.
- ~1.7s per compaction -- ~20x faster than sequential AM, 10-30x faster than LLM summarization.
- Worker keeps a persistent KV cache of the orchestrator's trajectory; on each call 90%+ of tokens reuse via KV prefix caching.

## Why this belongs in the Playground

Agent harnesses (including the one this repo is run by) spend enormous token budgets re-hydrating context into every sub-call. Latent Briefing is a practical recipe for cutting that cost without retraining, which is directly relevant to the agentic-coding and security-audit experiments living alongside this one (`vulnllm-analyzer/`, `recursive-lm-security-audit/`).

## Architecture

```
  ┌─────────────────────┐
  │ Orchestrator Agent  │   long trajectory, shared context
  │  (full KV cache)    │
  └──────────┬──────────┘
             │ compact (Attention Matching)
             ▼
  ┌─────────────────────┐      ┌──────────────────────┐
  │ Latent Briefing     │─────▶│  Worker Agent         │
  │  (compacted K, V)   │      │  (prefill from K,V)   │
  │  ~10% of tokens     │      │  KV prefix cache hit  │
  └─────────────────────┘      └──────────────────────┘
```

Instead of re-tokenising the orchestrator's context into a natural-language summary, AM constructs a smaller `(K', V')` pair that **reproduces the original attention outputs and preserves attention mass per KV head**. The worker then runs as if prefilled on the full context.

## Layout

| File | Purpose |
|------|---------|
| `setup.sh`          | Clones `adamzweiger/compaction` into `./upstream/` and installs requirements |
| `requirements.txt`  | Python deps for running the demo locally |
| `demo.py`           | Thin wrapper around the upstream `examples.qa_demo` with sensible defaults |
| `briefing.py`       | Stub for a Latent-Briefing-style orchestrator ↔ worker loop on top of AM |
| `scripts/run_longbench.sh` | Example LongBench v2 subset evaluation command |

## Replication

### 1. Clone upstream and install deps

```bash
cd latent-briefing
./setup.sh
```

This creates `upstream/compaction/` (the Zweiger et al. reference implementation) and installs its requirements into the active Python environment. A GPU with enough VRAM for the chosen backbone (Qwen3-4B fits on a single 24 GB card) is required.

### 2. Quick smoke test (Qwen3-4B, 10% compaction)

```bash
python demo.py --model Qwen/Qwen3-4B --target-size 0.1
```

Under the hood this invokes:

```bash
python -m examples.qa_demo --model Qwen/Qwen3-4B --target-size 0.1
```

from inside `upstream/compaction/`, which prefills an article, compresses its KV cache to 10% via AM, and compares QA accuracy against the uncompacted baseline.

### 3. LongBench v2 subset (matches Latent Briefing setup)

```bash
./scripts/run_longbench.sh
```

which runs:

```bash
python -m evaluation.run_qa_evaluation \
  --algorithm-config default \
  --methods original AM-HighestAttnKeys \
  --dataset-name quality \
  --n-articles 1 \
  --compute-stats 1
```

### 4. Latent-Briefing-style orchestrator loop (WIP)

`briefing.py` sketches the integration: maintain a persistent KV cache on the worker across orchestrator calls, AM-compact the orchestrator trajectory between turns, and let the worker resume from the compacted `(K', V')`. This is the Playground-local experimental piece; the upstream repo only ships single-turn QA demos.

## Status

Experimental -- this directory captures intent, references, and an entry point. The cross-agent KV-sharing harness in `briefing.py` is a placeholder to be fleshed out.

## References

- Ramp Labs announcement: <https://x.com/RampLabs/status/2042660310851449223>
- Zweiger, Fu, Guo, Kim. *Fast KV Compaction via Attention Matching.* arXiv:2602.16284 -- <https://arxiv.org/abs/2602.16284>
- Upstream code: <https://github.com/adamzweiger/compaction>

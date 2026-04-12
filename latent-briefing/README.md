# Latent Briefing

An implementation of the **Attention Matching (AM)** KV-cache compaction algorithm ([Zweiger et al., *Fast KV Compaction via Attention Matching*, arXiv:2602.16284](https://arxiv.org/abs/2602.16284)), with a multi-agent orchestrator/worker harness on top that mirrors the pattern in Ramp Labs' **["Latent Briefing: Efficient Memory Sharing for Multi-Agent Systems via KV Cache Compaction"](https://x.com/RampLabs/status/2042660310851449223)** (Apr 2026).

Instead of re-tokenising the orchestrator's context into natural-language summaries for each worker call, this system compacts the **KV cache directly in latent space** and hands the compacted `(K', V')` to the worker. The worker also keeps a persistent prefix cache across turns so repeated calls reuse unchanged tokens.

## What's here

```
latent-briefing/
├── compaction/                       Model-agnostic pure-torch core
│   ├── attention_matching.py         AM (top-m keys + ridge LS V'), + baselines
│   └── cache.py                      DynamicCache / legacy-tuple plumbing
├── briefing/                         HuggingFace transformers integration
│   ├── probe.py                      Per-layer post-RoPE Q capture via hooks
│   ├── model.py                      LatentBriefingModel wrapper
│   └── session.py                    OrchestratorWorkerSession with prefix reuse
├── tests/                            15 unit tests, no network required
│   ├── test_attention_matching.py    AM correctness on synthetic tensors
│   ├── test_cache.py                 DynamicCache round-trip
│   ├── test_probe.py                 Probe Q matches model-internal Q bit-exact
│   └── test_end_to_end.py            Full pipeline on a tiny random Llama
├── examples/
│   └── multi_agent.py                Orchestrator + 3 workers + append-update
├── demo.py                           Single-question AM vs. baselines
├── benchmark.py                      Multi-question, multi-seed NLL + accuracy
├── scripts/run_longbench.sh          Passthrough to upstream LongBench v2 eval
├── setup.sh                          Clones upstream reference implementation
└── requirements.txt
```

## Quick start (CPU)

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install transformers numpy

python -m unittest tests.test_attention_matching tests.test_cache \
                    tests.test_probe tests.test_end_to_end

python demo.py --model distilgpt2 --ratio 0.3
python benchmark.py --model distilgpt2 --ratios 0.2 0.3 0.5 --random-seeds 5
python examples/multi_agent.py --model distilgpt2 --ratio 0.3
```

## The algorithm

**Attention Matching** (closed form, in `compaction/attention_matching.py`):

Given a cache `K, V` of shape `[num_heads, n, head_dim]` and a probe `Q` of shape `[num_heads, q, head_dim]`:

1. Compute full probe attention `A = softmax(Q K.T / sqrt(d))` and output `O = A V`.
2. Select `m << n` keys per head by highest aggregate attention mass `sum(A, dim=probe-queries)`. Gather `K' = K[idx]`.
3. Recompute `A' = softmax(Q K'.T / sqrt(d))` against the selected keys.
4. Solve `V' = argmin ||A' V' - O||^2` via least squares (ridge-regularised when `q < m`).

`(K', V')` reproduces the attention *output* the probe would see, not just the keys. This is the `AM-HighestAttnKeys` variant from the paper, plus LS-solved values. Upstream (`adamzweiger/compaction`) has additional variants (non-uniform per-head budgets, alternative selection strategies) that are not reimplemented here.

## The harness

`LatentBriefingModel` (`briefing/model.py`) wraps a HF causal LM:

- `prefill(text)` → full-context forward, returns `DynamicCache`.
- `probe_queries(text, cache)` → per-layer **post-RoPE** Q, captured via forward pre-hooks on each attention module.
  - GPT-2 path: read Q from the `c_attn` split.
  - Llama / Qwen / Mistral / Gemma / Phi path: run `q_proj` and apply the architecture's own `apply_rotary_pos_emb` using the `(cos, sin)` already passed in to the attention forward.
  - GQA is handled via `align_probe_to_kv_heads` (mean-pool query heads within each KV group).
- `compact(cache, probe_qs, ratio)` → AM per layer, rebuild a `DynamicCache`.
- `generate(prompt, past_cache=...)` → token-by-token decode anchored on any cache.

`OrchestratorWorkerSession` (`briefing/session.py`):

- `set_orchestrator_trajectory(text)` → diff against the current trajectory, truncate cache at the shared prefix, re-prefill only the delta.
- `dispatch_worker(task, ratio)` → probe + compact + generate.

## What's verified

**Algorithm correctness** (7 tests, synthetic tensors):
- AM beats random and recent-window baselines on probe-attention reconstruction MSE.
- LS-solved `V'` beats naive `V[idx]` gather.
- Ridge branch handles the `q < m` underdetermined case without NaNs.

**Cache plumbing** (4 tests):
- Legacy tuple and `DynamicCache` round-trip through the compaction pipeline.
- Token-count helpers, layer alignment.

**Probe correctness** (3 tests, tiny random Llama built from config — no weights download):
- Post-RoPE Q captured by our pre-hook matches the Q the model uses **bit-for-bit** (max abs diff < 1e-5) against the real forward.
- GPT-2 (no-RoPE) path still reports `used_rope=False` and captures Q directly.

**End-to-end** (1 test, tiny random Llama with GQA):
- Prefill 48 tokens → probe 6 tokens → compact to 12 (25%) → generate. Runs cleanly, shapes all line up.

```
Ran 15 tests in ~13s. OK.
```

## What's NOT verified

- **Large-model quality.** Every test runs on CPU with either a random-weight tiny Llama or `distilgpt2`. No real model, no real benchmark dataset has been evaluated in this tree.
- **The Ramp Labs 49%-savings LongBench v2 number.** That claim comes from running their actual method on real models at scale. Reproducing it requires a GPU and the LongBench v2 dataset; see `scripts/run_longbench.sh` for the upstream passthrough.
- **Qualitative generation quality on a real model.** The `distilgpt2` demo below is a sanity check, not a quality study.

## Demo results (distilgpt2, anecdotal)

`python demo.py --model distilgpt2 --ratio 0.3 --context-repeat 2` on one QA pair:

```
method       tokens  savings      NLL     ΔNLL     ms
full            202     0.0%   1.4881   0.0000      —
AM               64    70.2%   2.6110  +1.1229      6
recent           64    70.2%   9.1438  +7.6557      2
random           64    70.2%   3.4039  +1.9158      3

[answer] full cache : 'Alexander the Great founded AlexandriaQ: Who'
[answer] AM        : 'Alexander the first Alexander the first Alexander the'
[answer] recent    : ''
[answer] random    : 'Who founded Alexandria? A: Who founded'
```

AM keeps the subject ("Alexander") where baselines lose it. This is one example on one small model -- read as a sanity check, not a benchmark.

## Benchmark results (distilgpt2, 4 QA items, 5 seeds for random)

`python benchmark.py --model distilgpt2 --ratios 0.2 0.3 0.5 --random-seeds 5`:

```
ratio=0.2 (20% KV kept)
method     tok_keep   NLL mean    ±std     ΔNLL    acc
full           100%     1.7723       —   0.0000  100.0%
AM            19.8%     3.7550  0.8470  +1.9828    0.0%
recent        19.8%     5.7360  3.8787  +3.9637    0.0%
random        19.8%     4.3769  1.6512  +2.6046    5.0%

ratio=0.3 (30% KV kept)
AM            29.9%     2.9177  0.8758  +1.1454   25.0%
recent        29.9%     4.5577  3.9997  +2.7854   25.0%
random        29.9%     3.1163  1.3024  +1.3440   15.0%

ratio=0.5 (50% KV kept)
AM            50.1%     2.9465  0.8845  +1.1743   25.0%
recent        50.1%     1.1093  0.6706  -0.6630   25.0%
random        50.1%     1.7245  0.9292  -0.0478   30.0%
```

Honest read of this:
- **NLL:** AM has the lowest mean NLL at aggressive ratios (0.2, 0.3) and a tighter spread than recent-window. At 0.5, noise dominates and baselines catch up.
- **Accuracy:** on `n=4` items this is essentially noise. Differences of a single item flip the numbers. AM is never worse than random/recent in accuracy, but "wins" are within sampling error.
- **This is a small-model toy benchmark.** To meaningfully evaluate AM you need a real model (≥1B params), a real long-context benchmark, and more items. See `scripts/run_longbench.sh`.

## Reproducing the paper

For the actual Ramp Labs numbers:

```bash
./setup.sh                      # clones adamzweiger/compaction into ./upstream/
./scripts/run_longbench.sh      # upstream's LongBench v2 eval
```

Swapping in a real model with this tree:

```bash
python demo.py --model Qwen/Qwen2.5-0.5B --ratio 0.2
python benchmark.py --model Qwen/Qwen2.5-0.5B --ratios 0.1 0.2 0.5
```

The RoPE probe path is now correct (verified against a tiny Llama), so these should produce meaningful numbers -- but they have not been run in this tree.

## Known limitations

- **Only `AM-HighestAttnKeys` + LS values.** No non-uniform per-head budgets, no alternative key-selection heuristics from upstream's `head_budget_optimization/`.
- **Architecture coverage.** Tested on GPT-2 (runtime) and tiny Llama (test suite). Qwen2/Qwen3/Mistral/Gemma/Gemma2/Phi *should* work because they all export `apply_rotary_pos_emb` at module scope and use `position_embeddings=(cos, sin)` in attention forwards, but I have not run them end-to-end. Exotic RoPE variants (YaRN, NTK, partial RoPE) may need per-architecture tweaks.
- **Batch size 1.** `compact_dynamic_cache` asserts `batch == 1`. Batched compaction is straightforward but not implemented.
- **No eager/flash-attn distinction.** Compaction operates on cached K/V tensors after the fact; the attention backend used during the probe forward doesn't matter, but generation from a compacted cache may behave differently across backends in edge cases.

## References

- Ramp Labs. *Latent Briefing: Efficient Memory Sharing for Multi-Agent Systems via KV Cache Compaction.* <https://x.com/RampLabs/status/2042660310851449223>
- Zweiger, A.; Fu, X.; Guo, H.; Kim, Y. *Fast KV Compaction via Attention Matching.* arXiv:2602.16284. <https://arxiv.org/abs/2602.16284>
- Upstream reference code: <https://github.com/adamzweiger/compaction>

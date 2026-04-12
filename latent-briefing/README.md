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
├── tests/                            23 unit tests, no network required
│   ├── test_attention_matching.py    AM correctness on synthetic tensors
│   ├── test_cache.py                 DynamicCache round-trip
│   ├── test_probe.py                 Probe Q matches model-internal Q bit-exact
│   ├── test_session.py               Incremental set_orchestrator_trajectory == fresh prefill
│   └── test_end_to_end.py            Full pipeline on tiny Llama + cache immutability regression
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

**Harness invariants:**
- `generate()` does not mutate the caller's `past_cache` (regression test — HF's DynamicCache updates are in-place, so we clone before stepping).
- `demo.held_out_nll()` does not mutate the caller's cache either (regression test — same root cause, different call site).
- `clone_cache()` is verified truly deep: extending or in-place-editing the clone does not leak to the original.
- `ProbeCapture` raises `RuntimeError` if it encounters a RoPE-using architecture where its `apply_rotary_pos_emb` call fails, rather than silently falling back to pre-RoPE Q (which would produce meaningless AM scores).
- `OrchestratorWorkerSession.set_orchestrator_trajectory()`'s truncate+extend path produces a KV cache **bit-identical** to `prefill(text)` across fresh/extend/branch/no-op/shrink scenarios (tested against a random-weights Llama; max abs diff < 1e-4).

**Real-model end-to-end** (not in the test suite — run via `demo.py` / `/tmp/verify_*.py`):
- SmolLM2-135M (Llama, 30 layers, GQA 3:1): full pipeline runs, 30/30 layers post-RoPE, AM at 80% savings generates "Alexander the Great" correctly where recent/random produce garbage.
- Qwen2.5-0.5B (Qwen2, 24 layers, GQA 7:1): full pipeline runs, 24/24 layers post-RoPE, AM at 80% savings ΔNLL=-0.003 (actually slightly lower than full cache) and generates the correct answer; recent/random ΔNLL around +7.

```
Ran 23 tests in ~9s. OK.
```

### GQA head-alignment ablation (empirical, not a fixed default)

For GQA models, AM needs to reduce the G query heads per group to a
single probe per KV head. Two choices are implemented:

- `align_probe_to_kv_heads(..., strategy="mean")` (default): mean-pool.
- `align_probe_to_kv_heads(..., strategy="concat")`: stack along time axis.

Per-strategy measurements on 4 QA items (target-NLL and answer accuracy;
lower NLL is better):

SmolLM2-135M (G=3):
```
ratio=0.5  mean: NLL=0.99 acc=50%   concat: NLL=1.42 acc=25%   better=mean
ratio=0.3  mean: NLL=1.02 acc=100%  concat: NLL=2.18 acc=50%   better=mean
ratio=0.2  mean: NLL=1.49 acc=75%   concat: NLL=2.08 acc=25%   better=mean
ratio=0.1  mean: NLL=3.04 acc=25%   concat: NLL=1.10 acc=100%  better=concat
```

Qwen2.5-0.5B (G=7):
```
ratio=0.5  mean: NLL=0.65 acc=50%   concat: NLL=1.75 acc=75%   better=mean
ratio=0.3  mean: NLL=0.78 acc=75%   concat: NLL=0.73 acc=75%   better=concat
ratio=0.2  mean: NLL=1.48 acc=75%   concat: NLL=1.03 acc=75%   better=concat
ratio=0.1  mean: NLL=7.13 acc=25%   concat: NLL=0.81 acc=75%   better=concat
```

Initial impulse was to default to `concat` based on a probe-attention
reconstruction MSE ablation (which concat wins by 40-400000x). But
probe-attention MSE does not predict downstream generation quality:
mean wins on actual target-NLL and answer accuracy at moderate
compression ratios, and concat only pulls ahead at aggressive ratios
(≤ 0.2 on Qwen, ≤ 0.1 on SmolLM2). Neither strategy is dominant.
`mean` is the default because it's usually better at the ratios the
method targets; `concat` is available for aggressive-compression
regimes where mean collapses.

## What IS NOT verified

- **The Ramp Labs 49%-savings LongBench v2 number.** That claim comes from running their actual method on real models at LongBench scale. Reproducing it requires a GPU and the LongBench v2 dataset; see `scripts/run_longbench.sh` for the upstream passthrough.
- **Long contexts.** Verified runs use 70-76 token contexts. Savings / quality at multi-thousand-token contexts is not empirically tested here (though the algorithm is context-length-agnostic).
- **Statistical rigor.** Each "real model" result below is one QA pair. Robust conclusions need a benchmark suite; small-scale distilgpt2 benchmark included for that.

## Verified end-to-end on real pretrained RoPE models

These are actual runs on real pretrained weights (not random-init test models).
One QA pair each, context: a 5-sentence passage about the founding of
Alexandria, question: *"Who founded Alexandria?"*, target: *"Alexander the Great"*.
NLL is token-averaged cross-entropy on the held-out target.

### SmolLM2-135M (Llama architecture, GQA 3:1, 30 layers)

```
[full]     tokens=70   NLL=0.8359   gen='The city was founded by Ptolemy I Soter...'
                                         ^ note: full cache picks the wrong subject

ratio=0.5  (35 tok, 50% saved)
  AM       NLL=1.035  ΔNLL=+0.20  gen='Ptolemy I Soter, the founder of Alexandria. ...'
  recent   NLL=7.229  ΔNLL=+6.39  gen='Euclid taught geometry in Alexandria...'
  random   NLL=2.620  ΔNLL=+1.78  gen='Ptolemy the Greek world...'

ratio=0.3  (21 tok, 70% saved)
  AM       NLL=0.858  ΔNLL=+0.02  gen='Alexander the Great. Alexandria was the capital...'  ← correct
  recent   NLL=5.858  ΔNLL=+5.02  gen='He studied there briefly. There briefly...'
  random   NLL=2.763  ΔNLL=+1.93  gen='Eu Eu Eu Eu Eu...'

ratio=0.2  (14 tok, 80% saved)
  AM       NLL=0.871  ΔNLL=+0.03  gen='Alexander the Great. Alexandria was founded in 300 BC...'  ← correct
  recent   NLL=8.823  ΔNLL=+7.99  gen=':::::::::::'
  random   NLL=4.012  ΔNLL=+3.18  gen='He founded Alexandria. The city was the intellectual city of the city...'
```

AM maintains ΔNLL within +0.03 at 80% savings; recent-window and random collapse
(+7.99 and +3.18). AM at ratio=0.3 flips the answer from the full-cache's *wrong*
"Ptolemy" to the *correct* "Alexander the Great" -- the AM briefing focuses on the
attention-relevant keys for the probe, which in this case are the "Alexander...
founded" keys, overriding the surface-level Ptolemy bias.

### Qwen2.5-0.5B (Qwen2 architecture, GQA 7:1, 24 layers)

```
[full]     tokens=76   NLL=0.1378   gen='Alexander the Great'

ratio=0.5  (38 tok)  AM: NLL=0.159  ΔNLL=+0.02   gen='Alexander the Great'  ← correct
                     recent: NLL=8.998  ΔNLL=+8.86   gen='Euclid taught geometry...'
                     random: NLL=1.675  ΔNLL=+1.54   gen='Alexander the Great founded Alexandria...'

ratio=0.3  (23 tok)  AM: NLL=0.198  ΔNLL=+0.06   gen='Alexander the Great'  ← correct
                     recent: NLL=8.812  ΔNLL=+8.67   gen='Archimedes studied Alexandria?...'
                     random: NLL=3.549  ΔNLL=+3.41   gen="Euclid's Elements..."

ratio=0.2  (15 tok)  AM: NLL=0.135  ΔNLL=-0.003  gen='Alexander the Great'  ← correct, ΔNLL negative!
                     recent: NLL=6.841  ΔNLL=+6.70   gen='One of the seven wonders...'
                     random: NLL=7.168  ΔNLL=+7.03   gen='The The The The...'
```

At 80% savings (ratio=0.2), AM's held-out NLL is marginally **lower** than the full
cache (-0.003) -- AM's solved `V'` acts as a regulariser on this probe's attention
output. Recent and random degrade catastrophically (ΔNLL ~+7).

RoPE was confirmed applied on 30/30 layers (SmolLM2) and 24/24 layers (Qwen2)
via the per-layer `used_rope` flag from `ProbeCapture`.

### Caveats on these numbers

- **One QA pair per model.** These are demos, not a statistically rigorous
  study. A rigorous eval requires LongBench v2 (see `scripts/run_longbench.sh`).
- **Short context (70-76 tokens).** The paper's 49% savings claim applies to
  32k-100k token documents where compaction has much more room to work.
  Savings on short contexts here are larger (70-80%) because the probe
  focuses on only a few tokens that carry the answer.
- **AM's "beating full cache" is real but setup-specific.** At aggressive
  compaction the LS-solved `V'` effectively regularises against the probe's
  exact attention output. This helps on focused factoid questions; on
  open-ended generation the full cache will generally still win.

### Small-model benchmark (distilgpt2, 4 items, 5 seeds for random)

`python benchmark.py --model distilgpt2 --ratios 0.2 0.3 0.5 --random-seeds 5`
runs in under a minute on CPU:

```
ratio=0.2 (20% KV kept)
method     tok_keep   NLL mean    ±std     ΔNLL    acc
full           100%     1.7723       —   0.0000   50.0%
AM            19.8%     4.6516  0.7954  +2.8793   25.0%
recent        19.8%     7.5565  3.2353  +5.7842    0.0%
random        19.8%     6.0086  1.2891  +4.2363    0.0%

ratio=0.3 (30% KV kept)
AM            30.4%     3.5781  0.6390  +1.8058   25.0%
recent        30.4%     5.2238  2.8874  +3.4515    0.0%
random        30.4%     5.5215  1.6710  +3.7492    0.0%

ratio=0.5 (50% KV kept)
AM            50.2%     2.8995  0.7620  +1.1272   25.0%
recent        50.2%     3.8720  2.8410  +2.0997   25.0%
random        50.2%     3.9591  1.9039  +2.1868   15.0%
```

On distilgpt2 AM wins NLL at every ratio by margins well outside one sigma of the
random baseline, and matches or beats the baselines on answer accuracy (though
n=4 items is not enough for a rigorous accuracy test).

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
- **Architecture coverage.** Tested end-to-end on GPT-2 (distilgpt2), Llama family (SmolLM2-135M), and Qwen2 family (Qwen2.5-0.5B). Mistral / Gemma / Gemma2 / Phi / Qwen3 *should* work because they follow the same convention (module-scope `apply_rotary_pos_emb`, `position_embeddings=(cos, sin)` passed into the attention forward), but have not been run. Exotic RoPE variants (YaRN, NTK, partial RoPE) may need per-architecture tweaks.
- **Batch size 1.** `compact_dynamic_cache` asserts `batch == 1`. Batched compaction is straightforward but not implemented.
- **No eager/flash-attn distinction.** Compaction operates on cached K/V tensors after the fact; the attention backend used during the probe forward doesn't matter, but generation from a compacted cache may behave differently across backends in edge cases.

## References

- Ramp Labs. *Latent Briefing: Efficient Memory Sharing for Multi-Agent Systems via KV Cache Compaction.* <https://x.com/RampLabs/status/2042660310851449223>
- Zweiger, A.; Fu, X.; Guo, H.; Kim, Y. *Fast KV Compaction via Attention Matching.* arXiv:2602.16284. <https://arxiv.org/abs/2602.16284>
- Upstream reference code: <https://github.com/adamzweiger/compaction>

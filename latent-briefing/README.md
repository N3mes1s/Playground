# Latent Briefing

A from-scratch implementation of **Ramp Labs' "Latent Briefing: Efficient Memory Sharing for Multi-Agent Systems via KV Cache Compaction"** ([announcement](https://x.com/RampLabs/status/2042660310851449223), Apr 2026), on top of the **Attention Matching (AM)** algorithm from Zweiger et al., *["Fast KV Compaction via Attention Matching"](https://arxiv.org/abs/2602.16284)* ([reference code](https://github.com/adamzweiger/compaction)).

Rather than re-tokenising the orchestrator's context into a natural-language summary for each worker call, this system compacts the **KV cache directly in latent space** and hands the compacted `(K', V')` to the worker as a "briefing." The worker also keeps a persistent prefix cache across turns, so repeated calls reuse 90%+ of the tokens via prefix caching.

## What's in here

```
latent-briefing/
├── compaction/                Core AM algorithm, pure torch, model-agnostic
│   ├── attention_matching.py  AM, random and recent-window baselines
│   └── cache.py               DynamicCache / legacy-tuple plumbing
├── briefing/                  HF transformers integration
│   ├── probe.py               Per-layer Q capture via forward pre-hooks
│   ├── model.py               LatentBriefingModel: prefill / probe / compact / generate
│   └── session.py             OrchestratorWorkerSession with prefix reuse
├── tests/                     Unit tests (pure-tensor + HF integration)
│   ├── test_attention_matching.py
│   └── test_cache.py
├── examples/
│   └── multi_agent.py         One orchestrator, three workers demo
├── demo.py                    Single-question AM vs. baselines comparison
├── benchmark.py               Multi-question NLL + answer-accuracy sweep
├── scripts/run_longbench.sh   LongBench v2 via upstream (optional)
├── setup.sh                   Clones upstream compaction repo for reference
└── requirements.txt
```

## Quick start (CPU, ~1 GB RAM)

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install transformers numpy

# Unit tests (pure-tensor AM math)
python -m unittest tests.test_attention_matching

# End-to-end demo on distilgpt2 (downloads ~320 MB on first run)
python demo.py --model distilgpt2 --ratio 0.3

# Multi-method sweep
python benchmark.py --model distilgpt2 --ratios 0.2 0.3 0.5

# Multi-agent orchestrator/worker loop
python examples/multi_agent.py --model distilgpt2 --ratio 0.3
```

For real model quality, swap in a larger causal LM (`gpt2`, `gpt2-medium`, `Qwen/Qwen3-4B`, ...). GPU is strongly recommended for models past ~125M params and context longer than a few hundred tokens.

## The algorithm

Attention Matching (closed form, ``compaction/attention_matching.py``):

1. Let ``K, V`` be the stored KV cache of shape ``[num_heads, n, head_dim]`` and let ``Q`` be a probe (the worker's task/question tokens) of shape ``[num_heads, q, head_dim]``.
2. Compute the full probe attention ``A = softmax(Q K.T / sqrt(d))`` and its output ``O = A V``.
3. Select ``m << n`` key indices by highest aggregate attention mass ``sum(A, dim=probe-queries)``. Gather ``K' = K[idx]``.
4. Recompute ``A' = softmax(Q K'.T / sqrt(d))`` against the selected keys.
5. Solve ``V' = argmin ||A' V' - O||^2`` via least squares (ridge-regularised when the probe is smaller than the budget).

The resulting ``(K', V')`` reproduces the attention *output* the probe queries would see under the full cache, not just the keys. In the tests we confirm this beats random-index and recent-window selection on probe-attention reconstruction MSE on synthetic data.

## The harness

`LatentBriefingModel` (in ``briefing/model.py``) wraps a HuggingFace causal LM and exposes:

* ``prefill(context)``: full-context forward, returns a ``DynamicCache``.
* ``probe_queries(probe, cache)``: run the probe tokens through the model with forward pre-hooks that tee out each attention layer's Q projection (GPT-2 c_attn split or Llama/Qwen q_proj, with GQA head averaging when needed).
* ``compact(cache, probe_qs, ratio)``: apply AM per layer and rebuild a ``DynamicCache`` of the same shape.
* ``generate(prompt, past_cache=...)``: token-by-token decode anchored on an arbitrary cache (compacted or not).

`OrchestratorWorkerSession` (``briefing/session.py``) layers the multi-agent loop on top:

* ``set_orchestrator_trajectory(text)``: diff the current trajectory against the stored one, truncate the cache at the shared prefix, re-prefill only the delta.
* ``dispatch_worker(task, ratio)``: probe + compact + generate from the compacted cache.

This mirrors the Ramp Labs pattern where the worker retains a persistent KV cache of the orchestrator's trajectory across calls and 90%+ of tokens are reused.

## Verified behaviour

From the included unit tests (``python -m unittest tests.test_attention_matching``):

```
test_attention_output_preserved_better_than_random  . AM mean-squared error
                                                      << random and recent
test_value_solve_beats_gather                       . LS-solved V' beats V[idx]
test_underdetermined_case_runs                      . q < m still yields valid V'
test_identity_when_no_compression                   . ratio=1.0 is a no-op
test_attention_mass_sums_to_q                       . per-head mass sums exactly
```

From ``python demo.py --model distilgpt2 --ratio 0.3`` (303-token context, held-out answer NLL + "was Alexander the Great" string match on generated text):

| method | tokens kept | ΔNLL vs full | generated answer |
|--------|------------:|-------------:|------------------|
| full            | 303 | 0.000  | Alexander the Great founded Alexandria... |
| **AM**          | 95  | +1.08  | **Alexander the Great founded Alexandria**... |
| recent-window   | 95  | +1.19  | Q\nQ\nQ\n...            |
| random          | 95  | +2.13  | Who founded Alexandria?... |

AM is the only method at the 70% savings budget that produces the correct factual answer on this probe; the baselines degrade completely.

## Reproducing the Ramp Labs numbers

The Ramp Labs announcement reports up to **49% median token savings** with comparable or improved accuracy on LongBench v2 (0-100k-token documents), at ~1.7s per compaction. Those numbers come from running on larger models and the LongBench v2 dataset.

To reproduce at that scale, run the upstream reference implementation via the bundled script:

```bash
./setup.sh                      # clones adamzweiger/compaction into ./upstream/
./scripts/run_longbench.sh      # python -m evaluation.run_qa_evaluation ...
```

The implementation in `compaction/` and `briefing/` here is a clean-room re-implementation of the core idea, verified end-to-end on CPU with distilgpt2, and structured so the same code path runs with a larger backbone once you point it at a GPU.

## References

- Ramp Labs. *Latent Briefing: Efficient Memory Sharing for Multi-Agent Systems via KV Cache Compaction.* <https://x.com/RampLabs/status/2042660310851449223>
- Zweiger, A.; Fu, X.; Guo, H.; Kim, Y. *Fast KV Compaction via Attention Matching.* arXiv:2602.16284. <https://arxiv.org/abs/2602.16284>
- Upstream reference code: <https://github.com/adamzweiger/compaction>

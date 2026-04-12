"""End-to-end Latent Briefing demo.

Builds a long shared context, compacts it with Attention Matching against a
worker's question, and compares worker output / NLL under:

    1. uncompacted baseline  (full KV cache)
    2. Attention Matching    (compact KV cache)
    3. Recent-window baseline (keep last-m tokens)
    4. Random baseline        (random-m tokens)

Runs on CPU with ``sshleifer/tiny-gpt2`` by default. Swap in ``gpt2`` or
``Qwen/Qwen3-4B`` for real model quality (the latter needs a GPU).

Usage:
    python demo.py                        # tiny-gpt2, ratio=0.3
    python demo.py --model gpt2 --ratio 0.2
    python demo.py --model gpt2 --context-repeat 40 --ratio 0.1
"""
from __future__ import annotations

import argparse
import math
import time
from typing import Callable

import torch

from briefing.model import LatentBriefingModel
from briefing.probe import align_probe_to_kv_heads
from compaction import (
    cache_token_count,
    clone_cache,
    compact_dynamic_cache,
    random_baseline,
    recent_window_baseline,
)
from compaction.attention_matching import attention_match


DEFAULT_CONTEXT = (
    "The ancient library of Alexandria housed hundreds of thousands of scrolls. "
    "Hypatia was a mathematician and philosopher in Alexandria. "
    "The lighthouse of Alexandria, the Pharos, was one of the seven wonders. "
    "Alexander the Great founded the city in 331 BC on the Mediterranean coast. "
    "The city became the intellectual capital of the Hellenistic world. "
    "Euclid, the father of geometry, taught there. Archimedes studied there. "
    "Ptolemy I Soter built the Mouseion, which housed the great library. "
)

DEFAULT_PROBE = "Q: Who founded Alexandria? A:"
DEFAULT_TARGET = " Alexander the Great founded Alexandria"


def held_out_nll(
    lbm: LatentBriefingModel, cache, probe: str, target: str,
) -> float:
    """NLL of ``target`` tokens given ``cache`` + ``probe`` as context.

    Measuring the held-out target (rather than the probe itself) makes this
    a fair evaluation: AM is optimised against the probe's attention, so
    scoring probe NLL would be gamed. The target is unseen by AM.

    Caller's ``cache`` is not mutated (HF's DynamicCache.update() is in-place,
    so we clone before the forward).
    """
    probe_ids = lbm.tokenizer(probe, return_tensors="pt").input_ids.to(lbm.device)
    target_ids = lbm.tokenizer(target, return_tensors="pt", add_special_tokens=False
                               ).input_ids.to(lbm.device)

    # Feed probe + target jointly; the cache is read-only for our NLL purposes.
    full_ids = torch.cat([probe_ids, target_ids], dim=-1)
    cache = clone_cache(cache) if cache is not None else None
    with torch.no_grad():
        out = lbm.model(input_ids=full_ids, past_key_values=cache,
                        use_cache=True, return_dict=True)
    logits = out.logits[0]                         # [T_total, V]

    # The logits at position (probe_len + i - 1) predict target token i.
    P = probe_ids.shape[-1]
    T = target_ids.shape[-1]
    if P == 0 or T == 0:
        return float("nan")
    pred_logits = logits[P - 1 : P - 1 + T]        # [T, V]
    nll = torch.nn.functional.cross_entropy(
        pred_logits.float(), target_ids[0].long(), reduction="mean"
    )
    return float(nll)


def run_baseline(
    lbm: LatentBriefingModel,
    full_cache,
    target_size: float,
    kind: str,
    probe_qs,
):
    if kind == "AM":
        new_cache, _, stats = lbm.compact(full_cache, probe_qs, target_size)
        return new_cache, stats
    if kind == "recent":
        pairs_fn = lambda k, v, q, t, **kw: recent_window_baseline(k, v, t)
        new_cache, _ = compact_dynamic_cache(
            full_cache, probe_qs, target_size, am_fn=pairs_fn
        )
    elif kind == "random":
        pairs_fn = lambda k, v, q, t, **kw: random_baseline(k, v, t)
        new_cache, _ = compact_dynamic_cache(
            full_cache, probe_qs, target_size, am_fn=pairs_fn
        )
    else:
        raise ValueError(kind)
    from briefing.model import BriefingStats
    stats = BriefingStats(
        source_tokens=cache_token_count(full_cache),
        compact_tokens=cache_token_count(new_cache),
        probe_tokens=probe_qs[0].shape[-2],
        layers=len(probe_qs),
    )
    return new_cache, stats


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="sshleifer/tiny-gpt2",
                    help="HF model id (tiny-gpt2, gpt2, distilgpt2, ...)")
    ap.add_argument("--ratio", type=float, default=0.3,
                    help="Compaction target as fraction of original KV length")
    ap.add_argument("--context-repeat", type=int, default=4,
                    help="Times to repeat DEFAULT_CONTEXT to build a long prompt")
    ap.add_argument("--context", default=None, help="Override context string")
    ap.add_argument("--probe", default=DEFAULT_PROBE)
    ap.add_argument("--target", default=DEFAULT_TARGET,
                    help="Held-out continuation used to score NLL fairly")
    ap.add_argument("--max-new-tokens", type=int, default=24)
    ap.add_argument("--device", default="cpu")
    args = ap.parse_args()

    context = args.context or (DEFAULT_CONTEXT * args.context_repeat).strip()

    print(f"[demo] loading {args.model} on {args.device} ...")
    t0 = time.time()
    lbm = LatentBriefingModel(args.model, device=args.device)
    print(f"[demo] loaded in {time.time() - t0:.1f}s (kv_heads={lbm._num_kv_heads})")

    # 1. Prefill full context
    t0 = time.time()
    _, full_cache = lbm.prefill(context)
    source_len = cache_token_count(full_cache)
    t_prefill = time.time() - t0
    print(f"[demo] context tokens: {source_len}  (prefill {t_prefill*1000:.0f}ms)")

    # 2. Probe with the worker's question
    t0 = time.time()
    probe_qs = lbm.probe_queries(args.probe, full_cache)
    t_probe = time.time() - t0
    print(f"[demo] probe '{args.probe}': {probe_qs[0].shape[-2]} tokens, "
          f"{len(probe_qs)} layers  ({t_probe*1000:.0f}ms)")

    # 3. Baseline NLL with full cache
    nll_full = held_out_nll(lbm, full_cache, args.probe, args.target)
    print(f"\n[baseline] full cache ({source_len} tok):  NLL={nll_full:.4f}")

    # 4. Compare AM vs random vs recent
    results = []
    for kind in ("AM", "recent", "random"):
        t0 = time.time()
        new_cache, stats = run_baseline(lbm, full_cache, args.ratio, kind, probe_qs)
        t_compact = time.time() - t0
        nll = held_out_nll(lbm, new_cache, args.probe, args.target)
        text, _ = lbm.generate(args.probe, past_cache=new_cache,
                               max_new_tokens=args.max_new_tokens)
        answer = text[len(args.probe):].strip()
        results.append((kind, stats, nll, t_compact, answer))

    # 5. Also generate with full cache for reference
    text_full, _ = lbm.generate(args.probe, past_cache=full_cache,
                                max_new_tokens=args.max_new_tokens)
    ref_answer = text_full[len(args.probe):].strip()

    # Pretty print
    print("\n" + "=" * 78)
    print(f"{'method':<10} {'tokens':>8} {'savings':>8} {'NLL':>8} {'ΔNLL':>8} {'ms':>6}")
    print("-" * 78)
    print(f"{'full':<10} {source_len:>8d} {'0.0%':>8} {nll_full:>8.4f} {'0.0000':>8} {'—':>6}")
    for kind, stats, nll, t_comp, _ in results:
        delta = nll - nll_full
        print(f"{kind:<10} {stats.compact_tokens:>8d} "
              f"{stats.savings*100:>7.1f}% {nll:>8.4f} {delta:>+8.4f} {t_comp*1000:>6.0f}")
    print("=" * 78)

    print(f"\n[answer] full cache  : {ref_answer!r}")
    for kind, _, _, _, answer in results:
        print(f"[answer] {kind:<10}: {answer!r}")

    # Interpretation hint
    am_row = next(r for r in results if r[0] == "AM")
    print(f"\n[summary] AM compacted {source_len} -> {am_row[1].compact_tokens} "
          f"tokens ({am_row[1].savings*100:.1f}% savings), NLL delta "
          f"{am_row[2] - nll_full:+.4f} vs. uncompacted.")


if __name__ == "__main__":
    main()

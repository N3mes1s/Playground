"""Multi-question benchmark for Latent Briefing (Attention Matching).

Averages held-out NLL and answer-match accuracy across several
(context, probe, target) triples and a sweep of compaction ratios.
Compares Attention Matching against random and recent-window baselines.

Designed to run on CPU with a small model like ``distilgpt2`` or ``gpt2``.
With a larger model on GPU and a real long-context benchmark
(e.g. LongBench v2) you can reproduce the Ramp Labs numbers directly --
see ``scripts/run_longbench.sh`` for that path.

Usage:
    python benchmark.py --model distilgpt2 --ratios 0.1 0.2 0.3 0.5
"""
from __future__ import annotations

import argparse
import json
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

import torch

from briefing.model import LatentBriefingModel
from compaction import (
    cache_token_count,
    compact_dynamic_cache,
    random_baseline,
    recent_window_baseline,
)
from demo import held_out_nll


# Small built-in eval set. Each item: (context, probe, target, answer_substring).
# Targets are the teacher-forced continuation used for NLL; answer_substring is
# checked as a case-insensitive infix in generated text to score accuracy.
EVAL_SET: List[Dict[str, str]] = [
    {
        "context": (
            "Alexander the Great founded the city of Alexandria in 331 BC on the "
            "Mediterranean coast. The city became the intellectual capital of the "
            "Hellenistic world. Ptolemy I Soter built the Mouseion there. Euclid "
            "taught geometry in Alexandria, and Archimedes studied there briefly. "
            "The Pharos lighthouse was one of the seven wonders of the ancient world."
        ),
        "probe": "Q: Who founded Alexandria? A:",
        "target": " Alexander the Great",
        "answer": "Alexander",
    },
    {
        "context": (
            "The Eiffel Tower was completed in 1889 for the World's Fair in Paris. "
            "It was designed by the engineer Gustave Eiffel and his company. At 330 "
            "metres tall it was the tallest man-made structure in the world for 41 "
            "years. It stands on the Champ de Mars beside the Seine."
        ),
        "probe": "Q: Who designed the Eiffel Tower? A:",
        "target": " Gustave Eiffel",
        "answer": "Eiffel",
    },
    {
        "context": (
            "Marie Curie was a Polish-French physicist and chemist who conducted "
            "pioneering research on radioactivity. She was the first woman to win "
            "a Nobel Prize, winning the Physics prize in 1903 jointly with her "
            "husband Pierre and with Henri Becquerel. She later won the Chemistry "
            "prize in 1911 alone. She discovered the elements polonium and radium."
        ),
        "probe": "Q: Which two elements did Marie Curie discover? A:",
        "target": " polonium and radium",
        "answer": "polonium",
    },
    {
        "context": (
            "The Apollo 11 mission in July 1969 was the first crewed mission to "
            "land on the Moon. Neil Armstrong became the first person to step "
            "onto the lunar surface, followed by Buzz Aldrin. Michael Collins "
            "remained in orbit around the Moon in the command module Columbia."
        ),
        "probe": "Q: Who stayed in lunar orbit during Apollo 11? A:",
        "target": " Michael Collins",
        "answer": "Collins",
    },
]


@dataclass
class MethodRow:
    name: str
    nll: List[float] = field(default_factory=list)
    hits: List[int] = field(default_factory=list)
    savings: List[float] = field(default_factory=list)
    compact_ms: List[float] = field(default_factory=list)


def gen_answer(lbm, probe, cache, max_new_tokens=16) -> str:
    text, _ = lbm.generate(probe, past_cache=cache, max_new_tokens=max_new_tokens)
    return text[len(probe):]


def eval_method(
    lbm: LatentBriefingModel,
    full_cache,
    probe: str,
    target: str,
    answer_substr: str,
    target_size: float,
    method: str,
    probe_qs,
    max_new_tokens: int,
) -> Tuple[float, int, float, float]:
    import time
    t0 = time.time()
    if method == "AM":
        new_cache, _, stats = lbm.compact(full_cache, probe_qs, target_size)
    elif method == "recent":
        fn = lambda k, v, q, t, **kw: recent_window_baseline(k, v, t)
        new_cache, _ = compact_dynamic_cache(full_cache, probe_qs, target_size, am_fn=fn)
        stats = None
    elif method == "random":
        fn = lambda k, v, q, t, **kw: random_baseline(k, v, t)
        new_cache, _ = compact_dynamic_cache(full_cache, probe_qs, target_size, am_fn=fn)
        stats = None
    else:
        raise ValueError(method)
    compact_ms = (time.time() - t0) * 1000

    source = cache_token_count(full_cache)
    kept = cache_token_count(new_cache)
    savings = 1.0 - kept / source

    nll = held_out_nll(lbm, new_cache, probe, target)
    gen = gen_answer(lbm, probe, new_cache, max_new_tokens)
    hit = int(answer_substr.lower() in gen.lower())
    return nll, hit, savings, compact_ms


def run(lbm, ratio: float, max_new_tokens: int, seeds: int) -> Dict[str, MethodRow]:
    rows: Dict[str, MethodRow] = {
        "full": MethodRow("full"),
        "AM": MethodRow("AM"),
        "recent": MethodRow("recent"),
        "random": MethodRow("random"),
    }
    for item in EVAL_SET:
        ctx, probe, tgt, ans = item["context"], item["probe"], item["target"], item["answer"]
        _, full_cache = lbm.prefill(ctx)
        probe_qs = lbm.probe_queries(probe, full_cache)

        # Full-cache reference (deterministic, one run).
        nll_full = held_out_nll(lbm, full_cache, probe, tgt)
        gen_full = gen_answer(lbm, probe, full_cache, max_new_tokens)
        hit_full = int(ans.lower() in gen_full.lower())
        rows["full"].nll.append(nll_full)
        rows["full"].hits.append(hit_full)
        rows["full"].savings.append(0.0)

        # AM and recent are deterministic -> one seed suffices.
        for method in ("AM", "recent"):
            nll, hit, sv, ms = eval_method(
                lbm, full_cache, probe, tgt, ans, ratio, method,
                probe_qs, max_new_tokens,
            )
            rows[method].nll.append(nll)
            rows[method].hits.append(hit)
            rows[method].savings.append(sv)
            rows[method].compact_ms.append(ms)

        # Random has a seed degree of freedom -> average across N seeds.
        for seed in range(seeds):
            torch.manual_seed(seed + 1234)
            nll, hit, sv, ms = eval_method(
                lbm, full_cache, probe, tgt, ans, ratio, "random",
                probe_qs, max_new_tokens,
            )
            rows["random"].nll.append(nll)
            rows["random"].hits.append(hit)
            rows["random"].savings.append(sv)
            rows["random"].compact_ms.append(ms)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="distilgpt2")
    ap.add_argument("--ratios", type=float, nargs="+", default=[0.1, 0.2, 0.3, 0.5])
    ap.add_argument("--max-new-tokens", type=int, default=16)
    ap.add_argument("--device", default="cpu")
    ap.add_argument("--random-seeds", type=int, default=5,
                    help="Averaging seeds for the random baseline")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    print(f"[bench] loading {args.model} on {args.device} ...")
    lbm = LatentBriefingModel(args.model, device=args.device)
    print(f"[bench] {len(EVAL_SET)} eval items, ratios={args.ratios}")

    all_results: Dict[str, Dict[str, MethodRow]] = {}
    for r in args.ratios:
        print(f"\n[bench] ratio={r}  (random baseline x{args.random_seeds} seeds)")
        rows = run(lbm, r, args.max_new_tokens, args.random_seeds)
        all_results[f"{r}"] = rows

        print(f"{'method':<10} {'tok_keep':>8} {'NLL mean':>10} {'±std':>8} "
              f"{'ΔNLL':>9} {'acc':>6} {'ms/op':>8}")
        nll_full = statistics.mean(rows["full"].nll)
        acc_full = statistics.mean(rows["full"].hits)
        print(f"{'full':<10} {'100%':>8} {nll_full:>10.4f} "
              f"{'—':>8} {'0.0000':>9} {acc_full:>6.1%} {'—':>8}")
        for name in ("AM", "recent", "random"):
            row = rows[name]
            mean_nll = statistics.mean(row.nll)
            std_nll = statistics.pstdev(row.nll) if len(row.nll) > 1 else 0.0
            acc = statistics.mean(row.hits)
            sv = statistics.mean(row.savings)
            ms = statistics.mean(row.compact_ms)
            print(f"{name:<10} {(1-sv)*100:>7.1f}% {mean_nll:>10.4f} "
                  f"{std_nll:>8.4f} {mean_nll - nll_full:>+9.4f} "
                  f"{acc:>6.1%} {ms:>8.1f}")

    if args.json_out:
        serial = {
            ratio: {
                name: {
                    "nll": row.nll,
                    "hits": row.hits,
                    "savings": row.savings,
                    "compact_ms": row.compact_ms,
                }
                for name, row in rows.items()
            }
            for ratio, rows in all_results.items()
        }
        with open(args.json_out, "w") as f:
            json.dump(serial, f, indent=2)
        print(f"\n[bench] wrote {args.json_out}")


if __name__ == "__main__":
    main()

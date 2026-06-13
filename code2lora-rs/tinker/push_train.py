#!/usr/bin/env python3
"""Push held-out exact-match as high as possible by scaling LoRA training.

Sweeps (train size, rank, epochs) on a single data-rich repo against a *fixed*
held-out test set (disjoint from every train pool), to chart how far parametric
repo-adaptation can go beyond the small-budget benchmark.

  export TINKER_API_KEY=...
  python push_train.py --github https://github.com/tkem/cachetools --test 50
"""
import argparse
import random
import subprocess
import sys
import tempfile

import tinker

import c2l_common as cc
import mine_assertions
from benchmark import train_lora


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--github")
    ap.add_argument("--repo")
    ap.add_argument("--model", default="Qwen/Qwen3.5-4B")
    ap.add_argument("--test", type=int, default=50)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--max-len", type=int, default=2048)
    ap.add_argument("--seed", type=int, default=0)
    # configs: "train:rank:epochs" comma-separated
    ap.add_argument("--configs", default="150:32:6,400:32:6,700:64:8")
    args = ap.parse_args()

    if args.github:
        repo = tempfile.mkdtemp(prefix="c2l-push-")
        subprocess.run(["git", "clone", "--depth", "1", args.github, repo], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        repo = args.repo
    if not repo:
        print("need --github or --repo", file=sys.stderr); sys.exit(1)

    # mine + dedupe + fixed split
    tasks = mine_assertions.mine_repo(repo)
    seen, uniq = set(), []
    for t in tasks:
        k = (t["prefix"], t["target"])
        if k not in seen:
            seen.add(k); uniq.append(t)
    random.Random(args.seed).shuffle(uniq)
    test = uniq[: args.test]
    pool = uniq[args.test :]
    print(f"{len(uniq)} unique tasks -> {len(test)} fixed test, {len(pool)} train pool", flush=True)

    sc = tinker.ServiceClient()
    base = sc.create_sampling_client(base_model=args.model)
    tok = base.get_tokenizer()

    base_em, _, _ = cc.evaluate(base, tok, test)
    print(f"\nbase EM: {base_em:.1%}\n", flush=True)

    results = [("base", 0, 0, base_em)]
    for spec in args.configs.split(","):
        n_train, rank, epochs = (int(x) for x in spec.split(":"))
        train = pool[:n_train]
        if len(train) < 4:
            print(f"skip {spec}: not enough train", flush=True); continue
        print(f"=== train={len(train)} rank={rank} epochs={epochs} ===", flush=True)
        sampler = train_lora(sc, args.model, rank, tok, train, epochs, args.batch,
                             args.lr, args.max_len, args.seed)
        em, ex, _ = cc.evaluate(sampler, tok, test)
        print(f"  -> held-out EM: {em:.1%}", flush=True)
        for ok, tgt, pred in ex[:4]:
            print(f"     [{'PASS' if ok else 'FAIL'}] {tgt!r} -> {pred!r}", flush=True)
        results.append((f"train={len(train)},r{rank},e{epochs}", len(train), rank, em))

    print("\n=== PUSH RESULTS ===")
    for name, _, _, em in results:
        print(f"  {name:<28} EM={em:.1%}")
    best = max(results, key=lambda r: r[3])
    print(f"\nbest: {best[0]} @ {best[3]:.1%}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Head-to-head: does turning a repo into a LoRA actually beat RAG?

For each repository we mine held-out assertion-completion tasks and score, on a
live `Qwen/Qwen3.5-4B` via Tinker:

  * base            — frozen model, no repository knowledge
  * RAG@k           — retrieve top-k non-test source chunks, prepend at inference
  * repo-LoRA       — train a repository-specific LoRA, zero inference context
  * repo-LoRA+RAG@k — both (does retrieval still help once knowledge is parametric?)

We report exact-match AND average prompt tokens, because the whole pitch of the
parametric approach is *zero inference-time token overhead*: RAG pays for context
on every query, forever; the LoRA pays once at train time.

Usage:
  export TINKER_API_KEY=...
  python benchmark.py --github https://github.com/tkem/cachetools \
                      --github https://github.com/keleshev/schema \
                      --rag-k 3,8 --max-train 48 --max-test 24 --epochs 4 --out RESULTS.md
"""
import argparse
import os
import random
import subprocess
import sys
import tempfile

import tinker

import c2l_common as cc
import mine_assertions
from rag import RagIndex


def get_repo(spec, github):
    if github:
        tmp = tempfile.mkdtemp(prefix="c2l-bench-")
        subprocess.run(["git", "clone", "--depth", "1", spec, tmp], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return tmp, tmp
    return spec, None


def mine_split(repo, max_test, max_train, seed):
    tasks = mine_assertions.mine_repo(repo)
    seen, uniq = set(), []
    for t in tasks:
        k = (t["prefix"], t["target"])
        if k not in seen:
            seen.add(k)
            uniq.append(t)
    random.Random(seed).shuffle(uniq)
    test = uniq[:max_test]
    train = uniq[max_test : max_test + max_train]
    return train, test, len(uniq)


def train_lora(sc, model, rank, tok, train, epochs, batch, lr, max_len, seed):
    tc = sc.create_lora_training_client(base_model=model, rank=rank)
    datums = [cc.build_datum(tok, t["prefix"], t["target"], max_len) for t in train]
    for epoch in range(epochs):
        random.Random(seed + epoch).shuffle(datums)
        for i in range(0, len(datums), batch):
            tc.forward_backward(datums[i : i + batch], loss_fn="cross_entropy")
            tc.optim_step(tinker.AdamParams(learning_rate=lr))
    return tc.save_weights_and_get_sampling_client()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--github", action="append", default=[], help="repeatable GitHub URL")
    ap.add_argument("--repo", action="append", default=[], help="repeatable local path")
    ap.add_argument("--model", default="Qwen/Qwen3.5-4B")
    ap.add_argument("--embed-model", default="BAAI/bge-small-en-v1.5")
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--rag-k", default="3,8")
    ap.add_argument("--max-train", type=int, default=48)
    ap.add_argument("--max-test", type=int, default=24)
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--max-len", type=int, default=2048)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--lora-rag", action="store_true", help="also eval LoRA+RAG combo")
    ap.add_argument("--out", help="write a markdown table here")
    args = ap.parse_args()

    ks = [int(x) for x in args.rag_k.split(",") if x.strip()]
    repos = [(g, True) for g in args.github] + [(r, False) for r in args.repo]
    if not repos:
        print("provide at least one --github or --repo", file=sys.stderr)
        sys.exit(1)

    sc = tinker.ServiceClient()
    base_sampler = sc.create_sampling_client(base_model=args.model)
    tok = base_sampler.get_tokenizer()

    rows = []  # (repo_name, method, em, avg_tokens)
    for spec, is_gh in repos:
        repo, tmp = get_repo(spec, is_gh)
        name = os.path.basename(spec.rstrip("/")).replace(".git", "")
        train, test, n_uniq = mine_split(repo, args.max_test, args.max_train, args.seed)
        print(f"\n##### {name}: {n_uniq} unique tasks -> {len(train)} train / {len(test)} test", flush=True)
        if len(test) < 4 or len(train) < 4:
            print("  too few tasks, skipping", flush=True)
            continue

        # base
        em, _, ntok = cc.evaluate(base_sampler, tok, test)
        rows.append((name, "base", em, ntok))
        print(f"  base           EM={em:.1%}  tokens={ntok:.0f}", flush=True)

        # RAG
        print(f"  building RAG index ({args.embed_model}) ...", flush=True)
        index = RagIndex(embed_model=args.embed_model)
        nchunks = index.build(repo)
        print(f"  indexed {nchunks} non-test chunks", flush=True)
        for k in ks:
            pf = index.prompt_builder(k, tok=tok)
            em, _, ntok = cc.evaluate(base_sampler, tok, test, prompt_fn=pf)
            rows.append((name, f"RAG@{k}", em, ntok))
            print(f"  RAG@{k:<2}         EM={em:.1%}  tokens={ntok:.0f}", flush=True)

        # repo-LoRA
        print(f"  training repo-LoRA (rank={args.rank}) ...", flush=True)
        trained = train_lora(sc, args.model, args.rank, tok, train, args.epochs, args.batch, args.lr, args.max_len, args.seed)
        em, ex, ntok = cc.evaluate(trained, tok, test)
        rows.append((name, "repo-LoRA", em, ntok))
        print(f"  repo-LoRA      EM={em:.1%}  tokens={ntok:.0f}", flush=True)
        for ok, tgt, pred in ex[:4]:
            print(f"      [{'PASS' if ok else 'FAIL'}] {tgt!r} -> {pred!r}", flush=True)

        if args.lora_rag:
            k = ks[-1]
            pf = index.prompt_builder(k, tok=tok)
            em, _, ntok = cc.evaluate(trained, tok, test, prompt_fn=pf)
            rows.append((name, f"repo-LoRA+RAG@{k}", em, ntok))
            print(f"  LoRA+RAG@{k:<2}    EM={em:.1%}  tokens={ntok:.0f}", flush=True)

        if tmp:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    # ---- aggregate table ----
    methods = []
    for _, m, _, _ in rows:
        if m not in methods:
            methods.append(m)
    repo_names = []
    for n, _, _, _ in rows:
        if n not in repo_names:
            repo_names.append(n)

    def cell(repo, method):
        for n, m, em, _ in rows:
            if n == repo and m == method:
                return em
        return None

    lines = []
    lines.append("| method | " + " | ".join(repo_names) + " | mean EM | avg tokens |")
    lines.append("|" + "---|" * (len(repo_names) + 3))
    for m in methods:
        ems = [cell(r, m) for r in repo_names]
        ems = [e for e in ems if e is not None]
        mean_em = sum(ems) / len(ems) if ems else 0.0
        toks = [t for n, mm, _, t in rows if mm == m]
        avg_tok = sum(toks) / len(toks) if toks else 0.0
        cells = []
        for r in repo_names:
            e = cell(r, m)
            cells.append(f"{e:.1%}" if e is not None else "—")
        lines.append(f"| {m} | " + " | ".join(cells) + f" | **{mean_em:.1%}** | {avg_tok:.0f} |")
    table = "\n".join(lines)

    print("\n\n=== BENCHMARK RESULTS ===")
    print(table)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write("# Code2LoRA vs RAG — live benchmark (Qwen/Qwen3.5-4B via Tinker)\n\n")
            fh.write(f"Held-out assertion-completion exact-match. Model: `{args.model}`, "
                     f"RAG embedder: `{args.embed_model}`, LoRA rank {args.rank}, "
                     f"{args.epochs} epochs, {args.max_train} train / {args.max_test} test per repo.\n\n")
            fh.write(table + "\n\n")
            fh.write("`avg tokens` is the mean prompt length fed to the model per query. "
                     "RAG pays that overhead on **every** inference; repo-LoRA carries the "
                     "repository in adapter parameters at **zero** inference-time token cost.\n")
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()

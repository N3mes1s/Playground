#!/usr/bin/env python3
"""Live proof on a modern (June-2026) model: GitHub repo -> LoRA -> attach -> works.

This is the executable, real-GPU counterpart to the Rust pipeline. Tinker cannot
ingest an externally-generated hypernetwork adapter, so here we demonstrate the
end-to-end *loop* the Code2LoRA hypernetwork amortizes: we mine assertion-
completion tasks from a repository (the paper's RepoPeftBench task), measure the
base model's exact-match, train a repository-specific LoRA on `Qwen/Qwen3.5-4B`
(the paper's "Per-repo LoRA" reference / upper bound), and re-measure. The gain
is the proof that a repository turned into LoRA parameters genuinely adapts the
model. Optionally exports the trained adapter to PEFT format.

Usage:
  export TINKER_API_KEY=...
  python run_tinker.py --github https://github.com/owner/repo
  python run_tinker.py --repo ./examples/sample_repo --max-train 40 --max-test 20
"""
import argparse
import os
import random
import subprocess
import sys
import tempfile

import tinker
from tinker_cookbook.supervised.common import compute_mean_nll

import mine_assertions
from c2l_common import build_datum, evaluate


def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--repo", help="path to a local repository")
    src.add_argument("--github", help="GitHub URL to shallow-clone")
    ap.add_argument("--model", default="Qwen/Qwen3.5-4B")
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--alpha", type=int, default=32)
    ap.add_argument("--max-train", type=int, default=40)
    ap.add_argument("--max-test", type=int, default=20)
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--max-len", type=int, default=1024)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--export", help="optional dir to export the trained PEFT adapter")
    args = ap.parse_args()

    # 1. Acquire repository.
    tmp = None
    if args.github:
        tmp = tempfile.mkdtemp(prefix="code2lora-repo-")
        print(f"cloning {args.github} ...", flush=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", args.github, tmp],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        repo = tmp
    else:
        repo = args.repo

    # 2. Mine + split assertion-completion tasks.
    tasks = mine_assertions.mine_repo(repo)
    # dedupe by (prefix, target)
    seen, uniq = set(), []
    for t in tasks:
        k = (t["prefix"], t["target"])
        if k not in seen:
            seen.add(k)
            uniq.append(t)
    random.Random(args.seed).shuffle(uniq)
    print(f"mined {len(tasks)} tasks ({len(uniq)} unique) from {repo}")
    if len(uniq) < 4:
        print("not enough tasks to demonstrate; need >= 4", file=sys.stderr)
        sys.exit(1)

    test = uniq[: args.max_test]
    train = uniq[args.max_test : args.max_test + args.max_train]
    print(f"split: {len(train)} train / {len(test)} test")

    sc = tinker.ServiceClient()

    # 3. Baseline EM on the frozen base model.
    base_sampler = sc.create_sampling_client(base_model=args.model)
    tok = base_sampler.get_tokenizer()
    print("\n=== baseline (frozen base model, no adapter) ===", flush=True)
    base_em, base_ex, _ = evaluate(base_sampler, tok, test)
    for ok, tgt, pred in base_ex:
        print(f"  [{'PASS' if ok else 'FAIL'}] target={tgt!r:<18} pred={pred!r}")
    print(f"baseline exact-match: {base_em:.1%}")

    # 4. Train a repository-specific LoRA.
    print(f"\n=== training repo LoRA on {args.model} (rank={args.rank}) ===", flush=True)
    tc = sc.create_lora_training_client(base_model=args.model, rank=args.rank)
    datums = [build_datum(tok, t["prefix"], t["target"], args.max_len) for t in train]
    step = 0
    for epoch in range(args.epochs):
        random.Random(args.seed + epoch).shuffle(datums)
        for i in range(0, len(datums), args.batch):
            batch = datums[i : i + args.batch]
            fb = tc.forward_backward(batch, loss_fn="cross_entropy")
            tc.optim_step(tinker.AdamParams(learning_rate=args.lr))
            out = fb.result()
            # weighted NLL over the supervised (completion) tokens.
            logprobs = [o["logprobs"] for o in out.loss_fn_outputs]
            weights = [d.loss_fn_inputs["weights"] for d in batch]
            nll = compute_mean_nll(logprobs, weights)
            step += 1
            print(f"  epoch {epoch} step {step}: train NLL={nll:.4f}", flush=True)

    # 5. Re-measure EM with the trained adapter attached.
    print("\n=== adapted (repo LoRA attached) ===", flush=True)
    trained_sampler = tc.save_weights_and_get_sampling_client()
    adapted_em, adapted_ex, _ = evaluate(trained_sampler, tok, test)
    for ok, tgt, pred in adapted_ex:
        print(f"  [{'PASS' if ok else 'FAIL'}] target={tgt!r:<18} pred={pred!r}")
    print(f"adapted  exact-match: {adapted_em:.1%}")

    print("\n=== RESULT ===")
    print(f"  base    EM: {base_em:.1%}")
    print(f"  adapted EM: {adapted_em:.1%}   (delta {adapted_em - base_em:+.1%})")
    print("PROOF: repository -> LoRA -> attached to live model -> measurable adaptation"
          if adapted_em >= base_em else
          "no improvement on this repo/budget; try more train tasks or epochs")

    # 6. Optional: export the trained adapter to PEFT format.
    if args.export:
        from tinker_cookbook import weights
        print(f"\nexporting PEFT adapter to {args.export} ...", flush=True)
        sampler_path = tc.save_weights_for_sampler(name="code2lora-export").result().path
        raw = weights.download(tinker_path=sampler_path, output_dir=args.export + "_raw")
        weights.build_lora_adapter(base_model=args.model, adapter_path=raw, output_path=args.export)
        print(f"PEFT adapter written to {args.export}")

    if tmp:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()

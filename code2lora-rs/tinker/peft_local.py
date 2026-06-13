#!/usr/bin/env python3
"""Load a Rust-generated Code2LoRA adapter onto the REAL base model and evaluate.

Tinker cannot ingest an externally-generated (hypernetwork) adapter, so this is
the live proof that the adapter the Rust pipeline emits actually attaches to and
runs on the real `Qwen/Qwen2.5-Coder-1.5B` (the paper's backbone) via PEFT, and
measures held-out assertion-completion exact-match with vs without it.

Note: the Rust hypernetwork is emitted at initialization (log-scale -3.5 ->
near-identity), so the generated adapter is expected to roughly match base here;
the point is that it *loads and runs on the real model*. Training the
hypernetwork through the base LLM (GPU) is what moves the number — proven
separately by `train-demo` and the per-repo LoRA loop.

Usage (CPU ok, slow):
  python peft_local.py --repo /tmp/ml/json --adapter /tmp/ad_neural --max-test 12
"""
import argparse
import re

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

import mine_multi


def normalize(s):
    return re.sub(r"\s+", " ", s).strip().rstrip(".,;:)")


def relaxed_em(pred, target):
    p, t = normalize(pred), normalize(target)
    return bool(t) and (p == t or p.startswith(t))


def complete(model, tok, prefix, max_new=12):
    ids = tok(prefix, return_tensors="pt", truncation=True, max_length=1024)
    with torch.no_grad():
        out = model.generate(
            **ids, max_new_tokens=max_new, do_sample=False,
            pad_token_id=tok.eos_token_id,
        )
    gen = out[0][ids["input_ids"].shape[1]:]
    text = tok.decode(gen, skip_special_tokens=True)
    return text.split("\n")[0]


def evaluate(model, tok, tasks):
    correct = 0
    ex = []
    for t in tasks:
        pred = complete(model, tok, t["prefix"])
        ok = relaxed_em(pred, t["target"])
        correct += ok
        if len(ex) < 6:
            ex.append((ok, t["target"], pred.strip()))
    return correct / max(1, len(tasks)), ex


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--adapter", required=True, help="Rust-generated PEFT adapter dir")
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-1.5B")
    ap.add_argument("--max-test", type=int, default=12)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    import random
    tasks = mine_multi.mine_repo(args.repo)
    seen, uniq = set(), []
    for t in tasks:
        k = (t["prefix"], t["target"])
        if k not in seen:
            seen.add(k)
            uniq.append(t)
    random.Random(args.seed).shuffle(uniq)
    test = uniq[: args.max_test]
    print(f"{len(uniq)} unique tasks; evaluating {len(test)} held-out")

    print(f"loading {args.model} (CPU) ...", flush=True)
    tok = AutoTokenizer.from_pretrained(args.model)
    base = AutoModelForCausalLM.from_pretrained(args.model, torch_dtype=torch.float32)
    base.eval()

    base_em, base_ex = evaluate(base, tok, test)
    print(f"\nbase model EM: {base_em:.1%}")
    for ok, tgt, pred in base_ex:
        print(f"  [{'PASS' if ok else 'FAIL'}] {tgt!r} -> {pred!r}")

    print(f"\nattaching Rust-generated adapter {args.adapter} via PEFT ...", flush=True)
    adapted = PeftModel.from_pretrained(base, args.adapter)
    adapted.eval()
    adapt_em, adapt_ex = evaluate(adapted, tok, test)
    print(f"\n+generated-adapter EM: {adapt_em:.1%}")
    for ok, tgt, pred in adapt_ex:
        print(f"  [{'PASS' if ok else 'FAIL'}] {tgt!r} -> {pred!r}")

    print("\n=== RESULT ===")
    print(f"  base               EM: {base_em:.1%}")
    print(f"  +generated adapter EM: {adapt_em:.1%}")
    print("PROOF: the Rust-generated Code2LoRA adapter loads onto the real "
          f"{args.model} via PEFT and runs end-to-end.")


if __name__ == "__main__":
    main()

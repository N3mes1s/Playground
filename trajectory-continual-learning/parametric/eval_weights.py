"""Evaluate the TUNED WEIGHTS vs the base model -- the parametric proof.

The decisive test for weight-level continual learning: give the model a plain
prompt with NO rules in context and NO refinement loop, and check whether the
*weights alone* now produce the user's style. We compare base vs base+LoRA on the
held-out prompts, scored by the same objective rule-checker (text_rules.py).

If tuned > base here, the preference is genuinely in the parameters -- which is
the one thing the in-context / memory path could not demonstrate.
"""

from __future__ import annotations

import json
import os
import sys

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from text_rules import check_text, features_of  # noqa: E402

MODEL = os.environ.get("BASE_MODEL", "HuggingFaceTB/SmolLM2-135M-Instruct")
OUT = os.path.join(HERE, "out")
ART = os.path.join(os.path.dirname(HERE), "artifacts", "parametric")
SYSTEM = "You are a writing assistant. Write the requested message."

torch.manual_seed(0)
torch.set_num_threads(max(1, os.cpu_count() or 4))


def gen(model, tok, prompt, max_new=160):
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]
    text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    ids = tok(text, add_special_tokens=False, return_tensors="pt")["input_ids"]
    with torch.no_grad():
        out = model.generate(ids, max_new_tokens=max_new, do_sample=False,
                             repetition_penalty=1.3, no_repeat_ngram_size=3,
                             pad_token_id=tok.pad_token_id)
    return tok.decode(out[0][ids.shape[1]:], skip_special_tokens=True).strip()


def reward(context, text):
    req = features_of(context)
    return len(check_text(context, text) & req) / len(req)


def evaluate(model, tok, prompts):
    rows, rewards = [], []
    for p in prompts:
        text = gen(model, tok, p["prompt"])
        r = reward(p["context"], text)
        rewards.append((p["context"], r))
        rows.append({"context": p["context"], "prompt": p["prompt"], "reward": r,
                     "satisfied": sorted(check_text(p["context"], text)), "text": text})
    return rows, rewards


def mean(rewards, ctx=None):
    xs = [r for c, r in rewards if ctx is None or c == ctx]
    return sum(xs) / len(xs) if xs else 0.0


def main():
    os.makedirs(ART, exist_ok=True)
    tok = AutoTokenizer.from_pretrained(OUT if os.path.exists(OUT) else MODEL)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    prompts = [json.loads(l) for l in open(os.path.join(HERE, "eval.jsonl"))]

    print("loading base model...")
    base = AutoModelForCausalLM.from_pretrained(MODEL, torch_dtype=torch.float32).eval()
    print("evaluating BASE (no lessons, no refine, just weights)...")
    base_rows, base_rw = evaluate(base, tok, prompts)

    print("loading tuned model (base + LoRA)...")
    tuned = PeftModel.from_pretrained(
        AutoModelForCausalLM.from_pretrained(MODEL, torch_dtype=torch.float32), OUT).eval()
    print("evaluating TUNED weights...")
    tuned_rows, tuned_rw = evaluate(tuned, tok, prompts)

    summary = {
        "base_model": MODEL,
        "method": "LoRA SFT on user-edited targets (parametric continual learning)",
        "eval": "held-out prompts, NO in-context rules, NO refine loop -- weights only",
        "base_reward": round(mean(base_rw), 3),
        "tuned_reward": round(mean(tuned_rw), 3),
        "base_reward_email": round(mean(base_rw, "email"), 3),
        "tuned_reward_email": round(mean(tuned_rw, "email"), 3),
        "base_reward_slack": round(mean(base_rw, "slack"), 3),
        "tuned_reward_slack": round(mean(tuned_rw, "slack"), 3),
        "base_rows": base_rows, "tuned_rows": tuned_rows,
    }
    with open(os.path.join(ART, "results.json"), "w") as f:
        json.dump(summary, f, indent=2)

    try:
        from chart import svg_bars
        svg_bars(["base weights", "tuned weights"],
                 [summary["base_reward"], summary["tuned_reward"]],
                 os.path.join(ART, "weights-bars.svg"),
                 title="Parametric learning: base vs LoRA-tuned weights (held-out)")
    except Exception as e:  # chart import is best-effort
        print("chart skipped:", e)

    _md(summary)
    print("\n" + "=" * 56)
    print("PARAMETRIC RESULT (weights only -- no context, no refine)")
    print("=" * 56)
    print(f"  base  weights reward: {summary['base_reward']:.2f}  "
          f"(email {summary['base_reward_email']:.2f}, slack {summary['base_reward_slack']:.2f})")
    print(f"  tuned weights reward: {summary['tuned_reward']:.2f}  "
          f"(email {summary['tuned_reward_email']:.2f}, slack {summary['tuned_reward_slack']:.2f})")
    print(f"  artifacts: {ART}/results.json , weights-bars.svg")


def _md(s):
    L = [f"# Parametric continual learning — tuned weights vs base\n",
         f"- **Base model:** `{s['base_model']}`",
         f"- **Method:** {s['method']}",
         f"- **Eval:** {s['eval']}", "",
         "| Weights | held-out reward | email | slack |",
         "|---|---|---|---|",
         f"| base | **{s['base_reward']:.2f}** | {s['base_reward_email']:.2f} | {s['base_reward_slack']:.2f} |",
         f"| **LoRA-tuned** | **{s['tuned_reward']:.2f}** | {s['tuned_reward_email']:.2f} | {s['tuned_reward_slack']:.2f} |",
         "", "![weights](weights-bars.svg)", "",
         "## Sample generations (held-out, weights only)", ""]
    for b, t in zip(s["base_rows"], s["tuned_rows"]):
        L.append(f"### [{b['context']}] {b['prompt']}")
        L += [f"**base (r={b['reward']:.2f}, {b['satisfied']}):**", "```", b["text"][:600], "```",
              f"**tuned (r={t['reward']:.2f}, {t['satisfied']}):**", "```", t["text"][:600], "```", ""]
    with open(os.path.join(ART, "results.md"), "w") as f:
        f.write("\n".join(L))


if __name__ == "__main__":
    main()

"""LoRA fine-tuning on user-edited targets -- the parametric 'Learn' path.

This is the piece that makes the WEIGHTS learn the user's preferences, not just
a context window. We SFT a small instruct model on the `chosen` (edited) drafts
with completion-only masking, using LoRA so it trains on CPU. After this, the
tuned model should produce the user's style from a plain prompt with NO rules in
context and NO refinement -- because the preference now lives in the weights.

Small + CPU on purpose: this is a playground proof of the mechanism, not a
frontier run. Scale the same recipe up and it is exactly the parametric half of
what a continual-learning platform does.
"""

from __future__ import annotations

import json
import os

import torch
from peft import LoraConfig, get_peft_model
from transformers import AutoModelForCausalLM, AutoTokenizer

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.environ.get("BASE_MODEL", "HuggingFaceTB/SmolLM2-135M-Instruct")
OUT = os.environ.get("ADAPTER_DIR", os.path.join(HERE, "out"))
SYSTEM = "You are a writing assistant. Write the requested message."

torch.manual_seed(0)
torch.set_num_threads(max(1, os.cpu_count() or 4))


def encode(tok, prompt, target, max_len=256):
    msgs_p = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]
    msgs_f = msgs_p + [{"role": "assistant", "content": target}]
    p_text = tok.apply_chat_template(msgs_p, tokenize=False, add_generation_prompt=True)
    f_text = tok.apply_chat_template(msgs_f, tokenize=False, add_generation_prompt=False)
    p_ids = tok(p_text, add_special_tokens=False)["input_ids"]
    f_ids = tok(f_text, add_special_tokens=False)["input_ids"][:max_len]
    labels = list(f_ids)
    for i in range(min(len(p_ids), len(f_ids))):
        labels[i] = -100
    return f_ids, labels


def collate(batch, pad_id):
    m = max(len(x[0]) for x in batch)
    ids, labs, att = [], [], []
    for f, l in batch:
        pad = m - len(f)
        ids.append(f + [pad_id] * pad)
        labs.append(l + [-100] * pad)
        att.append([1] * len(f) + [0] * pad)
    return (torch.tensor(ids), torch.tensor(labs), torch.tensor(att))


def main(epochs=int(os.environ.get("EPOCHS", "6")), bs=4, lr=2e-4):
    tok = AutoTokenizer.from_pretrained(MODEL)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(MODEL, torch_dtype=torch.float32)
    lora = LoraConfig(r=16, lora_alpha=32, lora_dropout=0.05, bias="none",
                      task_type="CAUSAL_LM",
                      target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                      "gate_proj", "up_proj", "down_proj"])
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()
    model.train()

    rows = [json.loads(l) for l in open(os.path.join(HERE, "train.jsonl"))]
    data = [encode(tok, r["prompt"], r["chosen"]) for r in rows]

    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=lr)
    pad_id = tok.pad_token_id
    step = 0
    for ep in range(epochs):
        torch.manual_seed(ep)
        idx = torch.randperm(len(data)).tolist()
        total = 0.0
        for i in range(0, len(idx), bs):
            batch = [data[j] for j in idx[i:i + bs]]
            ids, labs, att = collate(batch, pad_id)
            out = model(input_ids=ids, attention_mask=att, labels=labs)
            out.loss.backward()
            torch.nn.utils.clip_grad_norm_(
                [p for p in model.parameters() if p.requires_grad], 1.0)
            opt.step(); opt.zero_grad()
            total += out.loss.item(); step += 1
        print(f"epoch {ep+1}/{epochs}  avg_loss={total/((len(idx)+bs-1)//bs):.4f}  steps={step}",
              flush=True)

    os.makedirs(OUT, exist_ok=True)
    model.save_pretrained(OUT)
    tok.save_pretrained(OUT)
    print(f"saved LoRA adapter to {OUT}")


if __name__ == "__main__":
    main()

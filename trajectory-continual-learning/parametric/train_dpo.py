"""DPO fine-tuning on (chosen, rejected) edit pairs -- the preference path.

Where train_sft.py imitates the edited target, DPO learns the *preference*: make
the edited (chosen) draft more likely than the original (rejected) one. This is
the objective the non-parametric miner already exports pairs for
([DPO, Rafailov et al. 2023](https://arxiv.org/abs/2305.18290)).

Implemented from scratch (no trl) and CPU-friendly: a single PEFT model serves as
both policy (adapter on, with grad) and reference (adapter disabled, no grad), so
we never hold two copies of the weights.
"""

from __future__ import annotations

import json
import os

import torch
import torch.nn.functional as F
from peft import LoraConfig, get_peft_model
from transformers import AutoModelForCausalLM, AutoTokenizer

from train_sft import encode  # reuse the chat-template encoder

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.environ.get("BASE_MODEL", "HuggingFaceTB/SmolLM2-135M-Instruct")
OUT = os.environ.get("ADAPTER_DIR", os.path.join(HERE, "out_dpo"))
BETA = float(os.environ.get("DPO_BETA", "0.1"))

torch.manual_seed(0)
torch.set_num_threads(max(1, os.cpu_count() or 4))


def seq_logp(model, ids, labels, att):
    """Sum of log-probs over the completion tokens (labels != -100)."""
    out = model(input_ids=ids, attention_mask=att)
    logp = F.log_softmax(out.logits[:, :-1, :], dim=-1)
    tgt = labels[:, 1:]
    mask = (tgt != -100)
    gathered = logp.gather(-1, tgt.clamp(min=0).unsqueeze(-1)).squeeze(-1)
    return (gathered * mask).sum(dim=-1)


def pad_pair(enc, pad_id):
    f, l = enc
    return f, l


def collate2(encs, pad_id):
    m = max(len(f) for f, _ in encs)
    ids, labs, att = [], [], []
    for f, l in encs:
        p = m - len(f)
        ids.append(f + [pad_id] * p)
        labs.append(l + [-100] * p)
        att.append([1] * len(f) + [0] * p)
    return torch.tensor(ids), torch.tensor(labs), torch.tensor(att)


def main(epochs=int(os.environ.get("EPOCHS", "5")), accum=4, lr=1e-4):
    tok = AutoTokenizer.from_pretrained(MODEL)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(MODEL, dtype=torch.float32)
    model = get_peft_model(model, LoraConfig(
        r=16, lora_alpha=32, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"]))
    model.print_trainable_parameters()
    model.train()

    rows = [json.loads(l) for l in open(os.path.join(HERE, "train.jsonl"))]
    chosen = [encode(tok, r["prompt"], r["chosen"]) for r in rows]
    rejected = [encode(tok, r["prompt"], r["rejected"]) for r in rows]
    pad_id = tok.pad_token_id

    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=lr)
    for ep in range(epochs):
        torch.manual_seed(ep)
        idx = torch.randperm(len(rows)).tolist()
        tot, acc_n, accloss = 0.0, 0, 0.0
        opt.zero_grad()
        for step, j in enumerate(idx, 1):
            ci, cl, ca = collate2([chosen[j]], pad_id)
            ri, rl, ra = collate2([rejected[j]], pad_id)
            # reference logprobs: adapter disabled, no grad
            with torch.no_grad(), model.disable_adapter():
                ref_c = seq_logp(model, ci, cl, ca)
                ref_r = seq_logp(model, ri, rl, ra)
            # policy logprobs: adapter on, with grad
            pol_c = seq_logp(model, ci, cl, ca)
            pol_r = seq_logp(model, ri, rl, ra)
            logits = BETA * ((pol_c - ref_c) - (pol_r - ref_r))
            loss = -F.logsigmoid(logits).mean() / accum
            loss.backward()
            accloss += loss.item() * accum
            if step % accum == 0 or step == len(idx):
                torch.nn.utils.clip_grad_norm_(
                    [p for p in model.parameters() if p.requires_grad], 1.0)
                opt.step(); opt.zero_grad()
            tot += accloss; accloss = 0.0; acc_n += 1
        print(f"epoch {ep+1}/{epochs}  avg_dpo_loss={tot/acc_n:.4f}", flush=True)

    os.makedirs(OUT, exist_ok=True)
    model.save_pretrained(OUT)
    tok.save_pretrained(OUT)
    print(f"saved DPO LoRA adapter to {OUT}")


if __name__ == "__main__":
    main()

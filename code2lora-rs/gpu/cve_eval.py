#!/usr/bin/env python3
"""Evaluate base vs repo-LoRA on the REAL CVE before/after dataset (cve_dataset.json).

Per CVE fix-commit pair:
  vuln (before-fix)  -> should be classified VULN  (true-positive if so)
  safe (after-fix)   -> should be classified SAFE  (false-positive if flagged VULN)

The after-fix code often still *contains* the dangerous sink but is safe because
the fix added the repo's own sanitizer (defined elsewhere in the repo). A per-repo
LoRA trains on the repo-context blob (which includes that sanitizer's definition,
NOT the eval functions) — testing whether repo knowledge clears the real fix
without missing the real vuln.

Reports base vs repo-LoRA: false-positive rate, true-positive rate, accuracy.
"""
import json, os


def run():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import LoraConfig, get_peft_model

    BASE = os.environ.get("VULN_BASE", "Qwen/Qwen2.5-Coder-1.5B")
    STEPS = int(os.environ.get("CVE_STEPS", "60"))
    LR = float(os.environ.get("CVE_LR", "2e-4"))
    MAXLEN = int(os.environ.get("CVE_MAXLEN", "1024"))
    DEV = "cuda"
    def log(*a): print(*a, flush=True)

    here = os.path.dirname(os.path.abspath(__file__))
    data = json.load(open(os.path.join(here, "cve_dataset.json")))
    log(f"CVE eval: {len(data)} repo-commits, "
        f"{sum(len(d['pairs']) for d in data)} before/after pairs, base={BASE}")

    tok = AutoTokenizer.from_pretrained(BASE)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(BASE, torch_dtype=torch.bfloat16).to(DEV)
    model.eval()

    PROMPT = (
        "{code}\n\n"
        "# Security audit of the function above. Does it have an exploitable\n"
        "# injection / RCE / path-traversal vulnerability reachable from untrusted\n"
        "# input? Consider whether any sanitizer makes it safe.\n"
        "# Answer one word: VULN or SAFE.\n# Answer:"
    )
    SAFE_IDS = tok(" SAFE", add_special_tokens=False).input_ids
    VULN_IDS = tok(" VULN", add_special_tokens=False).input_ids

    @torch.no_grad()
    def classify(m, code):
        ids = tok(PROMPT.format(code=code), return_tensors="pt",
                  truncation=True, max_length=MAXLEN).to(DEV)

        def lp(cont):
            cur = ids.input_ids; tot = 0.0
            for t in cont:
                out = m(cur)
                tot += float(torch.log_softmax(out.logits[0, -1].float(), -1)[t])
                cur = torch.cat([cur, torch.tensor([[t]], device=DEV)], 1)
            return tot / max(1, len(cont))
        return "SAFE" if lp(SAFE_IDS) >= lp(VULN_IDS) else "VULN"

    def metrics(preds):
        # preds: list of (gold, pred)
        safe = [(g, p) for g, p in preds if g == "SAFE"]   # after-fix
        vuln = [(g, p) for g, p in preds if g == "VULN"]   # before-fix
        fp = sum(1 for g, p in safe if p == "VULN") / max(1, len(safe))
        tp = sum(1 for g, p in vuln if p == "VULN") / max(1, len(vuln))
        acc = sum(1 for g, p in preds if g == p) / max(1, len(preds))
        return fp, tp, acc, len(safe), len(vuln)

    def train_ctx(m, ctx):
        cfg = LoraConfig(r=16, lora_alpha=32, lora_dropout=0.0, bias="none",
                         target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                         "gate_proj", "up_proj", "down_proj"],
                         task_type="CAUSAL_LM")
        pm = get_peft_model(m, cfg); pm.train()
        opt = torch.optim.AdamW([p for p in pm.parameters() if p.requires_grad], lr=LR)
        enc = tok(ctx, return_tensors="pt", truncation=True, max_length=2048).to(DEV)
        for _ in range(STEPS):
            out = pm(input_ids=enc.input_ids, attention_mask=enc.attention_mask,
                     labels=enc.input_ids)
            opt.zero_grad(); out.loss.backward(); opt.step()
        pm.eval()
        return pm

    base_preds, lora_preds = [], []
    for di, d in enumerate(data):
        items = []
        for pr in d["pairs"]:
            items.append(("VULN", pr["vuln"]))
            items.append(("SAFE", pr["safe"]))
        for gold, code in items:
            base_preds.append((gold, classify(model, code)))
        if d.get("context"):
            pm = train_ctx(model, d["context"])
            for gold, code in items:
                lora_preds.append((gold, classify(pm, code)))
            model = pm.unload()
        else:
            for gold, code in items:
                lora_preds.append((gold, classify(model, code)))
        if di < 2:
            log(f"  [{d['repo']}] {len(d['pairs'])} pairs, ctx={len(d.get('context',''))}c")

    b = metrics(base_preds); l = metrics(lora_preds)
    log("\n================  REAL CVE before/after — base vs repo-LoRA  ================")
    log(f"  pairs: {b[3]} SAFE(after-fix) / {b[4]} VULN(before-fix)")
    log(f"  {'':18s}{'base':>10s}{'repo-LoRA':>12s}")
    log(f"  {'false-pos rate':18s}{b[0]:>9.0%}{l[0]:>12.0%}   (real fixes flagged VULN; LOWER better)")
    log(f"  {'true-pos rate':18s}{b[1]:>9.0%}{l[1]:>12.0%}   (real vulns caught; HIGHER better)")
    log(f"  {'accuracy':18s}{b[2]:>9.0%}{l[2]:>12.0%}")
    return {"base": {"fp": b[0], "tp": b[1], "acc": b[2]},
            "repo_lora": {"fp": l[0], "tp": l[1], "acc": l[2]},
            "n_safe": b[3], "n_vuln": b[4]}


if __name__ == "__main__":
    print(run())

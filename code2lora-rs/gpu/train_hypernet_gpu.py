#!/usr/bin/env python3
"""Train the Code2LoRA-Static hypernetwork THROUGH a frozen base LLM (GPU).

Closes the core gap: show that a LoRA adapter *generated in one forward pass*
from a repository embedding (no per-repo training) improves a real model on
held-out, cross-repo assertion completion.

Pipeline:
  * frozen base = Qwen/Qwen2.5-Coder-1.5B; LoRA injected on q,k,v,o,gate,up,down,
    shared across layers, values produced by a trainable hypernetwork H(e_repo).
  * repo embedding e_repo = mean-pooled base-model hidden states over sampled
    non-test source (no extra model to download).
  * train: sample a repo, H(e)->LoRA, run a batch of that repo's assertion QnAs
    through base+LoRA, cross-entropy on the target, backprop into H only.
  * eval (cross-repo, held-out): H(e)->LoRA in one pass, measure assertion EM
    with the generated adapter vs the bare base model.

Run on the GPU box (drives itself): clones data repos, mines tasks, trains, evals.
"""
import os, re, sys, glob, random, subprocess, math
import torch, torch.nn as nn

BASE = os.environ.get("BASE_MODEL", "Qwen/Qwen2.5-Coder-1.5B")
DEV = "cuda"
DT = torch.bfloat16
RANK = int(os.environ.get("RANK", "8"))
ALPHA = int(os.environ.get("ALPHA", "16"))
STEPS = int(os.environ.get("STEPS", "700"))
BATCH = int(os.environ.get("BATCH", "4"))
LR = float(os.environ.get("LR", "1e-4"))
MAXLEN = 384
MODULES = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]

TRAIN_REPOS = [
    "https://github.com/tkem/cachetools", "https://github.com/keleshev/schema",
    "https://github.com/mahmoud/boltons", "https://github.com/seatgeek/thefuzz",
    "https://github.com/jd/tenacity", "https://github.com/cdgriffith/Box",
    "https://github.com/jab/bidict",
]
EVAL_REPOS = [  # held-out, disjoint from train
    "https://github.com/ets-labs/python-dependency-injector",
    "https://github.com/scrapinghub/dateparser",
    "https://github.com/pyeve/cerberus",
]

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tinker"))
import mine_multi  # noqa


def clone(url, dst):
    if not os.path.isdir(dst):
        subprocess.run(["git", "clone", "--depth", "1", url, dst], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return dst


def mine(url, root):
    d = clone(url, os.path.join(root, os.path.basename(url)))
    tasks, seen = [], set()
    for t in mine_multi.mine_repo(d):
        k = (t["prefix"], t["target"])
        if k not in seen and 1 <= len(t["target"]) <= 60:
            seen.add(k); tasks.append(t)
    return d, tasks


def non_test_text(repo_dir, max_files=24, max_chars=1500):
    out = []
    for f in glob.glob(os.path.join(repo_dir, "**", "*.py"), recursive=True):
        if any(s in f for s in ("/test", "tests/", "test_")):
            continue
        try:
            out.append(open(f, encoding="utf-8", errors="ignore").read()[:max_chars])
        except OSError:
            pass
        if len(out) >= max_files:
            break
    return out


# ---- LoRA injection wrapper ----
class LoRALinear(nn.Module):
    def __init__(self, base, mtype, store):
        super().__init__()
        self.base = base            # frozen
        self.mtype = mtype
        self.store = store          # dict mtype -> (A[r,in], B[out,r]) or None
        self.scaling = ALPHA / RANK

    def forward(self, x):
        out = self.base(x)
        ab = self.store.get(self.mtype)
        if ab is None:
            return out
        A, B = ab
        lora = (x.to(A.dtype) @ A.t()) @ B.t()
        return out + self.scaling * lora.to(out.dtype)


def inject(model, store):
    dims = {}
    for layer in model.model.layers:
        for blk, names in (("self_attn", ["q_proj", "k_proj", "v_proj", "o_proj"]),
                           ("mlp", ["gate_proj", "up_proj", "down_proj"])):
            mod = getattr(layer, blk)
            for n in names:
                lin = getattr(mod, n)
                if isinstance(lin, LoRALinear):
                    lin = lin.base
                dims[n] = (lin.in_features, lin.out_features)
                setattr(mod, n, LoRALinear(lin, n, store))
    return dims


# ---- Hypernetwork ----
class HyperNet(nn.Module):
    def __init__(self, in_dim, dims, d_h=512, trunk_h=512):
        super().__init__()
        self.trunk = nn.Sequential(nn.Linear(in_dim, trunk_h), nn.GELU(),
                                   nn.Linear(trunk_h, d_h))
        self.d_h = d_h
        self.headA, self.headB, self.sA, self.sB = (nn.ModuleDict(), nn.ModuleDict(),
                                                    nn.ParameterDict(), nn.ParameterDict())
        for m, (i, o) in dims.items():
            self.headA[m] = nn.Linear(d_h, RANK * i)
            self.headB[m] = nn.Linear(d_h, o * RANK)
            self.sA[m] = nn.Parameter(torch.tensor(-2.0))
            self.sB[m] = nn.Parameter(torch.tensor(-2.0))
        self.dims = dims

    def forward(self, e):
        h = self.trunk(e)
        h = math.sqrt(self.d_h) * torch.nn.functional.normalize(h, dim=-1)
        lora = {}
        for m, (i, o) in self.dims.items():
            A = torch.tanh(self.headA[m](h)).view(RANK, i) * self.sA[m].exp()
            B = torch.tanh(self.headB[m](h)).view(o, RANK) * self.sB[m].exp()
            lora[m] = (A.to(DT), B.to(DT))
        return lora


def normalize(s): return re.sub(r"\s+", " ", s).strip().rstrip(".,;:)")
def em(pred, tgt):
    p, t = normalize(pred), normalize(tgt)
    return bool(t) and (p == t or p.startswith(t))


def main():
    from transformers import AutoModelForCausalLM, AutoTokenizer
    root = "/workspace/data"; os.makedirs(root, exist_ok=True)
    print(f"loading {BASE} ...", flush=True)
    tok = AutoTokenizer.from_pretrained(BASE)
    model = AutoModelForCausalLM.from_pretrained(BASE, torch_dtype=DT).to(DEV).eval()
    for p in model.parameters():
        p.requires_grad_(False)
    store = {}
    dims = inject(model, store)
    print("LoRA dims:", dims, flush=True)

    @torch.no_grad()
    def embed_repo(repo_dir):
        texts = non_test_text(repo_dir)
        if not texts:
            return torch.zeros(model.config.hidden_size, device=DEV, dtype=torch.float32)
        vs = []
        for t in texts:
            ids = tok(t, return_tensors="pt", truncation=True, max_length=512).to(DEV)
            h = model.model(**ids).last_hidden_state
            vs.append(h[0].mean(0).float())
        return torch.stack(vs).mean(0)

    def collate(tasks_b):
        ids, labels = [], []
        for t in tasks_b:
            p = tok(t["prefix"], truncation=True, max_length=MAXLEN - 16).input_ids
            c = tok(t["target"], add_special_tokens=False).input_ids + [tok.eos_token_id]
            seq = p + c
            lab = [-100] * len(p) + c
            ids.append(seq[:MAXLEN]); labels.append(lab[:MAXLEN])
        m = max(len(x) for x in ids)
        pad = tok.pad_token_id or tok.eos_token_id
        att = [[1] * len(x) + [0] * (m - len(x)) for x in ids]
        ids = [x + [pad] * (m - len(x)) for x in ids]
        labels = [x + [-100] * (m - len(x)) for x in labels]
        return (torch.tensor(ids, device=DEV), torch.tensor(att, device=DEV),
                torch.tensor(labels, device=DEV))

    print("mining + embedding repos ...", flush=True)
    train = []
    for url in TRAIN_REPOS:
        d, tk = mine(url, root)
        if len(tk) >= 20:
            train.append((embed_repo(d), tk))
            print(f"  train {os.path.basename(url)}: {len(tk)} tasks", flush=True)
    held = []
    for url in EVAL_REPOS:
        d, tk = mine(url, root)
        if len(tk) >= 10:
            random.Random(0).shuffle(tk)
            held.append((os.path.basename(url), embed_repo(d), tk[:24]))
            print(f"  eval  {os.path.basename(url)}: {len(tk)} tasks", flush=True)
    assert train and held, "not enough data"

    in_dim = model.config.hidden_size
    H = HyperNet(in_dim, dims).to(DEV)
    opt = torch.optim.AdamW(H.parameters(), lr=LR, weight_decay=0.01)

    def set_lora(e):
        for k, v in H(e.to(DEV)).items():
            store[k] = v
    def clear_lora():
        store.clear()

    @torch.no_grad()
    def eval_em(use_hyper):
        H.eval(); tot = cor = 0
        per = []
        for name, e, tasks in held:
            if use_hyper: set_lora(e)
            else: clear_lora()
            c = 0
            for t in tasks:
                ids = tok(t["prefix"], return_tensors="pt", truncation=True, max_length=MAXLEN).to(DEV)
                g = model.generate(**ids, max_new_tokens=12, do_sample=False,
                                   pad_token_id=tok.eos_token_id)
                pred = tok.decode(g[0][ids.input_ids.shape[1]:], skip_special_tokens=True).split("\n")[0]
                c += em(pred, t["target"])
            per.append((name, c / len(tasks))); tot += len(tasks); cor += c
        clear_lora()
        return cor / tot, per

    print("\n=== EVAL: base (no adapter) ===", flush=True)
    base_em, base_per = eval_em(False)
    for n, v in base_per: print(f"  {n}: {v:.1%}")
    print(f"base cross-repo EM: {base_em:.1%}", flush=True)

    print(f"\n=== TRAIN hypernetwork ({STEPS} steps) ===", flush=True)
    H.train()
    for step in range(1, STEPS + 1):
        e, tasks = random.choice(train)
        batch = random.sample(tasks, min(BATCH, len(tasks)))
        set_lora(e)
        ids, att, labels = collate(batch)
        out = model(input_ids=ids, attention_mask=att, labels=labels)
        loss = out.loss
        opt.zero_grad(); loss.backward(); opt.step()
        if step % 50 == 0 or step == 1:
            print(f"  step {step}: loss={loss.item():.4f}", flush=True)

    print("\n=== EVAL: one-pass GENERATED adapter (held-out repos) ===", flush=True)
    gen_em, gen_per = eval_em(True)
    for n, v in gen_per: print(f"  {n}: {v:.1%}")
    print(f"generated-adapter cross-repo EM: {gen_em:.1%}", flush=True)

    print("\n=== RESULT ===", flush=True)
    print(f"  base                       cross-repo EM: {base_em:.1%}")
    print(f"  one-pass generated adapter cross-repo EM: {gen_em:.1%}   (delta {gen_em-base_em:+.1%})")
    print("PROOF: hypernetwork-generated adapters (no per-repo training) improve a "
          "real model on unseen repos." if gen_em > base_em else
          "no improvement at this budget.")


if __name__ == "__main__":
    main()

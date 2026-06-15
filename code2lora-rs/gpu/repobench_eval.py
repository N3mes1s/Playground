#!/usr/bin/env python3
"""Run a REAL public benchmark: RepoBench v1.1 (tianyang/repobench_python_v1.1).

Standard repo-level next-line completion. Retrieval source is the benchmark's own
REAL cross-file snippets from the actual repos (NOT test siblings) — this is the
externally-valid version of the "does repo context help" question.

Conditions (same base model = Qwen2.5-Coder-1.5B), standard metrics
(exact-match + edit-similarity on next_line):
  * in-file only            : prompt = imports + preceding code (no cross-file)
  * + BM25 cross-file (k=1)  : prepend the top BM25-retrieved cross-file snippet
  * + ORACLE cross-file      : prepend the gold cross-file snippet (upper bound)

Official prompt format (RepoBench):
  cross = "# Path: {path}\n{snippet}\n" ... ;  in_file = "# Path: {fp}\n{imports}\n{cropped_code}"
  prompt = cross + in_file
"""
import os, re


def _lev(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def edit_sim(a, b):
    a, b = a.strip(), b.strip()
    m = max(len(a), len(b))
    return 1.0 if m == 0 else 1.0 - _lev(a, b) / m


def run():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from datasets import load_dataset
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from retrieval import BM25, tokenize

    BASE = os.environ.get("VULN_BASE", "Qwen/Qwen2.5-Coder-1.5B")
    SPLIT = os.environ.get("RB_SPLIT", "cross_file_first")
    N = int(os.environ.get("RB_N", "500"))
    MAXLEN = int(os.environ.get("RB_MAXLEN", "1800"))
    MAXNEW = int(os.environ.get("RB_MAXNEW", "48"))
    SNIP_CHARS = int(os.environ.get("RB_SNIP_CHARS", "800"))
    DEV = "cuda"
    def log(*a): print(*a, flush=True)

    tok = AutoTokenizer.from_pretrained(BASE)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(BASE, torch_dtype=torch.bfloat16).to(DEV)
    model.eval(); model.config.use_cache = True

    ds = load_dataset("tianyang/repobench_python_v1.1", split=SPLIT)
    if N and N < len(ds):
        ds = ds.shuffle(seed=0).select(range(N))
    log(f"RepoBench {SPLIT}: {len(ds)} examples, base={BASE}")

    def infile_prompt(d):
        return f"# Path: {d['file_path']}\n{d['import_statement']}\n{d['cropped_code']}"

    def snippet_block(c):
        return f"# Path: {c['path']}\n{c['snippet'][:SNIP_CHARS]}\n"

    @torch.no_grad()
    def gen(prompt):
        # keep the TAIL of the prompt (completion point is at the end)
        ids = tok(prompt, return_tensors="pt").input_ids[0][-MAXLEN:]
        ii = ids.unsqueeze(0).to(DEV)
        g = model.generate(input_ids=ii, attention_mask=torch.ones_like(ii),
                           max_new_tokens=MAXNEW, do_sample=False, pad_token_id=tok.eos_token_id)
        out = tok.decode(g[0][ii.shape[1]:], skip_special_tokens=True)
        return out.split("\n")[0]

    def bm25_pick(d):
        ctx = d["context"]
        if not ctx:
            return None
        bm = BM25([tokenize(c["snippet"]) for c in ctx])
        q = tokenize("\n".join(d["cropped_code"].splitlines()[-30:]))
        scores = bm.scores(q)
        return ctx[max(range(len(ctx)), key=lambda i: scores[i])]

    conds = {"in-file only": 0, "+BM25 cross-file": 0, "+ORACLE cross-file": 0}
    es = {k: 0.0 for k in conds}
    n = 0
    for d in ds:
        gold = (d["next_line"] or "").strip()
        if not gold:
            continue
        n += 1
        infile = infile_prompt(d)
        # in-file only
        p = gen(infile)
        conds["in-file only"] += (p.strip() == gold); es["in-file only"] += edit_sim(p, gold)
        # BM25 retrieved
        bsnip = bm25_pick(d)
        pb = gen(snippet_block(bsnip) + infile) if bsnip else p
        conds["+BM25 cross-file"] += (pb.strip() == gold); es["+BM25 cross-file"] += edit_sim(pb, gold)
        # oracle
        gi = d.get("gold_snippet_index", -1)
        if isinstance(gi, int) and 0 <= gi < len(d["context"]):
            po = gen(snippet_block(d["context"][gi]) + infile)
        else:
            po = pb
        conds["+ORACLE cross-file"] += (po.strip() == gold); es["+ORACLE cross-file"] += edit_sim(po, gold)
        if n % 100 == 0:
            log(f"  ...{n} done")

    log(f"\n================  RepoBench {SPLIT} (n={n})  base={BASE}  ================")
    log(f"  {'condition':22s}{'exact-match':>14s}{'edit-sim':>12s}")
    res = {}
    for k in conds:
        em = conds[k] / max(1, n); e = es[k] / max(1, n)
        res[k] = {"em": em, "edit_sim": e}
        log(f"  {k:22s}{em:>13.1%}{e:>12.1%}")
    return {"split": SPLIT, "n": n, "results": res}


if __name__ == "__main__":
    print(run())

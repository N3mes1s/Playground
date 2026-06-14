#!/usr/bin/env python3
"""Repo-LoRA for vulnerability analysis — does a repo-specialized adapter cut
false positives by learning the codebase's *custom safe wrappers*?

The claim (SECURITY.md): a scanner backed by a repo-LoRA "already knows the
codebase's sinks ... and custom safe wrappers, cutting false positives (it learns
that safe_query() is safe) at zero context tokens."

Controlled test that isolates exactly that mechanism:
  * N synthetic repos, each with a UNIQUE, documented safe-wrapper idiom
    (e.g. repo A: `db_guard(x)` sanitizes before `cursor.execute`; repo B:
    `shell_safe(x)` before `os.system`; ...).
  * Each repo ships a short "context" (the wrapper definition + a doc line stating
    it sanitizes + a safe example) — what a per-repo LoRA trains on.
  * Eval items per repo, each labelled SAFE / VULN:
      - WRAPPER-TRAP (SAFE): `sink(wrapper(user_input))`  -> looks dangerous, is
        safe; a context-free scanner false-positives here.
      - RAW-SINK   (VULN): `sink(user_input)`            -> genuinely vulnerable.
      - controls (constant-safe SAFE; a different raw sink VULN).

We classify with the frozen base model (likelihood of " SAFE" vs " VULN" verdict),
then train a tiny per-repo LoRA on that repo's context and re-classify. Report,
base vs repo-LoRA:
  * FALSE-POSITIVE rate on wrapper-traps (lower = better; the headline),
  * TRUE-POSITIVE rate on raw-sink vulns (must stay high — don't just learn to
    say SAFE),
  * overall accuracy.

Honest by construction: if the repo-LoRA lowers FP *without* dropping TP, repo
specialization helps; if TP collapses, it just learned to rubber-stamp.
"""
from __future__ import annotations
import os, random, itertools

# ---------------------------------------------------------------------------
# Synthetic multi-repo dataset (no deps; inspect with `python vuln_repo_lora.py`)
# ---------------------------------------------------------------------------
SINKS = [
    ("cursor.execute", "SQL query", "sql"),
    ("os.system", "shell command", "cmd"),
    ("subprocess.call", "subprocess", "cmd"),
    ("eval", "dynamic eval", "eval"),
    ("open", "file path", "path"),
    ("render_template_string", "template", "ssti"),
]
WRAPPERS = [
    "db_guard", "shell_safe", "clean_arg", "sanitize_path", "safe_tmpl",
    "escape_sql", "harden", "validate_in", "scrub", "guard_exec", "safe_q", "neutralize",
]
USER_SRCS = ['request.args["id"]', 'request.form["q"]', 'sys.argv[1]',
             'input()', 'req.params["name"]', 'flask.request.values["x"]']


def make_repos(n_repos=12, seed=0):
    rng = random.Random(seed)
    repos = []
    wr = WRAPPERS[:]; rng.shuffle(wr)
    for i in range(n_repos):
        sink, desc, kind = SINKS[i % len(SINKS)]
        wrapper = wr[i % len(wr)]
        sink_call = sink if sink != "eval" else "eval"
        # context the per-repo LoRA trains on: define + document + safe example
        context = (
            f"# project utility module\n"
            f"# {wrapper}() fully sanitizes untrusted input for the {desc} sink.\n"
            f"# It is SAFE to pass {wrapper}(x) directly into {sink_call}.\n"
            f"def {wrapper}(x):\n"
            f"    # strict allow-list sanitization\n"
            f"    return _enforce_policy(x)\n\n"
            f"# canonical safe usage in this codebase:\n"
            f"{sink_call}({wrapper}({rng.choice(USER_SRCS)}))\n"
        )
        # repeat a few safe usages so the idiom is well-represented
        safe_usages = "\n".join(
            f"{sink_call}({wrapper}({rng.choice(USER_SRCS)}))  # SAFE: sanitized by {wrapper}()"
            for _ in range(6)
        )
        # CONTRASTIVE negatives: raw untrusted input into the sink IS a vuln. This
        # teaches the *boundary* (wrapper=safe vs raw=vuln) so the adapter cuts
        # false positives without globally drifting to "everything is SAFE".
        unsafe_usages = "\n".join(
            f"{sink_call}({rng.choice(USER_SRCS)})  # VULN: raw untrusted input, missing {wrapper}()"
            for _ in range(6)
        )
        context = (context + safe_usages + "\n"
                   + f"# WARNING: never pass raw untrusted input into {sink_call} without {wrapper}().\n"
                   + unsafe_usages + "\n")

        items = []
        for _ in range(3):  # wrapper-trap: SAFE (the false-positive test)
            u = rng.choice(USER_SRCS)
            items.append((f"{sink_call}({wrapper}({u}))", "SAFE", "wrapper_trap"))
        for _ in range(3):  # raw sink: VULN (the true-positive test)
            u = rng.choice(USER_SRCS)
            items.append((f"{sink_call}({u})", "VULN", "raw_sink"))
        # controls
        items.append((f'{sink_call}("constant_safe_value")', "SAFE", "const_safe"))
        other_sink = SINKS[(i + 3) % len(SINKS)][0]
        items.append((f"{other_sink}({rng.choice(USER_SRCS)})", "VULN", "other_raw"))
        repos.append({"name": f"repo_{i:02d}_{wrapper}", "wrapper": wrapper,
                      "sink": sink_call, "kind": kind, "context": context, "items": items})
    return repos


PROMPT = (
    "{code}\n\n"
    "# Security audit: does the code above pass untrusted user input into a\n"
    "# dangerous sink WITHOUT sanitization? Answer one word: VULN or SAFE.\n"
    "# Answer:"
)


# ---------------------------------------------------------------------------
# Model side (Modal): classify by verdict likelihood; per-repo LoRA via peft
# ---------------------------------------------------------------------------
def run():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import LoraConfig, get_peft_model

    BASE = os.environ.get("VULN_BASE", "Qwen/Qwen2.5-Coder-1.5B")
    N_REPOS = int(os.environ.get("VULN_REPOS", "12"))
    STEPS = int(os.environ.get("VULN_STEPS", "40"))
    LR = float(os.environ.get("VULN_LR", "2e-4"))
    DEV = "cuda"
    def log(*a): print(*a, flush=True)

    tok = AutoTokenizer.from_pretrained(BASE)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(BASE, torch_dtype=torch.bfloat16).to(DEV)
    model.eval()

    # verdict tokens (leading space variants), compare summed logprob
    def word_ids(w):
        return tok(w, add_special_tokens=False).input_ids
    SAFE_IDS, VULN_IDS = word_ids(" SAFE"), word_ids(" VULN")

    @torch.no_grad()
    def classify(m, code):
        prompt = PROMPT.format(code=code)
        ids = tok(prompt, return_tensors="pt", truncation=True, max_length=512).to(DEV)

        def cont_logprob(cont_ids):
            cur = ids.input_ids
            total = 0.0
            for t in cont_ids:
                out = m(cur)
                lp = torch.log_softmax(out.logits[0, -1].float(), dim=-1)
                total += float(lp[t])
                cur = torch.cat([cur, torch.tensor([[t]], device=DEV)], dim=1)
            return total / max(1, len(cont_ids))
        return "SAFE" if cont_logprob(SAFE_IDS) >= cont_logprob(VULN_IDS) else "VULN"

    def metrics(preds):
        # preds: list of (kind, label, pred)
        traps = [(l, p) for k, l, p in preds if k == "wrapper_trap"]      # all SAFE
        vulns = [(l, p) for k, l, p in preds if k in ("raw_sink", "other_raw")]  # all VULN
        fp = sum(1 for l, p in traps if p == "VULN") / max(1, len(traps))  # SAFE flagged VULN
        tp = sum(1 for l, p in vulns if p == "VULN") / max(1, len(vulns))  # VULN caught
        acc = sum(1 for k, l, p in preds if l == p) / max(1, len(preds))
        return fp, tp, acc

    repos = make_repos(N_REPOS, seed=int(os.environ.get("VULN_SEED", "0")))
    log(f"vuln repo-LoRA test: {len(repos)} repos, base={BASE}, steps/repo={STEPS}")

    base_preds, lora_preds = [], []
    for ri, repo in enumerate(repos):
        # ---- base (no adapter) ----
        for code, label, kind in repo["items"]:
            base_preds.append((kind, label, classify(model, code)))

        # ---- per-repo LoRA: train on the repo's context, then classify ----
        cfg = LoraConfig(r=16, lora_alpha=32, lora_dropout=0.0, bias="none",
                         target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                         "gate_proj", "up_proj", "down_proj"],
                         task_type="CAUSAL_LM")
        peft_model = get_peft_model(model, cfg)
        peft_model.train()
        opt = torch.optim.AdamW([p for p in peft_model.parameters() if p.requires_grad], lr=LR)
        ctx = tok(repo["context"], return_tensors="pt", truncation=True, max_length=512).to(DEV)
        for _ in range(STEPS):
            out = peft_model(input_ids=ctx.input_ids, attention_mask=ctx.attention_mask,
                             labels=ctx.input_ids)
            opt.zero_grad(); out.loss.backward(); opt.step()
        peft_model.eval()
        for code, label, kind in repo["items"]:
            lora_preds.append((kind, label, classify(peft_model, code)))
        # unwrap the LoRA so the next repo starts from the clean base
        model = peft_model.unload()
        if ri == 0:
            log(f"  [sample repo {repo['name']}] wrapper={repo['wrapper']} sink={repo['sink']}")

    b_fp, b_tp, b_acc = metrics(base_preds)
    l_fp, l_tp, l_acc = metrics(lora_preds)
    log("\n================  REPO-LoRA VULN ANALYSIS  ================")
    log(f"  {'':18s}{'base':>10s}{'repo-LoRA':>12s}")
    log(f"  {'false-pos rate':18s}{b_fp:>9.0%}{l_fp:>12.0%}   (wrapper-traps flagged VULN; LOWER better)")
    log(f"  {'true-pos rate':18s}{b_tp:>9.0%}{l_tp:>12.0%}   (real raw-sink vulns caught; HIGHER better)")
    log(f"  {'accuracy':18s}{b_acc:>9.0%}{l_acc:>12.0%}")
    verdict = ("repo-LoRA CUTS false positives while keeping TP"
               if (l_fp < b_fp - 1e-9 and l_tp >= b_tp - 0.05)
               else "no clean win — see TP (did it just learn to say SAFE?)")
    log(f"  => {verdict}")
    return {"base": {"fp": b_fp, "tp": b_tp, "acc": b_acc},
            "repo_lora": {"fp": l_fp, "tp": l_tp, "acc": l_acc}, "verdict": verdict}


if __name__ == "__main__":
    # offline: print one synthetic repo so the construction is inspectable
    r = make_repos(2, 0)[0]
    print("=== sample repo:", r["name"], "===")
    print("--- context (what the repo-LoRA trains on) ---")
    print(r["context"])
    print("--- eval items ---")
    for code, label, kind in r["items"]:
        print(f"  [{label:4s} / {kind:12s}]  {code}")

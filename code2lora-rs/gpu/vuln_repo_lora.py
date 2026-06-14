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
# Disjoint user-input sources for TRAIN vs EVAL so the eval tests generalization
# of the rule (wrapper=safe / raw=vuln) to call sites never seen in training,
# not memorization of exact strings.
USER_SRCS_TRAIN = ['request.args["id"]', 'request.form["q"]', 'sys.argv[1]']
USER_SRCS_EVAL = ['input()', 'req.params["name"]', 'flask.request.values["x"]']


def make_repos(n_repos=12, seed=0):
    rng = random.Random(seed)
    repos = []
    wr = WRAPPERS[:]; rng.shuffle(wr)
    for i in range(n_repos):
        sink, desc, kind = SINKS[i % len(SINKS)]
        wrapper = wr[i % len(wr)]
        sink_call = sink if sink != "eval" else "eval"
        other_sink = SINKS[(i + 3) % len(SINKS)][0]

        # documentation prepended to every training prompt (the wrapper's contract)
        doc = (f"# In this project, {wrapper}() sanitizes untrusted input; it is SAFE "
               f"to pass {wrapper}(x) into {sink_call}.")

        # TRAIN: labelled verdict examples (the repo's documented safe/unsafe call
        # sites) — both classes, using TRAIN sources only.
        train_examples = []
        for u in USER_SRCS_TRAIN:
            train_examples.append((f"{sink_call}({wrapper}({u}))", "SAFE"))    # wrapper -> safe
            train_examples.append((f"{sink_call}({u})", "VULN"))               # raw -> vuln
        train_examples.append((f'{sink_call}("literal")', "SAFE"))             # constant -> safe
        # duplicate for a little more signal
        train_examples = train_examples * 2

        # EVAL: held-out call sites (EVAL sources, never trained on)
        items = []
        for u in USER_SRCS_EVAL:
            items.append((f"{sink_call}({wrapper}({u}))", "SAFE", "wrapper_trap"))
            items.append((f"{sink_call}({u})", "VULN", "raw_sink"))
        items.append((f'{sink_call}("constant_safe_value")', "SAFE", "const_safe"))
        items.append((f"{other_sink}({rng.choice(USER_SRCS_EVAL)})", "VULN", "other_raw"))

        repos.append({"name": f"repo_{i:02d}_{wrapper}", "wrapper": wrapper,
                      "sink": sink_call, "kind": kind, "doc": doc,
                      "train_examples": train_examples, "items": items})
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
    def classify(m, code, doc=""):
        prompt = (doc + "\n" + PROMPT.format(code=code)) if doc else PROMPT.format(code=code)
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

    def build_train_batch(repo):
        # supervised: prompt -> verdict, loss only on the verdict tokens.
        ids_list, lab_list = [], []
        for code, verdict in repo["train_examples"]:
            prompt = repo["doc"] + "\n" + PROMPT.format(code=code)
            p = tok(prompt, add_special_tokens=False).input_ids
            v = tok(" " + verdict, add_special_tokens=False).input_ids + [tok.eos_token_id]
            ids_list.append(p + v)
            lab_list.append([-100] * len(p) + v)
        m = max(len(x) for x in ids_list)
        pad = tok.pad_token_id
        inp = torch.tensor([x + [pad] * (m - len(x)) for x in ids_list], device=DEV)
        att = torch.tensor([[1] * len(x) + [0] * (m - len(x)) for x in ids_list], device=DEV)
        lab = torch.tensor([x + [-100] * (m - len(x)) for x in lab_list], device=DEV)
        return inp, att, lab

    base_preds, lora_preds = [], []
    for ri, repo in enumerate(repos):
        # ---- base (no adapter), WITH the repo's doc line in-context (fair: base
        # gets the same wrapper documentation, just not trained on it) ----
        for code, label, kind in repo["items"]:
            base_preds.append((kind, label, classify(model, code, doc=repo["doc"])))

        # ---- per-repo LoRA: SUPERVISED on labelled verdict examples ----
        cfg = LoraConfig(r=16, lora_alpha=32, lora_dropout=0.0, bias="none",
                         target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                         "gate_proj", "up_proj", "down_proj"],
                         task_type="CAUSAL_LM")
        peft_model = get_peft_model(model, cfg)
        peft_model.train()
        opt = torch.optim.AdamW([p for p in peft_model.parameters() if p.requires_grad], lr=LR)
        inp, att, lab = build_train_batch(repo)
        for _ in range(STEPS):
            out = peft_model(input_ids=inp, attention_mask=att, labels=lab)
            opt.zero_grad(); out.loss.backward(); opt.step()
        peft_model.eval()
        for code, label, kind in repo["items"]:
            lora_preds.append((kind, label, classify(peft_model, code, doc=repo["doc"])))
        model = peft_model.unload()
        if ri == 0:
            log(f"  [sample repo {repo['name']}] wrapper={repo['wrapper']} sink={repo['sink']}  "
                f"final loss={float(out.loss):.3f}")

    b_fp, b_tp, b_acc = metrics(base_preds)
    l_fp, l_tp, l_acc = metrics(lora_preds)
    log("\n================  REPO-LoRA VULN ANALYSIS  ================")
    log(f"  {'':18s}{'base':>10s}{'repo-LoRA':>12s}")
    log(f"  {'false-pos rate':18s}{b_fp:>9.0%}{l_fp:>12.0%}   (wrapper-traps flagged VULN; LOWER better)")
    log(f"  {'true-pos rate':18s}{b_tp:>9.0%}{l_tp:>12.0%}   (real raw-sink vulns caught; HIGHER better)")
    log(f"  {'accuracy':18s}{b_acc:>9.0%}{l_acc:>12.0%}")
    # A clean win = false positives drop meaningfully AND true-positives stay high
    # in ABSOLUTE terms AND accuracy improves. (Comparing TP to a degenerate
    # always-VULN base, whose TP is trivially 100%, would be misleading.)
    verdict = ("repo-LoRA CUTS false positives while keeping TP high"
               if (l_fp < b_fp - 0.1 and l_tp >= 0.8 and l_acc > b_acc + 0.05)
               else "no clean win — see TP (did it just learn to say SAFE?)")
    log(f"  => {verdict}")
    return {"base": {"fp": b_fp, "tp": b_tp, "acc": b_acc},
            "repo_lora": {"fp": l_fp, "tp": l_tp, "acc": l_acc}, "verdict": verdict}


if __name__ == "__main__":
    # offline: print one synthetic repo so the construction is inspectable
    r = make_repos(2, 0)[0]
    print("=== sample repo:", r["name"], "===")
    print("doc:", r["doc"])
    print("--- TRAIN examples (labelled; TRAIN sources) ---")
    for code, verdict in r["train_examples"][:7]:
        print(f"  [{verdict:4s}]  {code}")
    print("--- EVAL items (held-out; EVAL sources) ---")
    for code, label, kind in r["items"]:
        print(f"  [{label:4s} / {kind:12s}]  {code}")

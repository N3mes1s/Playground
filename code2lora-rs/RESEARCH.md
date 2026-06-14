# How to beat Code2LoRA — researched recipe (deep-research synthesis)

Goal: exceed the ~53–55% cross-repo (CR-test) exact-match we reproduced for the
paper's released checkpoint on a fair harness (paper reports 63.8%). Below is a
prioritized, citation-backed plan from a 5-angle web research pass (hypernetwork
LoRA architectures, structured adapters, code encoders, generalization training,
hybrid parametric+retrieval). Confidence flags: ★★★ primary-source + cross-checked,
★★ single strong source, ★ directional.

## What we already established (the starting point)
- Reproduced their layer-shared rank-16 head: ~53–55% CR-test EM on a fair harness;
  our from-scratch training **matches but does not beat** it (~52–53%).
- Our naive **per-layer (FiLM)** head diverged/underperformed (stability + a
  magnitude/expressivity tradeoff).
- **Code2LoRA-Static already matches the per-repo LoRA oracle** (66.2 in-repo vs
  64.0) ★★★ — so beating it needs something *beyond* per-repo fine-tuning quality:
  hybrid retrieval, better conditioning, or test-time refinement.

## Tier 1 — highest expected value (the unexplored gap)
**1. RAFT-trained parametric+retrieval hybrid ("Code2LoRA-Combine").**
Generate the repo adapter **and** prepend ONE small retrieved snippet (most-relevant
signature / nearby assertion), and **train** the adapter with *oracle + distractor*
snippets so it learns to use good hints and ignore noise.
- Evidence: PRAG/DyPRAG **"-Combine"** (adapter + retrieved doc) is the global best,
  beating parametric-alone and RAG-alone by ~1–5pp; on **Qwen2.5-1.5B** Combine 28.9
  vs PRAG 27.1 vs RAG 23.2 ★★ ([DyPRAG 2503.23895](https://arxiv.org/abs/2503.23895)).
  **RAFT** gives **+27–31pp on code/API tasks** by distractor-training the model to
  exploit good context and ignore noise ★★★ ([RAFT 2403.10131](https://arxiv.org/abs/2403.10131)).
- Why it fits: Code2LoRA *never tried the hybrid*, and our pure-RAG loss is exactly
  the "model wasn't trained to use retrieval" failure RAFT fixes.
- Expected: **+2–6pp** over the bar. Risk: needs a retriever + RAFT training; bad
  snippet selection can regress (RAFT mitigates).

## Tier 2 — architecture: do per-layer the *stable* way (fixes our FiLM failure)
**2. Factorized per-(layer,module) generation, Zhyper/T2L-style.**
Shared hypernet conditioned on `[repo_emb ‖ learned layer-emb ‖ learned module-type-emb]`
that emits a **small r×r (or diagonal) modulator between *frozen* LoRA A,B**
(LoRA-XS/Zhyper), not full per-layer A,B.
- Evidence: **Zhyper** ≈ T2L accuracy at **26× fewer params** with **better
  out-of-domain generalization** ★★ ([Zhyper 2510.19733](https://arxiv.org/abs/2510.19733));
  **HyperFormer++** showed shared-trunk + per-(layer,module) *embeddings* matches
  physically-separate per-layer heads (86.48 vs 86.58 GLUE) at ~20× fewer params ★★★
  ([2106.04489](https://aclanthology.org/2021.acl-long.47/)) — i.e. *embeddings*, not
  separate heads, carry per-layer specialization.

**Why our per-layer (FiLM) actually failed — and the 4 exact fixes** ★★★ (triangulated):
1. **Wrong conditioning mechanism.** FiLM is empirically *weaker/less stable* than
   concatenating learned **layer+module embeddings** into the trunk (T2L/Zhyper/
   HyperFormer++ all concat; a conditioning bake-off ranks concat/conditional ≥ FiLM
   ≥ cross-attention for a single vector, [2604.03329]). → replace FiLM with concat.
2. **No zero-init B / Bias-HyperInit.** The adapter must start at ΔW=0 (LoRA Init[A]
   dynamics tolerate larger LR; [Hayou 2406.08447]). T2L's **Bias-HyperInit** (zero
   the output-head *weights*, set bias to standard LoRA init) is *required* — "runs
   often fail" without it ([T2L 2506.06105]). Our head grew log-scales freely → blow-up.
3. **Mis-scaled hypernet output.** Vanilla Xavier/He on a hypernet produces
   wrong-scale generated weights; use **Hyperfan-in/out** (scale to the *mainnet*
   fan-in) ([Chang, ICLR 2020](https://openreview.net/forum?id=H1lma24tPB)).
4. **No rank-stable scaling.** Apply **γ = α/√r (rsLoRA)** to the generated ΔW instead
   of letting the generator learn arbitrary magnitude ([2312.03732]).
Optionally **freeze A, generate only B** (improves calibration; HypeLoRA AfixA) and/or
use **frozen orthogonal aux factors + zero-init trainable factor** (HyperDreamBooth LiDB).
- Why it fits: each fix directly counters one cause of our NaN/0%/blow-up. Frozen-base
  factorization (Zhyper) bounds magnitude; OOD edge = the cross-repo axis.
- Expected: **+1–3pp** and (mainly) stability; risk: amortization gap may leave it ≈ shared.

**2b. Drag-and-Drop LLMs (DnD).** Conv decoder maps a prompt batch → all LoRA weights;
**+30.9pp HumanEval pass@10 on Qwen2.5-1.5B** vs best training LoRA ★★
([DnD 2506.16406](https://arxiv.org/abs/2506.16406)) — but needs a dataset of
(repo → per-repo trained LoRA) pairs (expensive). High ceiling, high effort.

**3. Generate DoRA instead of LoRA.** Emit a per-output-column magnitude vector +
low-rank direction. **+3.4% over LoRA**, +0.01% params, hypernet-cheap ★★★
([DoRA 2402.09353](https://arxiv.org/abs/2402.09353)). Add **rsLoRA `α/√r`** (free)
★★ ([2312.03732](https://arxiv.org/abs/2312.03732)). Expected **+1–3pp**, low risk.

## Tier 3 — conditioning quality (biggest ceiling, needs raw repos)
**4. Better encoder + learned pooling.** Re-embed raw repos with a **code-specialized**
encoder (Qwen3-Embedding-4B 80.1 MTEB-Code, or SFR-Embedding-Code) and aggregate
files with **attention pooling (Set-Transformer PMA, k≈4–8 seeds) + importance
weighting**, not frozen mean+max.
- Evidence: code encoders beat generic by **~10–16 retrieval pts** ★★★
  ([CoIR 2407.02883](https://arxiv.org/abs/2407.02883)); multi-vector/attention
  pooling > single mean+max ★ ([Set Transformer 1810.00825](https://arxiv.org/abs/1810.00825)).
- Caveat: the released dataset ships *frozen* mean+max embeddings, so this requires
  recomputing from RepoPeftBench's raw repos. Expected: potentially the **largest**
  lift (conditioning bounds everything) but pipeline effort + uncertain downstream.

## Tier 4 — cheap training tricks (stack them; fight our early-overfit)
**5.** Keep **end-to-end SFT** (not weight-distillation — T2L shows SFT generalizes
better; if distilling, distill teacher *behavior/outputs*, Doc-to-LoRA, within ~5pp
of oracle) ★★★. Keep **repo-stratified sampling** (sample repo→example) ★★★ (Code2LoRA).
Add (under-explored, low-risk): **embedding dropout/noise + consistency loss**, **EMA
of hypernet weights**, **early-stop on held-out repos**, **checkpoint soup**, **chunk
repos to raise effective task count**, **two-stage warm-start** ★. Expected +1–3pp combined.
**6.** If the amortization gap persists, go **semi-amortized**: a few test-time
refinement steps on the generated adapter ★.

## Bottom line
The single best bet to clear ~55% is **#1 (RAFT-trained hybrid)** — the only approach
with published head-to-head evidence of beating *both* parametric-alone and RAG-alone,
unexplored for Code2LoRA, and it directly fixes our "RAG hurt" result. Stack **#3 (DoRA
+ rsLoRA)** and **#5 (reg tricks)** for cumulative cheap gains; use **#2 (Zhyper-style
per-layer)** for stability + OOD; **#4 (encoder/pooling)** is the high-ceiling but
higher-effort lever. Realistic target: ~53→**58–62%**; beating the paper's *reported*
63.8% likely also needs the full 8192-context eval. Honest risk: each lever is a few
points and not guaranteed; #1 is the highest-probability real beat.

## Sources
Code2LoRA https://arxiv.org/abs/2606.06492 · T2L https://arxiv.org/abs/2506.06105 ·
Zhyper https://arxiv.org/abs/2510.19733 · Generative Adapter https://arxiv.org/abs/2411.05877 ·
DoRA https://arxiv.org/abs/2402.09353 · rsLoRA https://arxiv.org/abs/2312.03732 ·
LoRA-XS https://arxiv.org/abs/2405.17604 · VeRA https://arxiv.org/abs/2310.11454 ·
DyPRAG https://arxiv.org/abs/2503.23895 · PRAG https://github.com/oneal2000/PRAG ·
RAFT https://arxiv.org/abs/2403.10131 · Doc-to-LoRA https://pub.sakana.ai/doc-to-lora/ ·
CoIR https://arxiv.org/abs/2407.02883 · Qwen3-Embedding https://arxiv.org/abs/2506.05176 ·
Set Transformer https://arxiv.org/abs/1810.00825 · LoRA Learns Less https://arxiv.org/abs/2405.09673 ·
AdapterSoup https://arxiv.org/abs/2302.07027 · HyperTuning https://proceedings.mlr.press/v202/phang23a.html

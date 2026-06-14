# Autoresearch: beat Code2LoRA on RepoPeftBench cross-repo EM

## Objective
Improve a hypernetwork that maps a 2048-d repository embedding -> a LoRA adapter
for frozen Qwen2.5-Coder-1.5B, maximizing held-out CROSS-REPO assertion-completion
exact-match (CR-test EM) on the paper's RepoPeftBench data. Baseline to beat: the
released checkpoint scores ~53-55% on our fair harness (paper reports 63.8%); our
from-scratch training matches (~52-53%) but has not beaten it. Each measure run also
reports the released checkpoint's EM on the SAME harness (`their_ckpt`) and `delta`.

## Metrics
- **Primary**: `em` (%, higher better) — generated-adapter CR-test EM. MAXIMIZE.
- **Secondary**: `their_ckpt` (the bar, ~constant), `delta` = em - their_ckpt (>0 means BEAT).

## How to Run
`./.auto/measure.sh` -> emits `METRIC em=<num>` (short Modal H100 run, ~15-25 min, ~$1).
Set `PL=1` for the per-layer head, `PL=0` for shared. Requires MODAL_TOKEN_ID/SECRET
exported in the launching shell.

## Files in Scope (edit these to try ideas)
- `gpu/perlayer.py` — per-layer (FiLM/embedding) head. Primary place to improve.
- `gpu/c2l_gpu.py` — trainer/eval driver (head construction, LR/clamp/scaling, loss).
Read `RESEARCH.md` first — it is the prioritized, cited recipe. `.auto/ideas.md` is the backlog.

## Off Limits (do NOT change — these define the fair benchmark)
- The eval set sampling (`qna_eval_sampled`), the EM definition (`em`), `EVAL_PER_REPO`,
  `MAXLEN`, the their-checkpoint anchor load, and `code2lora-data-snapshots` data paths.
  Changing the harness would invalidate the comparison.

## Strategy (priority order, from RESEARCH.md)
1. Stable per-layer: replace FiLM with concat of learned layer+module embeddings;
   add Bias-HyperInit (zero output-head weights, LoRA-init bias), Hyperfan-in init,
   rsLoRA alpha/sqrt(r). Expected the biggest architecture win + stability.
2. Generate DoRA (LoRA pair + per-output magnitude vector) + rsLoRA.
3. Regularization vs early-overfit: embedding dropout/noise + consistency, EMA of head
   weights, early-stop on best (already saved), weight decay.
4. (bigger) hybrid: prepend one retrieved snippet, RAFT-style train — needs harness work.

## Notes
- Keep changes minimal per experiment so keep/revert is clean.
- `keep` only when `em` improves beyond noise (~±2pp; prefer +3pp to be safe).

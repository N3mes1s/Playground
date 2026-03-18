# Autoresearch Exploration

Analysis and experimentation notes for [karpathy/autoresearch](https://github.com/karpathy/autoresearch) — an autonomous AI agent system that conducts ML research by modifying training code, running 5-minute experiments, and iterating automatically.

## How Autoresearch Works

### Core Loop
```
LOOP FOREVER:
  1. Modify train.py with an experimental idea
  2. git commit
  3. Run: uv run train.py > run.log 2>&1  (5 min fixed budget)
  4. Extract results: grep "^val_bpb:" run.log
  5. If val_bpb improved → keep commit, advance branch
  6. If val_bpb worse → git reset, discard
  7. Log results to results.tsv
```

### Architecture (GPT in train.py)

The model is a single-file GPT implementation with several modern tricks:

| Component | Details |
|-----------|---------|
| **Attention** | Flash Attention 3, RoPE, sliding window (SSSL pattern: 3 short + 1 long) |
| **Value Embeddings** | ResFormer-style: alternating layers get a learned value embedding mixed via input-dependent gating |
| **Normalization** | RMS norm (no bias, no learnable params) |
| **MLP** | ReLU-squared activation (ReGLU variant without gating) |
| **Residual** | Per-layer learnable lambdas: `x = λ_resid * x + λ_x0 * x0` (skip to initial embedding) |
| **Logit softcap** | `15 * tanh(logits / 15)` prevents extreme logits |
| **Optimizer** | MuonAdamW — Muon (polar-express orthogonalization) for matrix params, AdamW for embeddings/scalars |
| **Scheduling** | Time-based (not step-based): warmup → constant → warmdown, with momentum ramp |

### Default Config
- 12 layers, 768 dim, 6 heads, 128 head_dim
- Aspect ratio: dim = depth * 64
- Vocab: 8192 (BPE via rustbpe)
- Sequence length: 2048
- Batch: 524K tokens (128 × 2048 × 2 grad accum)
- 5-minute wall-clock training budget

### Key Design Decisions

1. **Fixed time, not fixed steps** — Experiments always take 5 minutes, so the agent can iterate ~12/hour
2. **Single metric (val_bpb)** — Bits-per-byte is vocab-size-independent, enabling fair comparison across configs
3. **Single file to modify** — `train.py` is the only editable file; `prepare.py` (data/eval) is read-only
4. **Simplicity criterion** — Equal results with less code = win; marginal gain with ugly complexity = not worth it

## Files in This Directory

- `analyze_architecture.py` — CPU-safe model introspection: parameter counts, FLOP estimates, layer analysis
- `experiment_ideas.py` — Generates and evaluates experiment ideas based on the autoresearch codebase patterns

## Relationship to Playground

This Playground is focused on security-oriented LLM research (VulnLLM analyzer, recursive LM auditing). Autoresearch is interesting as a complementary methodology:

- **Autonomous experimentation loop** — The keep/discard pattern with git commits could be applied to security scanner hyperparameter tuning
- **Time-budgeted evaluation** — Fixed 5-min runs ensure experiments don't hang; useful for benchmarking security scanners
- **results.tsv logging** — Simple, reviewable experiment tracking

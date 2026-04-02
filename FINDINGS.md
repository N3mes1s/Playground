# Playground — Research Findings

This document summarizes key findings from experiments conducted in the Playground repository. Two projects pursued the same core methodology — autonomous iterative improvement (autoresearch) — applied to different domains: text compression and security exploit generation.

---

## 1. Autoresearch Compression

### Methodology

A CPU-based stand-in for Karpathy's [autoresearch](https://github.com/karpathy/autoresearch) loop. Instead of training a GPU-based GPT, the system iterates on an n-gram text compressor measured by **bits-per-byte (val_bpb)**. Each experiment runs within a ~10-second CPU budget, and results are kept or discarded based on whether val_bpb improves.

### Results Progression

| Experiment | val_bpb | Delta from Baseline | Status | Description |
|---|---|---|---|---|
| baseline | 1.793 | — | keep | order=3, Laplace smoothing=0.1, backoff=0.4 |
| smooth0 (0.01) | 1.558 | -0.235 | keep | Reduced smoothing from 0.1 to 0.01 |
| smooth0 (0.001) | 1.538 | -0.256 | keep | Reduced smoothing to 0.001 |
| grid_hp | 1.536 | -0.257 | keep | Grid search: smoothing=0.0016, backoff=1.0 |
| kn_o5 | 1.337 | -0.456 | keep | Kneser-Ney smoothing, order=5, discount=0.3 |
| kn_o8 | 1.196 | -0.597 | keep | KN order=8, discount=0.1 |
| kn_o12 | 1.154 | -0.639 | keep | KN order=12, discount=0.1 |
| kn_o15 | 1.150 | -0.643 | keep | KN order=15, discount=0.1 |
| kn_o20 | 1.147 | -0.647 | keep | KN order=20, discount=0.1 (6.5s) |
| ppmkn | 1.133 | -0.660 | keep | PPM-KN hybrid: order=20, discount=0.05, +online (7.6s) |
| **ppmkn2** | **1.129** | **-0.664** | **keep** | PPM-KN: order=22, discount=0.001, +online (7.6s) |

### Score Progression (val_bpb, lower is better)

```
1.793  ████████████████████████████████████████████████████  baseline
1.538  ███████████████████████████████████████████▌          tuned smoothing (-14.2%)
1.337  ████████████████████████████████████▊                 KN order=5 (-25.4%)
1.147  ████████████████████████████████▍                     KN order=20 (-36.0%)
1.129  ████████████████████████████████                      PPM-KN+Online (-37.1%)
```

### Key Findings

1. **Kneser-Ney smoothing was the breakthrough.** Laplace smoothing degraded badly at high n-gram orders (order=7 scored 4.126 — worse than baseline). KN's recursive backoff distribution unlocked orders 5-20, dropping val_bpb from 1.536 to 1.147.

2. **Higher orders failed with Laplace, thrived with KN.** Every attempt at order > 3 with Laplace smoothing was discarded. With KN, performance improved monotonically up to order=20.

3. **Three stacked innovations drove the final result:**
   - Recursive KN backoff (replaced flat Laplace)
   - Online adaptation (PPM-style incremental updates)
   - Ultra-low discount (0.001 — aggressive trust in observed counts)

4. **37.1% total improvement** from baseline (1.793 to 1.129), all within the 10-second CPU budget.

### Failed Experiments

| Experiment | val_bpb | Why It Failed |
|---|---|---|
| order=4–7 (Laplace) | 2.24–4.13 | Laplace smoothing over-smooths sparse high-order counts |
| order=5–8 + low smooth | 1.95–3.24 | Still Laplace-based; reducing alpha helped but not enough |
| backoff weight sweeps | ~1.793 | Backoff weight had near-zero impact at order=3 |

---

## 2. RLM Exploit Writer

### Methodology

A DSPy-based autonomous exploit generation system. Given vulnerable source code and a CVE description, the pipeline generates a working exploit. DSPy's Recursive Language Model (RLM) module iteratively self-improves the exploit across N iterations. An automated evaluation rubric scores outputs on a 100-point scale across four categories.

### Evaluation Rubric

| Category | Points | What It Checks |
|---|---|---|
| Payload correctness | 40 | `must_contain` keywords (60%) + `payload_keywords` (40%) |
| Completeness | 25 | Delivery mechanism, code block, expected output, impact |
| Specificity | 20 | Correct exploit type, target field/parameter, correct impact |
| Practicality | 15 | Length, actual payload strings, references to source code |

### Results Progression (50-case scaled evaluation)

| Phase | Experiment | Score | Delta | Status | Description |
|---|---|---|---|---|---|
| **1** | baseline | 74.5 | — | keep | Claude Sonnet, chained pipeline, temp=0.7, iter=15 |
| **1** | struct_gen | 76.9 | +2.4 | keep | Structured output matching scorer criteria |
| **1** | pipe_3step | 79.6 | +5.1 | keep | Added PayloadRefiner as 3rd pipeline step |
| **2** | rlm_enh | 81.0 | +6.5 | keep | Switched to RLM with enhanced prompts |
| **2** | rlm_iter8 | 82.4 | +7.9 | keep | 8 iterations (sweet spot) |
| **3** | temp_06 | 87.1 | +12.6 | keep | Temperature 0.6 (20-case eval) |
| **4** | rlm_refine | **87.3** | **+12.8** | keep | RLM + PayloadRefiner post-pass |
| **4** | per_cwe | **87.3** | **+12.8** | keep | Per-CWE specialized prompts |

### Score Progression

```
74.5  ████████████████████████████████████▌                     baseline
76.9  █████████████████████████████████████▊                    struct_gen (+2.4)
79.6  ███████████████████████████████████████▊                  pipe_3step (+5.1)
81.0  ████████████████████████████████████████▌                 rlm_enh (+6.5)
82.4  █████████████████████████████████████████▏                rlm_iter8 (+7.9)
87.1  ████████████████████████████████████████████▌             temp_06 (+12.6)
87.3  ████████████████████████████████████████████▋             rlm_refine (+12.8)
```

### Contribution Breakdown

| Change Type | Points Gained | Category |
|---|---|---|
| RLM self-improvement loop | +6.5 | Architecture |
| PayloadRefiner pipeline step | +5.1 | Architecture |
| Temperature tuning (0.7 → 0.6) | +4.7 | Hyperparameter |
| Structured output format | +2.4 | Prompt engineering |
| Iteration count (15 → 8) | +1.4 | Hyperparameter |
| Per-CWE prompts / refinement | +0.2 | Prompt engineering |

### Key Findings

1. **Architecture > prompt engineering.** Structural changes (RLM +6.5, PayloadRefiner +5.1) delivered 11.6 points combined. Prompt engineering alone contributed at most +2.4.

2. **RLM iteration count has a sharp optimum.** 8 iterations was optimal — 15 was wasteful (slower, no quality gain), 5 was insufficient, 10 timed out at the higher quality level. There is a clear convergence curve.

3. **Temperature 0.6 is the sweet spot.** 0.3 caused crashes (too deterministic). 0.55 scored 86.4. 0.6 scored 87.1. 0.65+ timed out. The margin is narrow.

4. **Ceiling near 87.3.** Three different approaches (rlm_refine, per_cwe, combined) all converged to 87.2–87.3. Further gains likely require changing the evaluation rubric or using a stronger base model.

5. **Enhanced prompts alone did nothing.** The `enh_analyzer` experiment (enhanced VulnAnalyzer prompts) scored exactly 74.5 — identical to baseline. `combined_v2` (both enhanced prompts) scored 74.7. Prompt wording without structural changes was near-useless.

### CWE Coverage & Difficulty

The system was evaluated across 20 CWE categories. Hardest categories identified for future work:

| CWE | Category | Difficulty |
|---|---|---|
| CWE-327 | Broken Cryptography | Hard — payloads are algorithmic, not injectable |
| CWE-611 | XML External Entities (XXE) | Hard — requires precise XML entity syntax |
| CWE-367 | Race Conditions (TOCTOU) | Hard — timing-dependent, no single payload |
| CWE-862 | Missing Authorization | Hard — logic flaws, not injection-based |

### Final Configuration

| Parameter | Value |
|---|---|
| Model | claude-sonnet-4-20250514 |
| Temperature | 0.6 |
| Max tokens | 8,000 |
| RLM iterations | 8 |
| Exploit strategy | aggressive |
| Pipeline | VulnAnalyzer → ExploitGenerator → PayloadRefiner → RLM loop |

### Failed Experiments (Notable)

| Experiment | Score | Why It Failed |
|---|---|---|
| rlm_t03 | 0.0 | Temperature 0.3 too deterministic — crashed on edge cases |
| rlm_fast | 21.1 | Scorer-aligned prompt + iter=8 — scoring logic broke |
| tok_12k | 85.0 | 12k tokens made outputs verbose without improving payloads |
| prompt_v2 (10-case) | 0.0 | Enhanced vuln analysis prompt — timed out at 600s |

---

## 3. Cross-Cutting Insights

### The Autoresearch Pattern Works

Both projects used the same core loop: modify code, evaluate against a fixed metric, keep improvements, discard regressions. This pattern proved effective in two very different domains — n-gram compression and LLM-based exploit generation.

### Algorithmic Changes Dominate Parameter Tuning

| Project | Algorithmic/Structural Gain | Parameter Tuning Gain |
|---|---|---|
| Compression | KN smoothing: -0.389 bpb (21.7%) | Smoothing alpha sweep: -0.257 bpb (14.3%) |
| Exploits | RLM + PayloadRefiner: +11.6 pts | Temp + iterations: +6.1 pts |

In both projects, changing the algorithm or architecture delivered roughly 2x the improvement of tuning hyperparameters.

### Small Improvements Compound

| Project | Num. Kept Experiments | Total Improvement |
|---|---|---|
| Compression | 11 | 37.1% (1.793 → 1.129 bpb) |
| Exploits | 7 | 17.2% (74.5 → 87.3 score) |

No single experiment delivered more than a 7.2% relative improvement. The gains came from stacking many small wins — the hallmark of iterative research.

### Diminishing Returns Are Real

Both projects hit apparent ceilings:
- **Compression:** Last three KN experiments (order 15, 20, PPM-KN) improved by only 0.021 bpb combined
- **Exploits:** Last three experiments (temp_06, rlm_refine, per_cwe) improved by only 0.2 points combined

Breaking through these ceilings likely requires a fundamentally different approach — different smoothing families for compression, different evaluation rubrics or base models for exploits.

### Keep/Discard Ratio

| Project | Total Experiments | Kept | Discarded/Crashed | Keep Rate |
|---|---|---|---|---|
| Compression | 27 | 11 | 16 | 40.7% |
| Exploits | 31 | 7 | 24 | 22.6% |

The compression project had a higher keep rate because the search space was more structured (ordered parameters). The exploit project had more crashes and timeouts due to the complexity of LLM-based generation.

---

## 4. Dataset & Infrastructure

### Exploit Writer Dataset

- **10 original cases**: Hand-written across SQL injection, XSS, path traversal, deserialization, SSRF, JWT confusion, command injection
- **10 hard cases**: More complex vulnerability patterns
- **2,600+ scaled cases**: LLM-generated across 20 CWE categories via a multi-agent pipeline (CVE Fetcher → Vuln Code Generator → Language Mutator)
- **Languages covered**: Python, Node.js, Java, Go, Ruby, PHP

### Compression Dataset

- Standard text compression benchmark evaluated by bits-per-byte (val_bpb)
- CPU-only execution within 10-second wall-clock budget

---

## 5. Future Directions

### Compression
- Explore PPM* (unbounded context) or neural-augmented n-gram hybrids
- Test on larger/diverse corpora beyond the current benchmark

### Exploit Writer
- Validate best config on the full 2,600-case dataset (experiments used 20–50 case subsets)
- Try Claude Opus as the base model — all experiments used Sonnet
- Apply DSPy optimizers (MIPROv2, BootstrapFewShot) for automatic prompt tuning
- Revise the evaluation rubric — the 87.3 ceiling may reflect metric saturation rather than a true quality limit

### Methodology
- Apply the autoresearch loop to other Playground projects (e.g., VulnLLM analyzer hyperparameter tuning)
- Build a shared experiment tracking infrastructure across projects

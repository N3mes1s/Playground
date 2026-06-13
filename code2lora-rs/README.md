# code2lora-rs

A Rust implementation of **Code2LoRA** — *Hypernetwork-Generated Adapters for
Code Language Models under Software Evolution* (Hotsko, Li, Deng, Nie, U. Waterloo;
[arXiv:2606.06492](https://arxiv.org/pdf/2606.06492)).

> **Goal of this experiment:** point it at a GitHub repository, and it becomes a
> LoRA adapter you can attach to a frozen base LLM — with *zero* inference-time
> token overhead. The repository's knowledge is pushed into adapter parameters
> by a single hypernetwork forward pass, not injected as long RAG context.

```
   GitHub repo ──▶ repository encoder ──▶ hypernetwork ──▶ LoRA adapter ──▶ frozen base LLM
                   (R^2048 embedding)      (one forward pass)  (PEFT format)   (Qwen2.5-Coder-1.5B)
```

## What the paper does (and what's here)

Code2LoRA has three components; **only the hypernetwork is trained**, the encoder
and base LLM are frozen (paper §3):

| Paper component | Where | Notes |
|---|---|---|
| **Repository encoder** (§3.1) | [`src/embedder.rs`](src/embedder.rs) | chunk files (4096-tok / 512 overlap) → embed → mean-pool per file → importance-weight (distinctiveness · size · path) → `e = [weighted_mean ; max_pool] ∈ R^2048` |
| **Code2LoRA-Static hypernetwork** (§3.2) | [`src/hypernet.rs`](src/hypernet.rs) | 2-layer GELU trunk → `h = √d_h · L2Norm(MLP(e))` → per-module-type heads `A=tanh(HeadA)·exp(sᴬ)`, `B=tanh(HeadB)·exp(sᴮ)`, rank 16, α 32, log-scale init −3.5, shared across all layers |
| **Target model spec** | [`src/model.rs`](src/model.rs) | exact Qwen2.5-Coder-1.5B dims; or load any model's `config.json` |
| **PEFT export** | [`src/lora.rs`](src/lora.rs) | replicates the shared `(A,B)` across all 28 layers → `adapter_config.json` + `adapter_model.safetensors` |
| **RepoPeftBench task** (§4) | [`tinker/mine_assertions.py`](tinker/mine_assertions.py) | mines assertion-completion tasks from a repo's test suite |

The hypernetwork's seven projection heads hold ~675M of the paper's "~720M
trainable parameters". Rather than materialize them on CPU, they are **streamed
deterministically from the seed** — i.e. this is the network *at initialization*
(log-scale −3.5 ⇒ small, near-identity adapters, exactly the paper's init).
Training those parameters is the one GPU-bound step; the Tinker harness below
stands in for it on a live model. `Code2LoRA-Evo` (the GRU-over-commit-diffs
variant, §3.3) is described in the paper for evolving repos; the encoder here
already produces the per-snapshot embeddings it consumes — wiring the recurrence
is the natural next step.

## Two layers of proof

**1. Offline, GPU-free (runs anywhere, in CI):** the generated artifact is a
structurally valid PEFT adapter *for the real model*, it round-trips, it is
reproducible, and it is genuinely **conditioned on the repository**.

```bash
cargo build --release
./target/release/code2lora info                                  # real Qwen2.5-Coder-1.5B dims + param counts
./target/release/code2lora generate --repo examples/sample_repo --out /tmp/adapter
./target/release/code2lora verify   --adapter /tmp/adapter        # shape-match vs real config, finite, near-identity
cargo test --release                                             # 4 proofs (see below)
```

`tests/integration.rs` proves:
- **`shapes_match_real_model`** — every one of the 392 tensors (28 layers × 7
  module types × {A,B}) matches Qwen2.5-Coder-1.5B's real projection dims.
- **`weights_finite_and_near_identity`** — all finite, max |w| < 0.5 at init.
- **`deterministic_same_repo_same_adapter`** — same repo+seed ⇒ identical bytes.
- **`conditioned_different_repos_differ`** — different repos ⇒ different adapters
  (the whole point: the adapter actually encodes the repository).

Target any model by passing its `config.json`:
```bash
./target/release/code2lora generate --repo <path> --out /tmp/a --config /path/to/config.json
```

**2. Live on a modern June-2026 model (Tinker, real GPU):** Tinker can't ingest
an externally-generated hypernetwork adapter, so the live harness demonstrates
the *loop the hypernetwork amortizes* — turn a repo into a LoRA on
`Qwen/Qwen3.5-4B` and show measurable adaptation (this is the paper's "Per-repo
LoRA" reference). See [`tinker/`](tinker/).

```bash
pip install -r tinker/requirements.txt
export TINKER_API_KEY=...
cd tinker
python run_tinker.py --github https://github.com/tkem/cachetools \
    --max-train 32 --max-test 16 --epochs 3
# optionally: --export /tmp/peft_adapter   (downloads the trained PEFT adapter)
```

It mines assertion tasks, measures base-model exact-match, trains a
repo-specific LoRA, and re-measures.

### Live result (Qwen3.5-4B, repo = `tkem/cachetools`)

Real run via the Tinker API (`--max-train 48 --max-test 24 --epochs 4`, rank 16):

| | exact-match on held-out assertions |
|---|---|
| frozen base `Qwen/Qwen3.5-4B` (no adapter) | **45.8%** |
| + repository LoRA (trained on the repo) | **66.7%** |
| **delta** | **+20.8 pp** |

Training NLL collapsed `7.54 → 0.04` over 24 steps. The adapter learned
repo-specific targets the base model missed, e.g.:

```
[base]    target='cache.ttl'     pred='1)'            FAIL
[adapted] target='cache.ttl'     pred='cache.ttl()'   PASS
[adapted] target='cache.timer()' pred='cache.timer()' PASS
[adapted] target='list(items)'   pred='list(items)'   PASS
```

The repository turned into adapter parameters that measurably adapt a live
modern model — exactly the loop the Code2LoRA hypernetwork performs in a single
forward pass. (A smaller `32/16/3` run reproduced the direction at +6.2 pp.)

### Does it actually beat RAG? (head-to-head, [`tinker/benchmark.py`](tinker/benchmark.py))

Same task, same held-out split, three real repos, on live `Qwen/Qwen3.5-4B`.
RAG retrieves real `bge-small` embeddings over each repo's non-test source
(leakage-safe). Full table in [`tinker/RESULTS.md`](tinker/RESULTS.md):

| method | cachetools | schema | boltons | **mean EM** | avg tokens/query |
|---|---|---|---|---|---|
| base (no repo knowledge) | 54.2% | 16.7% | 54.2% | 41.7% | 206 |
| RAG@3 | 45.8% | 16.7% | 54.2% | 38.9% | 1,563 |
| RAG@8 | 41.7% | 20.8% | 50.0% | 37.5% | 2,260 |
| **repo-LoRA** | **62.5%** | **62.5%** | **62.5%** | **62.5%** | **206** |
| repo-LoRA + RAG@8 | 62.5% | 66.7% | 58.3% | 62.5% | 2,260 |

Two findings, both matching the paper:
- **Parametric beats context-injection.** repo-LoRA averages **62.5%** vs RAG's
  ~38% and the 41.7% base. On the hard `schema` repo RAG was useless (16.7%)
  while LoRA jumped **+45.8 pp**. RAG often *hurt* (distracting context) and
  never clearly won.
- **At a fraction of the cost.** RAG pays ~1,500–2,300 prompt tokens on *every*
  query; the LoRA carries the repo in parameters at **zero** inference-time
  token overhead (206 = just the task prefix). Adding RAG on top of the LoRA
  doesn't help — the knowledge is already in the weights.

(These use a deliberately small budget — 48 train / rank 16 / 4 epochs. Scaling
training pushes EM substantially higher; see `tinker/run_tinker.py` with larger
`--max-train`, `--rank`, `--epochs`.)

## Why Qwen3.5-4B for the live run?

The paper's backbone is Qwen2.5-Coder-1.5B (late-2024, code-specialized). It is
kept as the **offline structural target** (clean 7-projection dense attention,
the exact architecture the paper assumes). For the **live** proof we use
`Qwen/Qwen3.5-4B` — a genuinely newer/stronger 2026 model and one Tinker actually
serves. The Rust pipeline is model-agnostic, so the same code targets either.

## Limitations (honest)

- The Rust hypernetwork is emitted **at initialization** (untrained): the proof
  is structural/format/conditioning correctness on the real model, not yet a
  quality gain. End-to-end *training* of the 720M hypernetwork needs a GPU.
- The default repository embedder is a deterministic **feature-hashing** stand-in
  for the paper's frozen Qwen3-Embedding-0.6B (so the crate runs with no
  multi-GB download). It is content-sensitive and reproducible; swap a neural
  embedder behind the `Embedder` trait for semantic fidelity.
- The live Tinker proof trains a per-repo LoRA (the paper's upper-bound
  baseline), which is the executable stand-in for a *trained* hypernetwork's
  one-shot generation on the same model + same PEFT artifact.

## Layout

```
src/embedder.rs   repository encoder (§3.1)
src/hypernet.rs   Code2LoRA-Static hypernetwork (§3.2)
src/model.rs      target base-model spec (Qwen2.5-Coder-1.5B / any config.json)
src/lora.rs       PEFT adapter export + round-trip loader
src/main.rs       CLI: encode | generate | verify | info
tests/            offline end-to-end proofs
tinker/           live proof on Qwen3.5-4B (real GPU via Tinker)
examples/sample_repo/  tiny demo repository
```

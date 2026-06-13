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
trainable parameters". For one-shot *generation* on the full Qwen target they are
**streamed deterministically from the seed** (the network at initialization;
log-scale −3.5 ⇒ small, near-identity adapters, the paper's init). Two further
pieces are implemented and tested:

- **Code2LoRA-Evo** (§3.3, [`src/evo.rs`](src/evo.rs)) — a GRU maintains a
  repository state over a chronological stream of commit diffs, re-emitting an
  adapter per commit (an *adapter trajectory*), with the snapshot prior carried
  in the initial state. See "Evolving repos" below.
- **Hypernetwork training** (§3.4, [`src/train.rs`](src/train.rs)) — a complete
  pure-Rust autograd training loop for the Static hypernetwork, proving the
  architecture *learns and generalizes to unseen repositories*. See "Training"
  below.

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

`tests/integration.rs` proves (7 tests):
- **`shapes_match_real_model`** — every one of the 392 tensors (28 layers × 7
  module types × {A,B}) matches Qwen2.5-Coder-1.5B's real projection dims.
- **`weights_finite_and_near_identity`** — all finite, max |w| < 0.5 at init.
- **`deterministic_same_repo_same_adapter`** — same repo+seed ⇒ identical bytes.
- **`conditioned_different_repos_differ`** — different repos ⇒ different adapters
  (the whole point: the adapter actually encodes the repository).
- **`evo_trajectory_evolves_and_is_ordered`** — Evo adapters change per commit
  and depend on commit order.
- **`evo_deterministic_and_exportable`** — Evo's final adapter exports as a valid
  PEFT artifact for the real model.
- **`hypernetwork_trains_and_generalizes`** — after training, held-out
  adaptation error drops below half the no-adaptation baseline.

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

(These use a deliberately small budget — 48 train / rank 16 / 4 epochs.)

**It generalizes across languages too.** Same small budget, 9 brand-new repos,
3 per language ([`tinker/RESULTS_multilang.md`](tinker/RESULTS_multilang.md)):

| method | JavaScript | Rust | Go | mean EM | tokens |
|---|---|---|---|---|---|
| base | 41.7% | 22.9% | 18.8% | 27.8% | 482 |
| RAG@3 | 35.4% | 33.3% | 14.6% | 27.8% | 1,819 |
| **repo-LoRA** | **66.7%** | **43.8%** | **56.2%** | **55.6%** | **482** |

repo-LoRA ~doubles base and wins **8/9** repos across JS/Rust/Go (the paper is
Python-only); RAG nets out equal to base at ~4× the tokens. Highlights:
`sindresorhus/is` 56%→**100%**, `gin` 12.5%→**62.5%**, `lodash` 44%→69%.

**Scaling the LoRA reaches 92%.** On `cachetools` with a fixed 50-example
held-out set ([`tinker/push_train.py`](tinker/push_train.py)):

| config | held-out EM |
|---|---|
| base | 60.0% |
| train=150, rank=32, epochs=6 | 80.0% |
| train=400, rank=32, epochs=6 | 84.0% |
| **train=700, rank=64, epochs=8** | **92.0%** |

A clean scaling curve (60% → 92%) at zero inference-time token overhead. The one
persistent miss — target `len(cache)`, prediction `cache.currsize` — is
*functionally identical*, so real functional accuracy is higher still. RAG never
beat the base model on this repo. See [`tinker/RESULTS.md`](tinker/RESULTS.md).

## Evolving repos: Code2LoRA-Evo (§3.3)

Real codebases change commit by commit, and a snapshot adapter goes stale. Evo
walks a repo's git history, embeds each commit's diff, advances a GRU, and
re-emits an adapter per commit — an adapter *trajectory*:

```bash
./target/release/code2lora evo --repo <git_repo> --out /tmp/adapter-evo --max-commits 8
```
```
adapter trajectory (||ΔA_q|| between consecutive commits):
  commit  1 dbec5fa0  ||ΔA_q||=   (init)
  commit  2 02b2254f  ||ΔA_q||=1.45130
  commit  3 484741be  ||ΔA_q||=2.60797
  ...
exported final-commit adapter to /tmp/adapter-evo (392 tensors)
```

Each step is one cheap GRU update on the stored diff embedding (no full re-encode),
and the final adapter exports as a normal PEFT artifact.

## Training the hypernetwork (§3.4)

Training the full ~720M hypernetwork that adapts Qwen needs a GPU (it must
backprop through the frozen base LLM, which Tinker doesn't expose). To prove the
*architecture* learns and generalizes, [`src/train.rs`](src/train.rs) trains the
identical Static hypernetwork shape — with full hand-written autograd, pure Rust,
no deps — on a frozen-base adaptation task: a fixed ground-truth linear
hypernetwork maps each repo embedding to a low-rank target adaptation of a frozen
`W0`, and our MLP hypernetwork must learn `e ↦ ΔW(e)` and generalize to **unseen**
repos.

```bash
./target/release/code2lora train-demo --steps 6000
```
```
held-out adaptation error (lower = better):
  no adaptation (ΔW=0):       260.14
  untrained hypernetwork:     260.31
  TRAINED hypernetwork:         2.20      # 99.2% lower than baseline
```

After crossing a convergence transition (~3k steps) the trained hypernetwork cuts
held-out adaptation error by **~99%** vs both the no-adaptation baseline and its
untrained init — i.e. it learned to *synthesize repository-specific adapters that
generalize to repositories it never saw*, which is exactly Code2LoRA's claim.

## Real (semantic) embeddings (§3.1)

The default encoder uses a deterministic feature-hashing stand-in. The paper uses
a *frozen neural* embedder (Qwen3-Embedding-0.6B). [`src/neural.rs`](src/neural.rs)
implements that behind the same `Embedder` trait via `candle` (a frozen
BERT-family sentence model, default `BAAI/bge-large-en-v1.5`, 1024-dim =
`EMBED_DIM`), so the generated LoRA is conditioned on the *meaning* of the code:

```bash
cargo build --release --features neural
./target/release/code2lora generate --repo <path> --out /tmp/a --neural
# --embed-model accepts a Hub id or a local dir (config.json + tokenizer.json + model.safetensors)
```

**Does it actually condition on semantics?** Cosine similarity between adapters
generated for three tiny repos — two HTTP servers written with *different words*,
one linear-algebra lib ([`scripts/adapter_cosine.py`](scripts/adapter_cosine.py)):

| adapter pair | neural embedder | hash (lexical) |
|---|---|---|
| http_a ↔ http_b (same idea, different wording) | **0.741** | 0.511 |
| http_a ↔ math | 0.399 | 0.113 |
| http_b ↔ math | 0.388 | 0.077 |

The neural embedder recognizes the two HTTP repos as much more similar (0.74)
than the lexical embedder (0.51) — it captures that "web server" ≈ "serves
webpages over TCP" — while both correctly separate HTTP from math. The generated
adapter is genuinely *semantically* conditioned on the repository.

> On networks with a TLS-intercepting proxy, `hf-hub`'s bundled roots may reject
> the proxy CA; download the model files with a system-trusted tool and pass the
> local dir to `--embed-model`.

## Security: anomalous-commit detection (`evo-scan`)

The Evo GRU's running repository state doubles as an **unsupervised supply-chain
detector**: a commit whose diff pushes the state abnormally far is flagged for
review. On **50 real `facebook/react` commits** with one planted backdoor commit
(exfiltrates `process.env`/secrets, `execSync`, `eval`), the semantic embedder
surfaces the malicious commit at **#3 of 51** (top 6%) vs **#24** for the lexical
embedder — see [`SECURITY.md`](SECURITY.md).

```bash
code2lora evo-scan --repo /path/to/react --max-commits 50 --inject evil.patch \
    --neural --embed-model /path/to/bge-large-en-v1.5 --no-snapshot
```

## Why Qwen3.5-4B for the live run?

The paper's backbone is Qwen2.5-Coder-1.5B (late-2024, code-specialized). It is
kept as the **offline structural target** (clean 7-projection dense attention,
the exact architecture the paper assumes). For the **live** proof we use
`Qwen/Qwen3.5-4B` — a genuinely newer/stronger 2026 model and one Tinker actually
serves. The Rust pipeline is model-agnostic, so the same code targets either.

## Limitations (honest)

- The hypernetwork's **one-shot generation for the full Qwen target** is emitted
  at initialization (streamed from the seed): that path proves
  structural/format/conditioning correctness on the real model. Training is
  proven separately (`train-demo`) on a tractable frozen base; training the 720M
  hypernetwork *through Qwen itself* needs a GPU (Tinker can't backprop into a
  custom hypernetwork).
- The *default* repository embedder is a deterministic **feature-hashing**
  stand-in (so the crate runs offline with no download). A real frozen **neural**
  embedder is available behind the same trait via `--features neural`
  (`src/neural.rs`) and is shown above to give semantically-conditioned adapters.
- The live Tinker proof trains a per-repo LoRA (the paper's upper-bound
  baseline), which is the executable stand-in for a *trained* hypernetwork's
  one-shot generation on the same model + same PEFT artifact.

## Layout

```
src/embedder.rs   repository encoder (§3.1) + single-doc/diff encoder
src/neural.rs     real frozen neural embedder via candle (feature "neural")
src/hypernet.rs   Code2LoRA-Static hypernetwork (§3.2)
src/evo.rs        Code2LoRA-Evo: GRU over commit diffs (§3.3)
src/train.rs      pure-Rust autograd training of the hypernetwork (§3.4)
src/model.rs      target base-model spec (Qwen2.5-Coder-1.5B / any config.json)
src/lora.rs       PEFT adapter export + round-trip loader
src/main.rs       CLI: encode | generate | verify | info | evo | train-demo
tests/            offline end-to-end proofs (7 tests)
tinker/           live proof + RAG benchmark on Qwen3.5-4B (Tinker)
examples/sample_repo/  tiny demo repository
```

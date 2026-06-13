# Code2LoRA — use cases (with the examples we actually ran)

Each use case is paired with the concrete experiment/result from this repo, so the
claims are grounded. Numbers come from live runs on real models (Qwen3.5-4B via
Tinker; Qwen2.5-Coder-1.5B via PEFT). See `README.md`, `SECURITY.md`,
`tinker/RESULTS.md`, `tinker/RESULTS_multilang.md`, `PROGRESS.md`.

## 1. Repo-aware code completion / assertion reasoning — cheaper than RAG
Bake a repo's APIs/conventions into adapter parameters instead of retrieving
context on every request.
- **Example we ran:** held-out assertion-completion on real repos. repo-LoRA beat
  RAG everywhere and cost ~¼ the tokens.
  - Python (3 repos): repo-LoRA **62.5%** vs RAG ~38% vs base 41.7%.
  - Cross-language (9 repos, JS/Rust/Go): repo-LoRA **55.6%** (wins 8/9); RAG = base
    (27.8%) at ~1,800 vs 482 tokens/query.
  - `sindresorhus/is` 56%→**100%**; `gin` 12.5%→**62.5%**; `lodash` 44%→69%.

## 2. Multi-tenant serving — one base model, many repo adapters
The exported adapter is standard PEFT, hot-swappable in vLLM/SGLang
(`--lora-modules`). One base in VRAM, a tiny adapter per repo per request.
- **Example we ran:** `code2lora generate` emits `adapter_config.json` +
  `adapter_model.safetensors` (392 tensors) that **loads onto the real
  Qwen2.5-Coder-1.5B via PEFT and runs** (`tinker/peft_local.py`).

## 3. Instant onboarding of any repo (the hypernetwork's unique value)
Per-repo fine-tuning needs a training job per repo; the hypernetwork **generates**
an adapter in one forward pass — support a just-pushed repo immediately.
- **Example we ran:** `code2lora generate --repo <r>` produces a repo-conditioned
  adapter with no training; tests confirm different repos → different adapters, and
  the pure-Rust autograd hypernetwork **generalizes to unseen repos** (held-out
  adaptation error −99.2%). *(End-to-end gain from one-pass generation on a real
  model is the GPU step now in progress — see PROGRESS.md.)*

## 4. Semantic conditioning (knows meaning, not just tokens)
- **Example we ran:** with the neural embedder, two differently-worded HTTP-server
  repos → generated-adapter cosine **0.74**, vs **0.39** to a linear-algebra repo
  (lexical hash embedder: 0.51 / 0.11). `scripts/adapter_cosine.py`.

## 5. Scaling to high accuracy
- **Example we ran:** scaling training (data/rank/epochs) on `cachetools` took
  held-out EM **60% → 92%** at zero inference-token overhead; lodash/serde-json/gin
  reached ~72–75% (ceiling is repo-dependent).

## 6. Evolving codebases (Code2LoRA-Evo)
Refresh the adapter per commit with one cheap GRU step instead of re-indexing
(RAG) or retraining.
- **Example we ran:** `code2lora evo` walks real git history and emits an adapter
  *trajectory* (per-commit `‖ΔA‖`), order-sensitive and deterministic.

## 7. Privacy / air-gapped / on-device
Knowledge in weights → no source chunks shipped into the prompt each call; small
base + small adapter runs on-prem/edge. (Caveat: the adapter encodes the code —
treat it as sensitive.)

## 8. Security: supply-chain commit triage (defensive)
Flag commits whose diff is an outlier in the repo's own distribution.
- **Example we ran (honest, incl. failures):** on the **real** `Marak/colors.js`
  Jan-2022 DoS, the **kNN** scorer ranks the malicious commit **#1/40**
  (`evo-scan --method knn`); state-jump missed it (#18). On the **real** `xz`
  CVE-2024-3094 backdoor it only reaches #5–6 because the payload is **binary**
  (text embedders can't see it). On a *synthetic overt* exfil patch in react it hit
  #3/51. → A triage *prior*, not a detector; details + dual-use risks in
  `SECURITY.md`.

## The "code2lora.com/user/repo" product
GitHub hosts the code; code2lora hosts the **model that understands the code** — a
weights mirror, versioned per commit/tag. A consumer can: download the PEFT
adapter, hit a hosted "chat-with-this-repo" endpoint, drop repo-aware autocomplete
into their IDE, refresh it per commit in CI, or compose it with a task adapter
(test-gen, security-review). The reasons it's a product and not RAG-as-a-service
are the three things we measured: **beats retrieval**, **zero per-query tokens**,
and **generatable on demand for any repo**.

## Where it is NOT the right tool
Verbatim retrieval/citations, very fresh facts, or one-off throwaway queries — use
RAG/long-context there. In practice it's **complementary**: parametric for the
stable high-frequency repo knowledge, retrieval for the long-tail exact lookups.

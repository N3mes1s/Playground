# Code2LoRA vs RAG — live benchmark (Qwen/Qwen3.5-4B via Tinker)

Held-out assertion-completion exact-match. Model: `Qwen/Qwen3.5-4B`, RAG embedder: `BAAI/bge-small-en-v1.5`, LoRA rank 16, 4 epochs, 48 train / 24 test per repo.

| method | cachetools | schema | boltons | mean EM | avg tokens |
|---|---|---|---|---|---|
| base | 54.2% | 16.7% | 54.2% | **41.7%** | 206 |
| RAG@3 | 45.8% | 16.7% | 54.2% | **38.9%** | 1563 |
| RAG@8 | 41.7% | 20.8% | 50.0% | **37.5%** | 2260 |
| repo-LoRA | 62.5% | 62.5% | 62.5% | **62.5%** | 206 |
| repo-LoRA+RAG@8 | 62.5% | 66.7% | 58.3% | **62.5%** | 2260 |

`avg tokens` is the mean prompt length fed to the model per query. RAG pays that overhead on **every** inference; repo-LoRA carries the repository in adapter parameters at **zero** inference-time token cost.

## Scaling to 92% — how high can a repo-LoRA go?

`push_train.py` on `tkem/cachetools` (998 tasks, **fixed 50-example held-out
set**, disjoint from every train pool), scaling train size, LoRA rank and epochs:

| config | held-out EM |
|---|---|
| base (no adapter) | 60.0% |
| train=150, rank=32, epochs=6 | 80.0% |
| train=400, rank=32, epochs=6 | 84.0% |
| **train=700, rank=64, epochs=8** | **92.0%** |

A clean scaling curve: more repository data + capacity → higher exact-match,
**60% → 92%**, still at *zero* inference-time token overhead. The single
persistent miss is instructive — target `len(cache)`, prediction
`cache.currsize`: **functionally identical** for a cache, so functional accuracy
is higher than the 92% strict-EM number. RAG, by contrast, never exceeded the
base model on this repo (see table above) while adding ~1,500–2,300 tokens/query.

Reproduce:
```bash
python push_train.py --github https://github.com/tkem/cachetools --test 50 \
    --configs "150:32:6,400:32:6,700:64:8"
```

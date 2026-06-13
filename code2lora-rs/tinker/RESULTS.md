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

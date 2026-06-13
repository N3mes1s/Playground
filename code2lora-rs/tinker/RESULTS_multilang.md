# Code2LoRA vs RAG across languages — live benchmark (Qwen/Qwen3.5-4B via Tinker)

Held-out assertion-completion exact-match on **9 brand-new repositories, 3 per
language, across complexity levels** (none used elsewhere in this project).
Model `Qwen/Qwen3.5-4B`; RAG embedder `BAAI/bge-small-en-v1.5`; **small uniform
budget**: LoRA rank 16, 3 epochs, 40 train / 16 test per repo (17 train for the
tiny `lo`). This matches the budget of the Python `RESULTS.md` table so it is a
floor, not a ceiling (cf. the 92% scaling result there).

Reproduce: clone the repos, then
`python benchmark.py --repo <each> --rag-k 3 --max-train 40 --max-test 16 --epochs 3`.

| language | repo (size) | base | RAG@3 | **repo-LoRA** |
|---|---|---|---|---|
| JavaScript | chalk (small)      | 25.0% | 25.0% | **31.2%** |
| JavaScript | sindresorhus/is (med) | 56.2% | 37.5% | **100.0%** |
| JavaScript | lodash (large)     | 43.8% | 43.8% | **68.8%** |
| Rust       | bitflags (small)   | 12.5% | 12.5% | **31.2%** |
| Rust       | itertools (med)    | 12.5% | 31.2% | **50.0%** |
| Rust       | serde-json (large) | 43.8% | **56.2%** | 50.0% |
| Go         | samber/lo (small)  | 18.8% | 12.5% | **62.5%** |
| Go         | uber-go/zap (med)  | 25.0% | 18.8% | **43.8%** |
| Go         | gin (large)        | 12.5% | 12.5% | **62.5%** |
| **mean**   |                    | **27.8%** | **27.8%** | **55.6%** |
| avg tokens/query |              | 482   | 1,819 | 482 |

## Findings

- **Parametric adaptation generalizes across languages.** repo-LoRA roughly
  **doubles** mean exact-match over base (27.8% → 55.6%) on JavaScript, Rust, and
  Go — languages the paper never tested (it is Python-only). It wins **8 of 9**
  repos.
- **RAG ≈ base on average (27.8% vs 27.8%), at ~4× the tokens.** Retrieval helped
  on 2 repos (itertools, serde-json), hurt on 3 (is, lo, zap), and was neutral on
  the rest — a wash overall, while paying ~1,800 vs 482 prompt tokens *per query*.
- **The one repo RAG won** (serde-json: 56.2% vs 50.0%) is exactly where the small
  40-example/3-epoch LoRA budget bites; scaling training (see `RESULTS.md`, where
  the same lever took cachetools 62.5% → 92%) is expected to flip it.
- **repo-LoRA carries the repo at zero inference-time token overhead** (482 = the
  bare task prefix), whereas RAG's cost recurs on every single query, forever.

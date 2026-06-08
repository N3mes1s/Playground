# Research: what does a "build system for LLM workflows" actually solve?

This file records the market/problem research behind llmake so the reasoning
lives with the code. It was produced by a multi-source web research pass
(5 parallel search angles, deduped and skeptically synthesized). Citations are
inline; vendor sources are flagged as self-interested where relevant.

> Method note: Reddit's API/search was blocked in the research environment, so
> primary practitioner quotes lean on Hacker News, Hamel Husain, and arXiv user
> studies, supplemented by vendor/dev blogs (flagged).

## Bottom line

The premise — *"change one input, recompute only what's downstream, keep the
artifacts"* — is **real but contested**:

- It is the **least-saturated** pain in the LLM-tooling space, and serious teams
  are hand-building it.
- It sits between two crowded neighborhoods: build systems that aren't
  LLM-native, and LLM tools that aren't build systems.
- The biggest objection — LLM **non-determinism** — is legitimate and
  unsolved-by-default, and must be designed around explicitly.
- Demand is **strong as an implicit need, weak as a voiced one** (no breakout
  tool; no viral "I wish make existed for prompts" thread).

## 1. The under-served problem (the premise, validated)

- **AI21** built this in-house: cache keyed on each call's *position in the
  computation graph* so *"changing one prompt means only LLM calls from that
  point onwards will actually run… turning experimentation from something you
  have to ration into part of the daily loop."*
  <https://www.ai21.com/blog/caching-in-agentic-llm-pipelines/> (in-house, not a product)
- **CocoIndex**: *"the cost of a full rebuild scales with the size of the
  codebase, not the size of the change"*; memoization → *"80–90% reduction in
  LLM calls on a normal edit."* <https://cocoindex.io/blogs/multi-codebase-summarization/> (vendor)
- **Eval re-runs** have the same shape — *"running LLM-as-a-judge on thousands
  of test cases for every commit is expensive,"* forcing nightly/merge-only
  runs. <https://dev.to/kuldeep_paul/continuous-integration-for-llm-prompts-a-step-by-step-guide-to-automated-prompt-deployment-359k>
- Independent voice (Hamel Husain): teams *"can't tell me if their changes are
  helping or hurting,"* data lives *"in spreadsheets,"* people are *"hunting
  through multiple systems to understand a single interaction."*
  <https://hamel.dev/blog/posts/field-guide/>

## 2. Already commoditized — do NOT lead with these

- **Prompt versioning / provenance / output tracking** — crowded field:
  Langfuse, LangSmith, PromptLayer, Humanloop, Agenta, Datadog, Braintrust.
  Residual pain is concentrated in **solo/ad-hoc users and SaaS-averse teams**
  (HN: *"I don't feel comfortable proxying my llm calls through a 3rd party or
  storing my prompts in a SaaS"*). <https://news.ycombinator.com/item?id=42441258>
- **Prompt/model drift** (*"I can't see this until customers complain"*; GPT-4
  84%→51% prime-detection drop) is real but a *monitoring* problem, not a
  build-system one. <https://agenta.ai/blog/prompt-drift>

## 3. Adjacent tools and the precise gap

The two halves of the premise exist separately and have never been fused:

| Tool | Has | Missing |
|---|---|---|
| **DVC** (`dvc repro`) | content-hash incremental rebuild, DAG, versioned artifacts | zero LLM/prompt/agent awareness; stages are opaque shell commands |
| **Marimo** | reactive DAG, ancestor-aware `persistent_cache` | not LLM-native; no prompt/model/agent as first-class |
| **DSPy** | LM program compile + 3-layer cache | cache is **response replay** keyed on request args, not a dependency-aware build; no DAG of pipeline steps |
| **LangGraph** | DAG + checkpointers | persistence keyed on `thread_id`, **not content** — change a prompt and it re-runs |
| **promptfoo** | declarative YAML, disk cache | explicitly *"not a DAG or incremental build system"* |
| **Langfuse / prompt-CMS** | prompt versioning + caching | caches prompt *fetching*, versions prompt *text*, not intermediate run artifacts |
| **promptflow** | prompts-as-DAG, big traction | orchestration/eval, not skip-the-unchanged rebuild |
| **aider / Cursor / Continue** | coding agents over a repo | output is git diffs; no persistent per-step artifact DAG |

**The whitespace:** *a declarative, file-based DAG where prompt-steps **and**
coding-agent-steps are first-class nodes, a changed prompt/model/upstream-output
invalidates only its descendants, and every step's output is a saved, diffable,
versioned artifact.* None of ~16 tools surveyed ships this. Mixing chat models
**and** coding agents in one incremental graph is done by nobody. That is the
quadrant llmake targets.

(Sources: <https://dspy.ai/tutorials/cache/>,
<https://docs.langchain.com/oss/python/langgraph/persistence>,
<https://www.promptfoo.dev/docs/configuration/caching/>,
<https://doc.dvc.org/user-guide/pipelines/defining-pipelines>,
<https://docs.marimo.io/api/caching/>, <https://github.com/microsoft/promptflow>)

## 4. Concrete workflows, ranked by evidence strength

1. **Research / literature synthesis** (strongest). Practitioners hand-run
   gather→summarize→code-into-spreadsheet→synthesize in *"large tabular
   spreadsheets"*; *"no single cohesive solution exists."* Named gap:
   **provenance + verification**, not generation.
   <https://arxiv.org/pdf/2504.18496>, <https://arxiv.org/abs/2412.15249>
2. **Notes/KB → compiled output** (clearest "this should be a tool" signal).
   Karpathy's "LLM Wiki" frames the **LLM as a compiler with a delta
   manifest** — *"a `.manifest.json` tracks every source… computes the delta
   and only processes what's new or changed"* — done today as DIY markdown
   skill files glued onto a coding agent.
   <https://denser.ai/blog/llm-wiki-karpathy-knowledge-base/>
3. **Batch extraction over folders** (real, partly served). Teams *"backtest
   against reference documents to prevent silent regressions"*; the gap is the
   iteration/eval/versioning layer, not raw throughput.
   <https://medium.com/alan/lessons-from-running-an-llm-document-processing-pipeline-in-production-33d87f99cdb1>
4. **Codebase documentation** (weak — crowded: Autodoc, CocoIndex, Swimm;
   incremental recompute already solved; residual problem is accuracy/trust:
   *"wrong documentation is even worse than no documentation"*).
   <https://news.ycombinator.com/item?id=35297766>
5. **Legal/compliance** (weakest greenfield — well-funded CLM incumbents).

## 5. The strongest counterargument — and the design line

**Objection (legitimate):** make-style caching assumes pure functions; LLMs
aren't. Even at temperature 0 the same prompt yields ~80 distinct completions
out of 1000 (Qwen3-235B), with accuracy swings up to 15–70 points, because
output depends on the server's nondeterministic batch size — an input the
caller can't observe. A silent provider-side model update stales the cache
invisibly. <https://thinkingmachines.ai/blog/defeating-nondeterminism-in-llm-inference/>,
<https://arxiv.org/html/2408.04667v5>, <https://news.ycombinator.com/item?id=45734865>

**Why it's answerable, not fatal:**
- Fixable in principle — batch-invariant kernels give bitwise-identical outputs;
  shipped in SGLang. <https://www.lmsys.org/blog/2025-09-22-sglang-deterministic/>
- Version model id + all params + context into the cache key (the established
  MLOps reproducibility definition) so provider changes invalidate entries.
  <https://mlip-cmu.github.io/book/24-versioning-provenance-and-reproducibility.html>
- Caching LLM work is already mainstream economics: Anthropic prompt caching
  cuts cost/latency up to 90%/85%; semantic caching cuts calls 30–70%.
  <https://claude.com/blog/prompt-caching>, <https://arxiv.org/abs/2411.05276>

**The design line llmake must hold:** for a *build system*, caching one sample
is the desired behavior — the artifact stays stable until **you** regenerate.
The danger is only when a user mistakes "cached" for "verified." So:

1. The cache key includes prompt + provider + **model** + params + upstream
   artifact keys (already true in `cache.compute_key`). Bump the model string
   when the provider's model changes, and entries invalidate.
2. "Regenerate / pin / compare" are first-class: `--force` regenerates;
   selective rebuild pins unchanged steps; artifacts are plain files you can
   diff across snapshots.
3. Never imply a cached artifact is *correct* — only *current as of its build*.
   Docs and the export footer say exactly this.

## 6. Implications for llmake (honest read)

- **Aim:** the one empty quadrant (LLM-native incremental build with chat **and**
  agent nodes). Confirmed unoccupied vs. 16 tools.
- **Lead demos:** research-synthesis and notes/KB→compile (Karpathy
  "LLM-as-compiler" is the premise in the wild) — not codebase docs (crowded)
  or legal (served).
- **Lean into** what's not commoditized: incremental recompute, local/file-based,
  no-SaaS. De-emphasize prompt-versioning/provenance as headline features.
- **Design around determinism** exactly as §5: model+params in the key;
  regenerate/pin/compare first-class; "current, not verified."
- **Soberest risk:** demand is mostly *implicit*; adjacent funded categories keep
  absorbing pieces. This is a "build it and name the category" bet, not a
  "ride loud existing demand" one.

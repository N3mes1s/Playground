# Source: The LLM-workflow tooling gap

Build systems (DVC, Make, Bazel) and reactive notebooks (Marimo) provide genuine
content-addressed incremental recompute and versioned artifacts, but are not
LLM-native — they know nothing about prompts, models, or agents.

Conversely, LLM tooling (DSPy, LangGraph, promptfoo, Langfuse, prompt-CMS
products) understands prompts and agents but offers only response-replay caches,
thread-state checkpoints, or prompt registries — none re-run only the steps
whose inputs changed, and none treat intermediate LLM outputs as versioned build
products.

Claim: the unoccupied space is a declarative, file-based DAG where prompt steps
*and* coding-agent steps are first-class nodes, a changed input invalidates only
its descendants, and every step's output is a saved, diffable artifact.

Limitation: demand is mostly implicit — serious teams hand-build this (e.g.
graph-position-aware caches), but there is no breakout tool and little loudly
voiced demand.

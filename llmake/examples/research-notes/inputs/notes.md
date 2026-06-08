# Field notes — "build system for LLM workflows"

People keep describing the same shape of problem:

- They have a pile of source material: markdown notes, specs, transcripts,
  scraped pages, prior outputs.
- They want to *compute over* that material repeatedly with LLMs — summarize,
  critique, extract, rewrite, cross-reference.
- The intermediate and final outputs are themselves valuable artifacts worth
  saving, versioning, and sharing.
- The loop is iterative: tweak an input or a prompt, re-run, compare.

Today this lives in scattered chat threads and ad-hoc scripts. Nothing makes
the *artifacts* first-class or the recompute *incremental*.

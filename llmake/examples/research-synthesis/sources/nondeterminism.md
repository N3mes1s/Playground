# Source: LLM inference non-determinism

Even at temperature 0, hosted LLM inference is typically non-deterministic. In
one experiment, the same prompt run 1000 times against a large model produced
about 80 distinct completions. Accuracy across repeated identical runs varied
materially — swings reported from ~15 points up to large best-vs-worst gaps.

The primary cause is identified as variable server-side batch size (load
dependent), which makes certain kernels not batch-invariant — not, as commonly
assumed, mere floating-point non-associativity.

Caveat / counterpoint: this is fixable. Batch-invariant kernels can restore
bitwise-identical outputs and have shipped in at least one inference engine, so
determinism is a property of the stack you control rather than an inherent law.

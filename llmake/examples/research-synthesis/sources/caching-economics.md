# Source: Caching economics of LLM pipelines

Prompt caching on hosted APIs reuses an identical prompt *prefix* to skip
re-processing. Anthropic reports up to ~90% cost reduction and ~85% latency
reduction for large cached prefixes, with cache reads priced at roughly a 90%
discount versus base input tokens.

Beyond prefix caching, "semantic caching" reuses prior *outputs* for
similar-but-not-identical queries via embedding similarity; reported API-call
reductions land in the 30–70% range.

Limitation: prefix caching requires a byte-identical prefix and carries a short
TTL (often ~5 minutes), so it helps stable system prompts more than iterative
editing. Quote: "even minor alterations result in a cache miss."

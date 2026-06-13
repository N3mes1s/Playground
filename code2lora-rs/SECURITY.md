# Code2LoRA security use cases

Code2LoRA's repository-conditioned adapters and the Evo recurrence enable several
**defensive** security applications. One is implemented and demonstrated here.

## Demonstrated: anomalous-commit detection (`evo-scan`)

The Code2LoRA-Evo GRU maintains a running "repository state" over the commit
stream. A commit whose diff pushes that state abnormally far from the repo's
recent trajectory is a cheap, **unsupervised** novelty signal — useful for
supply-chain / backdoor / insider-threat review ("this change doesn't look like
how this project normally evolves"). One GRU step per commit, no labels, no
retraining.

```bash
# lexical (fast, offline)
code2lora evo-scan --repo <git_repo> --max-commits 50 --inject suspicious.patch
# semantic (stronger; needs --features neural + a 1024-dim embedder)
code2lora evo-scan --repo <git_repo> --max-commits 50 --inject suspicious.patch \
    --neural --embed-model /path/to/bge-large-en-v1.5 --no-snapshot
```

### Live demo on `facebook/react`

We took **50 real commits** from react and planted one **malicious supply-chain
commit** — a small (715-byte) patch to `ReactDOMRoot.js` that exfiltrates
`process.env` / `NPM_TOKEN` / `AWS_SECRET_ACCESS_KEY` to a look-alike domain,
runs `child_process.execSync('curl … | sh')`, and `eval`s a base64 payload.
We then ranked all 51 commits by Evo state-jump anomaly score:

| embedder | planted commit rank | interpretation |
|---|---|---|
| hash (lexical) | **#24 / 51** (z=+0.16) | missed — shares JS tokens with real diffs |
| neural (bge-large, semantic) | **#3 / 51** (z=+1.59, top 6%) | **surfaced** — a reviewer scanning the top of the anomaly list catches it |

The semantic embedder is what makes it work: a backdoor is *lexically* ordinary
JavaScript but *semantically* far from react's UI/reconciler changes, so it lands
in the top 6% of anomalies. It isn't #1 only because (a) the GRU is **untrained**
(random init — training on a repo's normal commits would sharpen the boundary)
and (b) the patch is tiny, so its magnitude competes with large legitimate
refactors. Even so, top-3-of-51 is an actionable review signal.

Honest caveats: this is a **novelty/outlier detector**, not a trained vulnerability
classifier; ranking (not the fixed z-threshold) is the signal; a size-normalized
score and a trained GRU would both help; CPU neural embedding of large diffs is
slow (the react run took ~26 min on CPU — seconds on GPU).

## Other security applications (design)

- **Repo-specialized vulnerability analysis** — a repo-LoRA gives a scanner a model
  that already knows the codebase's sinks, auth flow, and *custom safe wrappers*,
  cutting false positives (it learns that `safe_query()` is safe) at zero context
  tokens. Natural fit for this repo's `vulnllm-analyzer` / `recursive-lm-security-audit`.
- **Repo-idiomatic patch/fix suggestion** using the project's own sanitizers and
  error types.
- **Fast, offline/air-gapped incident-response assistants** that already know the
  codebase.

## Dual-use risks (must be governed)

- The adapter **encodes the source**: leaking an adapter ≈ leaking code knowledge
  (model-inversion / verbatim-extraction risk). Treat adapters as sensitive as the
  repo.
- **Poisoning** (especially Evo) via malicious commits; **license/attribution
  leakage** (generations can surface verbatim training spans). Prompt injection
  still applies at inference.

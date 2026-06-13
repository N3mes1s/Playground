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

### Evaluation: synthetic vs. two REAL supply-chain attacks (honest results)

We tested `evo-scan` on three cases and report what actually happened — including
where it **fails**.

| case | type | malicious commit rank | detected? |
|---|---|---|---|
| `facebook/react` + planted exfil patch | **synthetic, overt** | **#3 / 51** (neural, z=+1.59) | ✅ surfaced (top 6%) |
| `Marak/colors.js` `074a0f8` (Jan 2022 DoS) | **real** | **#29 / 40** (neural, z=−0.46) | ❌ missed |
| `tukaani-project/xz` `cf44e4b7` (CVE-2024-3094) | **real** | **#15 / 40** (z=+0.51) | ❌ missed |

**The synthetic case works** because the planted patch was *overtly foreign* —
`fetch(secrets)`, `execSync('curl|sh')`, `eval(payload)` — code semantically
unlike anything in react, so its state-jump is large (with the **semantic**
embedder; the lexical one missed it at #24, since it shares JS tokens).

**Both REAL attacks defeat it, for instructive reasons:**
- **colors.js** — the DoS payload (`for (let i=666;i<Infinity;i++) console.log('…'.zalgo)`)
  is *camouflaged as idiomatic colors.js*: a string-styling library where
  `'x'.zalgo`/`.rainbow`/`.america` and `console.log` are completely normal. It's
  not novel, so it ranks *below average* (z=−0.46).
- **xz** — the payload was committed as **binary** test files
  (`bad-3-corrupt_lzma2.xz`) plus an innocuous README line; a *text* embedder sees
  almost nothing anomalous (#15/40). This is exactly how the backdoor evaded human
  review for months.

**Honest conclusion.** Evo state-jump novelty on an **untrained** GRU catches
*blatantly out-of-distribution* malicious code, but is defeated by the two
camouflage strategies real attackers actually use — **mimicking the repo's own
idioms** (colors.js) and **hiding payload in binary** (xz). To make this
production-grade you need: a **trained** Evo GRU (learn each repo's normal
next-diff distribution, so an idiom-camouflaged but contextually-wrong commit gets
low likelihood), **binary/entropy features** (flag unexplained binary blobs), and
**intent** detection (infinite-loop / exfil signatures) rather than pure novelty.
The honest version of this tool is a triage *prior*, not a detector.

Reproduce:
```bash
# real colors.js DoS (no injection — find the real commit)
code2lora evo-scan --repo colors.js --max-commits 40 --neural \
    --embed-model bge-large-en-v1.5 --no-snapshot --flag 074a0f8
# xz backdoor: git checkout cf44e4b7 first, then
code2lora evo-scan --repo xz --max-commits 40 --no-snapshot --flag cf44e4b7
```

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

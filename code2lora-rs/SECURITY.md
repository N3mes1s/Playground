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
| `Marak/colors.js` `074a0f8` (Jan 2022 DoS) | **real** | **#1 / 40** (kNN, z=+2.10) | ✅ caught by kNN |
| `tukaani-project/xz` `cf44e4b7` (CVE-2024-3094) | **real** | #5–6 / 40 (centroid/kNN) | ⚠️ top-15%, not top-10% |

> **Correction (multi-scorer run).** The headline above originally reported only
> the *state-jump* scorer and called both real attacks missed. The full
> `commit_anomaly.py` run shows the scorer choice matters a lot: **kNN novelty
> catches the colors.js DoS at rank #1/40** (z=+2.10), and centroid/kNN surface
> the xz commit at #5–6/40 (top 15%). The *trained next-diff predictor* and
> state-jump both miss them. So the honest takeaway is "the right scorer (kNN)
> catches the idiom-camouflaged DoS; xz's binary payload still defeats a text
> embedder."

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

## Demonstrated: repo-LoRA cuts vulnerability-scanner false positives (`gpu/vuln_repo_lora.py`)

**Claim tested:** a repo-specialized LoRA knows the codebase's *custom safe
wrappers*, so it stops flagging `sink(safe_wrapper(user_input))` as a vuln —
cutting false positives — while still catching genuine raw-sink vulns.

**Controlled setup:** 12 synthetic repos, each with a unique documented safe
wrapper (e.g. `db_guard(x)` before `cursor.execute`). A per-repo LoRA is trained
(supervised) on that repo's documented `wrapper(x)→SAFE` / `raw(x)→VULN` call
sites, then evaluated on **held-out call sites using input sources never seen in
training**. The base model gets the same wrapper doc *in-context* (just no
training), so the comparison isolates what training the adapter adds.

| metric | base (doc in-context) | **repo-LoRA** |
|---|---|---|
| false-positive rate (safe wrapper-usage flagged VULN) | **100%** | **0%** |
| true-positive rate (real raw-sink vulns caught) | 100%\* | 88% |
| accuracy | 50% | **94%** |

\* The base is a *cry-wolf* classifier — it labels **everything** VULN (so its
100% TP is meaningless; its FP is also 100%). The repo-LoRA learns the actual
boundary and generalizes it to unseen call sites: **false positives 100%→0%**,
true-positives a healthy 88%, accuracy 50%→94%.

**Honest notes:** (1) this is a *controlled* demonstration of the mechanism, not a
real-CVE benchmark — it proves repo specialization *can* encode "this wrapper is
safe" and cut FPs, the exact pain point of noisy scanners. (2) Plain LM-training
on context text did **not** work (it only shifts the global VULN/SAFE prior, v1/v2);
the win needs **supervised** training on the repo's labelled safe/unsafe examples.
(3) TP is 88%, not 100% — a few held-out raw sinks slip to SAFE, so it's a
false-positive *reducer*, best paired with the conservative scanner, not a
standalone oracle.

Reproduce: `modal run gpu/modal_app.py --mode vuln`  (knobs: `VULN_REPOS`,
`VULN_STEPS`, `VULN_LR`). Natural fit for this org's `vulnllm-analyzer` /
`recursive-lm-security-audit`.
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

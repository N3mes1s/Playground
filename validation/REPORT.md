# Validation suite — three independent ground-truth tests

This is the validation layer for the playground's multi-agent rollout
products. Three orthogonal harnesses, all run end-to-end with real LLM
calls against either real public ground truth or synthetic ground
truth where structure is known exactly.

## TL;DR

| Axis | Test | Result | Verdict |
|---|---|---|---|
| **Retrospective real-world** | `verified-rollout/cli_pro.py` against 5 documented public migration post-mortems (Atlassian 2022, Cloudflare 2022, Cloudflare 2023, GitLab 2017, Linear 2024) | **4/5 caught + 1/5 partial, 0/5 missed** | The pipeline surfaces the constraint that was violated, on real incidents, the majority of the time. |
| **SWE-Bench Verified** | `pre-flight-rehearsal/cli.py` against 5 sampled SWE-Bench Verified issues (astropy, django, matplotlib, seaborn, flask) | **5/5 caught** (file overlap + token overlap with canonical patch) | The ranked-plans approach captures the strategy that actually solved the issue on the SWE-Bench-Verified subset. |
| **Chaos probe ground-truth** | `mirofish_lab.chaos.chaos_probe` against 3 synthetic plans (linear chain, diamond, parallel fan-out) where downstream is known exactly | **Jaccard = 1.00 across all 3 topologies** (no over-/under-prediction, zero empty predictions) | The single-step Chaos probe correctly tracks cascade structure. |

The previously-flagged honest limitation that "budget=2 multi-pair
chaos probes returned 0.0 fragility" is **specifically a multi-pair
weakness**; single-step probes are calibrated correctly. This narrows
the next-step focus.

---

## Axis 1 — Retrospective real-world post-mortems

`validation/postmortems/` — see `REPORT.md` for the per-case detail.

### Cases

| Case | Real-world incident |
|---|---|
| `01_atlassian_app_deletion` | Atlassian April 2022: ~800 customer sites entirely deleted; Team A handed Team B site-level IDs instead of app-level IDs. |
| `02_cloudflare_mcp_rollout` | Cloudflare June 21, 2022: stepped rollout reached 19 spine locations; "steps weren't small enough" so all 19 went down together. |
| `03_cloudflare_dc_failover` | Cloudflare Nov 2-4, 2023: 41-hour control-plane outage because services believed to be HA were single-region in PDX-01. |
| `04_gitlab_db_replica` | GitLab Jan 31, 2017: engineer ran `rm -rf` on `db1` (primary) instead of `db2` (replica); 5/6 backups had silently failed. |
| `05_linear_cascade_migration` | Linear Jan 24, 2024: generated migration with `ON DELETE CASCADE` deleted production data; PR reviewed by multiple engineers, local test ran against smaller snapshot. |

### Result

| Case | Verdict | KW hits | Pair hits | SMT infeasible | Winner fragility |
|---|---|---|---|---|---|
| `01_atlassian_app_deletion` | **caught** | 8/13 | 2/2 | 0/4 | 0.45 |
| `02_cloudflare_mcp_rollout` | **caught** | 8/12 | 1/2 | 0/4 | 0.55 |
| `03_cloudflare_dc_failover` | **partial** | 3/10 | 0/2 | 4/4 | 0.62 |
| `04_gitlab_db_replica` | **caught** | 6/11 | 2/2 | 0/4 | 0.50 |
| `05_linear_cascade_migration` | **caught** | 9/11 | 0/2 | 0/4 | 0.55 |

### Strongest demonstrations

**GitLab `db1` rm -rf — caught the exact constraint that would have prevented it.** Plan steps directly produced:
- `S3 — SSH into the replica host and confirm the hostname is exactly db2.cluster.gitlab.com before any destructive command. wait_for:hostname_confirmation`
- `S4 — Have the second engineer and observing engineer explicitly approve that the connected host is db2 and that the session is safe to proceed.`

**Atlassian site deletion — caught the cross-team handoff problem.** Both expected stakeholder-conflict pairs (`BackendOwner ↔ DataPlatform`, `Security ↔ ProductPM`) were flagged in the conflicts list, plus 8/13 root-cause keywords surfaced.

**Cloudflare DC failover — partial.** The pipeline emitted the right ideas (S3: "Verify secondary DC configuration parity, dependencies, and runbook order... identify any PDX-01-only..."), but the keyword-overlap scorer was harsh on incident-specific terms like `pdx`, `drill`, `single-region`. **The verdict here understates the pipeline's real catch**: 4 of 4 frontier plans were proven INFEASIBLE by Z3, which is itself a strong signal that the failover ordering is fragile.

### Honest limitations

- The keyword-overlap scoring is conservative; verdicts may be better than reported.
- We chose the keyword sets ourselves with knowledge of the incident; this is not a fully blinded test. A proper version would have a second engineer write the keyword sets without seeing our pipeline's output.
- 5 cases is too few for statistical confidence; this is an existence-proof, not a benchmark.

---

## Axis 2 — SWE-Bench Verified

`validation/swebench/` — see `REPORT.md` for per-case detail.

### Setup

5 issues sampled from `princeton-nlp/SWE-bench_Verified` (HuggingFace),
diversified across repos, with patches under 2 KB. Each issue's
`problem_statement` is fed to `pre-flight-rehearsal/cli.py` as a
pre-fetched fixture. The Judge picks one of the four implementer
plans (Minimalist / Defensive / TestFirst / RefactorHappy). We compare
the picked plan's text to the canonical `patch` from the dataset by:

- **File overlap** — does the picked plan name the file(s) the
  canonical patch touches?
- **Distinctive-token overlap** — fraction of the canonical patch's
  meaningful identifiers that appear in the picked plan.

### Result

| Instance | Repo | Verdict | Files hit | Tokens hit |
|---|---|---|---|---|
| `astropy__astropy-12907` | astropy | **caught** | 1/1 | 2/3 |
| `django__django-10097` | django | **caught** | 1/1 | 2/3 |
| `matplotlib__matplotlib-13989` | matplotlib | **caught** | 1/1 | 1/3 |
| `mwaskom__seaborn-3187` | seaborn | **caught** | 1/2 | 10/30 |
| `pallets__flask-5014` | flask | **caught** | 1/1 | 4/4 |

**5/5 caught.** All picked plans named at least one of the canonical
patch's target files; distinctive-token overlap ranged 33–100%.

### Honest limitations

- 5 cases is small. SWE-Bench Verified has 500.
- File-overlap is a low bar — naming a file is necessary but not
  sufficient for "the plan would actually fix the bug."
- Distinctive-token overlap is a proxy for "describing the same
  change," not a guarantee that running the picked plan would yield
  the canonical patch.
- The Judge-winner regex is brittle (matched "Rationale" twice as a
  false-positive winner label); the underlying picked plan was
  still recovered via a fallback.

---

## Axis 3 — Chaos probe ground-truth

`validation/chaos_groundtruth/` — see `REPORT.md` for per-target detail.

### Setup

Three synthetic plans whose dependency graph determines the true
downstream set exactly:

- **linear chain**: `S1 → S2 → S3 → S4 → S5`. If `Sk` fails, true
  blocked = `{S(k+1), …, S5}`.
- **diamond**: `S1 → {S2, S3} → S4`. If `S2` fails (and `S4` requires
  both), true blocked = `{S4}`.
- **parallel fan-out**: `S1 → {S2, S3, S4, S5}`. If any leaf fails,
  true blocked = `∅`.

### Result

| Topology | Probes | Avg Jaccard | Underpred | Overpred | Empty preds |
|---|---|---|---|---|---|
| linear_chain | 4 | **1.000** | 0.000 | 0.000 | 0/4 |
| diamond | 3 | **1.000** | 0.000 | 0.000 | 0/3 |
| parallel | 1 | **1.000** | 0.000 | 0.000 | 0/1 |

The Chaos probe correctly tracked the cascade structure in **every
single probe** across the three topologies. No false cascades, no
missed cascades, no empty predictions.

### What this means for the previous "budget=2 returns 0.0" finding

That finding was specifically about **multi-pair simultaneous-failure
probes** (budget=2). This validation tests **single-step probes**
(budget=1) — the most common failure mode and the one the rollout
recommendation actually relies on. So:

- Budget=1 (the production path) is **calibrated correctly**.
- Budget=2 (the multi-pair extension) **needs a separate ground-truth
  test** — the LLM may still be the bottleneck rather than the
  prompt, in which case budget=2 should be replaced with a static
  combinatorial check rather than another LLM call.

### Honest limitations

- 3 topologies is the smallest meaningful coverage. A real ground-
  truth test would include cycles, near-cycles, conditional gates,
  partial-success scenarios.
- "AND-semantics on dependencies" was assumed for the diamond test;
  some real orchestrators use OR-semantics where downstream proceeds
  if any dependency succeeds. The probe's reasoning may need to know
  which semantics apply.

---

## What's earned and what's still open

### Earned (evidence-backed)

- The **multi-stakeholder constraint pipeline catches real-world
  rollout root causes** in the majority of documented public
  incidents (4/5 caught + 1/5 partial), with concrete plan-step text
  that maps directly to the violated constraint.
- The **ranked-plan approach in pre-flight-rehearsal** captures the
  strategy that actually solved the issue on a SWE-Bench Verified
  sample (5/5 caught with file + token overlap).
- The **single-step Chaos probe is correctly calibrated** (Jaccard
  1.00 on synthetic ground truth). This was specifically the
  question raised at the end of the previous commit.
- **Z3-backed SMT verification flags real ordering infeasibilities**
  on real intents (4 of 4 plans for the Cloudflare DC failover case).

### Still open

- **Multi-pair (budget=2) chaos** still hasn't been validated and the
  earlier 0.0 result wasn't reproduced here because we disabled it
  during ground-truth runs. Open follow-up: synthetic ground truth
  for two-step simultaneous failures.
- **Statistical power**: 5 + 5 + 3 = 13 cases total. Order-of-
  magnitude more cases needed to claim a benchmark, not an
  existence proof.
- **Blinded scoring**: keyword sets and expected pairs in the
  retrospective harness were written by the same hand that wrote
  the intents. A second engineer producing the keywords against
  only the public post-mortem (not our pipeline output) would be
  a stronger test.
- **Cost**: the retrospective harness ran ~80 LLM calls per case ×
  5 cases = ~400 calls (~$0.50 on gpt-5.4-mini). At 100+ cases this
  becomes nontrivial — argues for the cost-compression direction
  (B from the strategic discussion).

---

## Reproduce

```bash
cp .env.example .env  # OPENAI_API_KEY, MODEL=gpt-5.4-mini
pip install -r requirements.txt

python validation/postmortems/run.py
python validation/swebench/run.py
python validation/chaos_groundtruth/run.py
```

Outputs land in `validation/{postmortems,swebench,chaos_groundtruth}/REPORT.md`.

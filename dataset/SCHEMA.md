# Unified rollout-evaluation dataset schema

Goal: a 20k-element corpus (10k real + 10k synthetic) of rollout /
migration scenarios, normalised to a single schema, that we can run
the verified-rollout pipeline against to produce **statistically
meaningful** evaluation rather than the 13-case existence-proof the
validation suite delivers today.

## Element shape

Every dataset element is a JSON object:

```json
{
  "id": "swebench_pro/django__django-11099",
  "source": "swebench_pro" | "swebench_verified" | "multi_swebench"
            | "danluu_postmortems" | "github_issues" | "synthetic",
  "kind": "code_change" | "post_mortem" | "migration_intent" | "infra_change",
  "title": "...",
  "intent_md": "<full markdown intent body, ready to feed into cli_grounded>",
  "repo": "owner/name (if applicable)",
  "repo_clone_url": "https://github.com/...",
  "language": "python" | "rust" | "typescript" | ... | null,
  "ground_truth": {
    "kind": "patch" | "root_cause" | "outcome" | null,
    "files_touched": ["..."] | null,
    "root_cause_keywords": ["cascade", "cdn", ...] | null,
    "outcome": "incident" | "shipped_clean" | null,
    "patch_uri": "..."
  },
  "metadata": {
    "stars": 12345,
    "loc": 50000,
    "tags": ["pydantic-v1", "schema-migration", ...],
    "stakeholders_present": ["backend", "data", "sre", ...]
  }
}
```

## Sources

- **swebench_verified** (500 elements). HuggingFace
  `princeton-nlp/SWE-bench_Verified`. Each issue → intent.
- **swebench_pro** (1,865 elements). HuggingFace
  `ScaleAI/SWE-bench_Pro`.
- **multi_swebench** (~2,000). HuggingFace
  `ByteDance-Seed/Multi-SWE-bench`. Multilingual coverage.
- **danluu_postmortems** (~500). `git clone github.com/danluu/post-mortems`,
  parse README links, fetch a curated subset of public post-mortem
  pages (Cloudflare, GitHub, GitLab, Stripe, etc.) into our intent
  format.
- **github_issues** (~5,000). GitHub Search API for labelled issues
  in popular Python/Rust/TS/Go repos: `label:migration`,
  `label:breaking-change`, `label:major-version`, `label:upgrade`.
- **synthetic** (10,000). Template-based generator under
  `dataset/synthetic/`.

## Ground truth coverage

Not every element has a useful ground truth:

- SWE-Bench gives us **gold patches** → we can score "did the
  pre-flight rehearsal pick a plan whose action mentions the right
  files?" against the patch.
- Post-mortems give us **root cause keywords** → we can score "did
  the verified-rollout flag a constraint whose summary contains the
  cause?"
- GitHub issues without merged fixes give us **intent only** → we
  can run the pipeline and score internal metrics
  (SMT-feasibility, fragility, family distribution) but no
  outcome ground truth.
- Synthetic items have **declared expected stakeholders** → we can
  score "did all expected personas emit constraints?"

The bench runner reports per-source coverage so we can see which
ground-truth signals are dominating.

## Output of running the pipeline against an element

The bench runner produces, per element, the existing pipeline JSON
sidecar plus:

```json
{
  "element_id": "swebench_pro/django__django-11099",
  "ran_pipeline": "cli_grounded" | "cli_pro" | "cli_chaos" | "cli_harden",
  "winner": "01-safety-leaning",
  "winner_family": "safety",
  "smt_feasible_count": 2,
  "n_plans": 4,
  "winner_fragility": 0.45,
  "ground_truth_match": {
    "files_overlap": 2,
    "files_total": 3,
    "keyword_hits": 5,
    "keyword_total": 10,
    "verdict": "caught" | "partial" | "missed"
  }
}
```

Aggregating across 200+ elements per run gives stable statistics on
where the pipeline does well and where it fails.

## Storage layout

```
dataset/
  SCHEMA.md                     this file
  sources/
    swebench_pro.py             one .py per source ingester
    swebench_verified.py
    multi_swebench.py
    postmortems.py
    github_issues.py
  synthetic/
    generator.py                template-based generator
    templates/                  yaml/md building blocks
  bench/
    bench_runner.py             orchestrator
    bench_report.py             aggregator
  data/
    real/                       *.jsonl files, one per source
    synthetic/                  *.jsonl
    combined/all.jsonl          single concatenation
  reports/
    bench_<timestamp>.md
    bench_<timestamp>.json
```

## Privacy / licensing notes

- SWE-Bench is MIT-licensed; redistribute under same.
- Multi-SWE-Bench is CC0; redistribute freely.
- danluu/post-mortems is a curated link list; we fetch the linked
  pages on first run and respect their robots.txt + terms.
- GitHub issues are public CC-BY-SA 3.0 by default; cite the
  original repo + issue URL.
- Synthetic data is ours; CC0.

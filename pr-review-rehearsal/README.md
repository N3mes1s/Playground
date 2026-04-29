# pr-review-rehearsal

Rehearse a PR review **before** you open the PR. Spin up four reviewer
personas (security, performance, grumpy architect, product owner), let
them review the diff in parallel, then have the implementer agent
iterate the patch and a judge agent rank the top concerns.

This is the most natural fit for MiroFish-style multi-agent simulation —
agent personalities + persistent memory + simulated stakeholder review.
The "Zep" piece is replaced by a local JSONL-backed memory under
`.mirofish_memory/` keyed per `(reviewer, repo)`, so re-runs against the
same repo accumulate reviewer history over time.

## Run

```bash
# from repo root
cp .env.example .env  # fill in OPENAI_API_KEY, MODEL=gpt-5.4-mini
pip install -r requirements.txt

# Live from GitHub:
python pr-review-rehearsal/cli.py --pr-url https://github.com/<owner>/<repo>/pull/<n>

# Or from a pre-fetched JSON fixture (useful in sandboxes without GitHub access):
python pr-review-rehearsal/cli.py --from-file fixtures/pr_n3mes1s_playground_1.json
```

Output lands in `pr-review-rehearsal/reports/<owner>_<repo>_pull_<n>.md`.
A real example run is committed there.

## What it does

1. Fetches the PR diff via the GitHub public API.
2. Runs four reviewer agents in parallel against the diff (CAMEL-AI
   `ChatAgent` under the hood, fallback to OpenAI direct).
3. Implementer agent reads all reviews, drafts responses + v2 edit list.
4. Judge agent ranks the top concerns and predicts merge-readiness.

## Limits

- Diff is truncated at 60 KB by default.
- No tool use — the agents see only the diff text, not the full repo.
- Memory persists locally only; no cross-machine sync (by design — Zep-free).

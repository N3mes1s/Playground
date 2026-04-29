# pre-flight-rehearsal

Take a real GitHub issue, spin up four implementer personas (Minimalist,
Defensive, TestFirst, RefactorHappy), have each produce a plan + diff
sketch in parallel, then have a judge rank them and pick a winner.

This is "ensembling-as-simulation" — instead of letting a managed coding
agent commit to one strategy, rehearse several styles cheaply and pick
the strongest before any code is actually written.

## Run

```bash
cp .env.example .env  # fill in OPENAI_API_KEY, MODEL=gpt-5.4-mini
pip install -r requirements.txt
python pre-flight-rehearsal/cli.py https://github.com/<owner>/<repo>/issues/<n>
```

Output: `pre-flight-rehearsal/reports/<owner>_<repo>_issues_<n>.md`.

## What it does

1. Fetches issue body + labels via GitHub API.
2. Runs four implementer personas in parallel.
3. Judge agent ranks the plans and picks a winner with rationale, also
   suggesting how to synthesise the strongest pieces from each.

## Limits

- The agents do not read the full repo — only the issue text. This is a
  first-pass plan, not an executable patch.
- Single-round: agents do not see each other's plans (parallel, not debate).
  If you want them to argue, swap `parallel_run` for `round_table` in
  `cli.py`.

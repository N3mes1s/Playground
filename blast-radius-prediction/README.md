# blast-radius-prediction

Predict downstream breakage from a proposed diff by treating each
top-level subsystem of the repo as an agent persona, then simulating
each subsystem's reaction to the change in a round-table.

This is the closest analogue to MiroFish's "graph build → simulation →
report" pipeline applied to coding agents: the call graph is the seed,
subsystems are the agents, the diff is the perturbation injected into
the simulated world.

## Run

```bash
cp .env.example .env  # fill in OPENAI_API_KEY, MODEL=gpt-5.4-mini
pip install -r requirements.txt

# from a real GitHub PR (repo must already be cloned somewhere):
python blast-radius-prediction/cli.py \
    --pr https://github.com/<o>/<r>/pull/<n> \
    --repo /path/to/cloned/repo

# from a pre-fetched PR JSON (sandbox-friendly):
python blast-radius-prediction/cli.py \
    --from-file fixtures/pr_n3mes1s_playground_1.json \
    --repo .

# or from a local diff file:
python blast-radius-prediction/cli.py \
    --diff fixtures/sample.diff --repo .
```

Output: `blast-radius-prediction/reports/<slug>.md`.

## What it does

1. Parses the diff, extracts changed Python symbols via AST.
2. Clusters the repo's files into subsystems by top-level package.
3. Identifies affected subsystems (changed file OR file that mentions a
   changed symbol via grep).
4. For each affected subsystem, instantiates an agent persona seeded
   with a sample of that subsystem's code.
5. Round-table: each subsystem-agent reacts to the proposed change.
6. Judge agent produces a per-subsystem risk roll-up + migration order.

## Limits

- Python-only AST extraction; non-Python repos get coarser results
  (subsystem clustering still works, but no symbol-level resolution).
- Caller detection is grep-based, not a true call graph; expect false
  positives. The judge agent is asked to flag "confused-sounding"
  subsystems precisely to surface these.
- Big repos: subsystems are capped at 20 files-of-context each by
  default to keep prompts under control.

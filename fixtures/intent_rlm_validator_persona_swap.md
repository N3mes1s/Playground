# Migrate `recursive-lm-security-audit/validator.py` from prosecution/defense to RedTeamTriager/Maintainer framing

## What

Rewrite the validator's adversarial pass so it uses the same
**RedTeamTriager + Maintainer** persona pair we adopted in
`adversarial-security-sim/` after discovering the original
prosecution/defense framing triggered model safety refusals on
critical findings.

The semantics are unchanged: each scanner finding is debated by two
agents, then a verdict agent classifies it as
`CONFIRMED` / `DOWNGRADED` / `DISMISSED`. Only the persona prompts and
the seed prompt change.

## Why

- Reduce safety-refusal rate on critical-severity findings. We saw a
  ~40% refusal rate in `adversarial-security-sim` until the reframe;
  the same prompts power `validator.py` and likely have the same
  problem.
- Consistency: both experiments now use the same persona vocabulary
  and shared prompt fragments.
- The verdict labels in `validator.py` (CONFIRMED / DOWNGRADED /
  DISMISSED) can stay; only the upstream framing is tightened.

## Scope

- `recursive-lm-security-audit/validator.py`:
  - Replace prosecution/defense system prompts with the
    `RedTeamTriager` / `Maintainer` prompts (or import them from
    `mirofish_lab/personas.py`).
  - Update the seed prompt template to "audit-level plausibility
    analysis" rather than "construct an exploit chain".
  - Keep the verdict prompt and label set identical.
- The benchmark runner (`benchmark.py`, `batch_runner.py`) gets a
  flag `--validator-mode={legacy,reframed}` so we can A/B compare
  refusal rate and verdict distribution before flipping the default.

## Constraints

- **Verdict label compatibility**: existing reports
  (`flowise-report.md`, `juice-shop-audit-report.md`,
  `n8n-audit-report.md`, `dvsa-audit-report.md`) must still parse as
  `CONFIRMED / DOWNGRADED / DISMISSED` so they stay comparable in the
  benchmark.
- **No accuracy regression**: on the `flowise-manual-verification.md`
  ground truth (4 confirmed real, 1 false positive), the reframed
  validator must match or exceed the legacy validator's F1.
- **Cost-neutral**: reframing prompts must not blow up token usage
  per finding — keep within ~10% of current spend.

## Out of scope

- Replacing the verdict classifier with a multi-class scoring agent.
- Cross-finding correlation.

## Affected stakeholders

- `recursive-lm-security-audit` (the change)
- `adversarial-security-sim` (shared persona module)
- Anyone reading existing audit reports and expecting the old verdict
  taxonomy

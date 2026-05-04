# adversarial-security-sim

Take an existing security-audit report (e.g. ones produced by
[`recursive-lm-security-audit`](../recursive-lm-security-audit/)) and
stress-test each finding via an Attacker-vs-Defender debate. A judge agent
then verdicts each finding as `REAL`, `FALSE_POSITIVE`, or `NEEDS_VALIDATION`.

This is the closest analogue to MiroFish's own pattern (populate a
sandbox with adversarial agents, simulate, report) applied to coding
agents specifically — it triages the noisy output of a static LLM
auditor by forcing each finding to survive a debate.

## Run

```bash
cp .env.example .env  # fill in OPENAI_API_KEY, MODEL=gpt-5.4-mini
pip install -r requirements.txt

# debate the top 5 findings from an existing audit:
python adversarial-security-sim/cli.py \
    recursive-lm-security-audit/flowise-report.md \
    --top 5 --rounds 2
```

Output: `adversarial-security-sim/reports/<report-stem>-adversarial.md`.

## What it does

1. Parses findings out of a markdown audit (heading + Severity heuristic).
2. For each top-N finding, runs an Attacker / Defender debate for K rounds.
3. Judge agent verdicts each finding with citations from the debate.

## Limits

- Heading-based parser; very unusually formatted reports may need tweaking.
- Agents see only the report text, not the underlying code. Pair with
  `recursive-lm-security-audit/validator.py` if you want the surviving
  hypotheses re-checked against actual source.

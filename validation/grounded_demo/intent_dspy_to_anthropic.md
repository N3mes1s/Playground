# Migrate `recursive-lm-security-audit/` from DSPy to direct Anthropic API calls

## What

The scanner pipeline in `recursive-lm-security-audit/` currently uses
the DSPy framework to orchestrate LLM calls. We are replacing DSPy
with direct calls to the Anthropic Messages API.

Concretely:

- Replace every `dspy.LM(...)`, `dspy.Predict(...)`, and
  `dspy.ChainOfThought(...)` instantiation with an `anthropic.Anthropic()`
  client + plain `messages.create(...)` calls.
- Replace DSPy's signature-based prompting with explicit prompt
  templates we manage ourselves.
- Keep the existing CLI surface (`cli.py`), output report formats,
  benchmark runner, and validator pipeline functioning byte-identically
  for the existing committed sample reports
  (`flowise-report.md`, `juice-shop-audit-report.md`,
  `n8n-audit-report.md`, `dvsa-audit-report.md`).

## Why

- DSPy's signature-based abstraction is opaque when prompts need
  surgical tuning. We have observed the validator's "prosecution /
  defense / verdict" prompts produce inconsistent verdict labels; we
  want explicit prompt control.
- Anthropic released `claude-opus-4-7` and `claude-haiku-4-5` after
  DSPy's last release; we want first-class support for those models
  including extended thinking and prompt caching, neither of which
  DSPy currently surfaces cleanly.
- DSPy adds a heavy dependency (~50 MB) we don't otherwise need.

## Scope

- `recursive-lm-security-audit/scanner.py` — rewrite the
  `CodeScanner` signature into explicit Anthropic Messages calls.
- `recursive-lm-security-audit/parallel_scanner.py` — same for the
  chunked-scan path.
- `recursive-lm-security-audit/validator.py` — replace the
  prosecution/defense/verdict DSPy modules with direct messages.create
  calls; tighten the verdict prompt.
- `recursive-lm-security-audit/benchmark.py` and
  `recursive-lm-security-audit/batch_runner.py` — switch their LM
  configuration paths.
- `recursive-lm-security-audit/cli.py` — argument plumbing for
  Anthropic API key (env var `ANTHROPIC_API_KEY` or
  `OPENROUTER_API_KEY`) + model selection.
- `recursive-lm-security-audit/requirements.txt` — drop `dspy-ai`,
  add `anthropic>=0.40`.

## Constraints

- **Output stability**: existing committed audit reports were produced
  by DSPy. After the migration, re-running the scanner against the
  same input must produce reports of comparable quality (manual
  spot-check on flowise-manual-verification.md's confirmed findings
  must still be detected as CONFIRMED).
- **Cost-neutral**: must stay within the existing ~$0.87/full-scan
  budget documented in the README.
- **Backwards-compatible CLI**: existing call patterns from any
  external scripts (`scan_sliver_latest.py` etc.) must continue to
  work, possibly via a thin shim.
- **Validator label set**: `CONFIRMED / DOWNGRADED / DISMISSED` must
  remain the verdict taxonomy — downstream consumers parse this.
- **Adversarial sim coupling**: this code is consumed by
  `adversarial-security-sim/cli.py` which expects the existing
  scanner output schema to hold.

## Out of scope

- Switching to a fundamentally different scanning algorithm.
- Adding tree-sitter / language-aware scanning (separate effort).
- Web UI for results.

## Affected stakeholders

- Backend / scanner team (the change owners).
- Adversarial-security-sim team (downstream consumer).
- Anyone running `vulnllm-analyzer/scan_*.py` shells on top of this
  pipeline.
- Cost / FinOps (validate $0.87/scan budget holds).

## What success looks like

- Scanner runs on Anthropic API directly, no DSPy dependency.
- All four existing audit reports re-runnable; manual-verification
  ground truth (4 confirmed real, 1 false positive on Flowise) still
  classified correctly.
- Verdict-label taxonomy preserved.
- Per-scan cost within ~10% of current ~$0.87 baseline.

# Grounded Rollout — intent_dspy_to_anthropic

> Intent: validation/grounded_demo/intent_dspy_to_anthropic.md · Repo: /home/user/Playground/recursive-lm-security-audit · Search patterns: 10 · Files scanned: 15 · Matches: 93 · Plans generated: 4 · Recommended: 01-safety-leaning · Model: gpt-5.4-mini

_Generated 2026-04-30T03:41:48Z_

## Recommendation

**01-safety-leaning** (smt_feasible=True, fragility=0.447, 12 of 12 steps grounded to real files).

## Codebase findings

## Codebase findings

- Scanned 15 files at `/home/user/Playground/recursive-lm-security-audit`.
- 93 total matches across 6 patterns.

**Hot files (most matches):**
- `/home/user/Playground/recursive-lm-security-audit/validator.py` — 42
- `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py` — 17
- `/home/user/Playground/recursive-lm-security-audit/benchmark.py` — 12
- `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` — 11
- `/home/user/Playground/recursive-lm-security-audit/scanner.py` — 6
- `/home/user/Playground/recursive-lm-security-audit/README.md` — 4
- `/home/user/Playground/recursive-lm-security-audit/n8n-audit-report.md` — 1

**Matches by pattern:**

- **Imports of DSPy framework** (8 matches):
    - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:27` — import dspy
    - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:27` — import dspy
    - `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py:21` — import dspy
    - `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py:21` — import dspy
    - `/home/user/Playground/recursive-lm-security-audit/scanner.py:14` — import dspy
    - `/home/user/Playground/recursive-lm-security-audit/scanner.py:14` — import dspy
    - _... and 2 more._
- **DSPy LM configuration instances** (30 matches):
    - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:108` — lm = dspy.LM(model, max_tokens=4000)
    - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:443` — lm = dspy.LM(model, max_tokens=max_tokens)
    - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:444` — sub_lm = dspy.LM(sub_model, max_tokens=max_tokens) if sub_model else lm
    - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:108` — lm = dspy.LM(model, max_tokens=4000)
    - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:443` — lm = dspy.LM(model, max_tokens=max_tokens)
    - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:444` — sub_lm = dspy.LM(sub_model, max_tokens=max_tokens) if sub_model else lm
    - _... and 24 more._
- **DSPy ChainOfThought module instantiations** (11 matches):
    - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:111` — extractor = dspy.ChainOfThought(AdvisoryFetcher)
    - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:476` — matcher = dspy.ChainOfThought(CVEMatcher)
    - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:111` — extractor = dspy.ChainOfThought(AdvisoryFetcher)
    - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:476` — matcher = dspy.ChainOfThought(CVEMatcher)
    - `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py:314` — synthesizer = dspy.ChainOfThought(ReportSynthesizer)
    - `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py:286` — Uses a standard dspy.ChainOfThought (not RLM) since the input is
    - _... and 5 more._
- **Validator verdict taxonomy labels in code or prompts** (25 matches):
    - `/home/user/Playground/recursive-lm-security-audit/validator.py:60` — - CONFIRMED: Real vulnerability with concrete exploit path
    - `/home/user/Playground/recursive-lm-security-audit/validator.py:61` — - DOWNGRADED: Real concern but lower severity than claimed
    - `/home/user/Playground/recursive-lm-security-audit/validator.py:62` — - DISMISSED: Not a vulnerability — feature working as designed,
    - _... and 19 more._
- _(truncated; see findings.json for full list)_

## Pareto scoreboard

| Plan | Steps | SMT feasible | Fragility | % grounded |
|---|---|---|---|---|
| 00-cost-leaning | 11 | N | 0.382 | 100% (11/11) |
| 01-safety-leaning | 12 | Y | 0.447 | 100% (12/12) |
| 02-speed-leaning | 12 | N | 0.371 | 100% (12/12) |
| 03-safety-tilted | 13 | N | 0.461 | 100% (13/13) |

## Plan: 00-cost-leaning

### Plan `00-cost-leaning`

| # | Action | Owner | Files | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Add Anthropic client wiring and a runtime toggle in recursive-lm-security-audit/ | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `approval:release_manager` | Restore the prior argparse surface and DSPy-backed |
| S2 | Rotate and verify Anthropic/OpenRouter secrets for first live use; confirm the n | Security | `/home/user/Playground/recursive-lm-security-audit/README.md` | `wait_for:secrets_rotation_complete` | Revoke new keys and restore prior key material/con |
| S3 | Implement direct anthropic.Anthropic().messages.create(...) wrappers in recursiv | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py` | `none` | Redeploy the previous DSPy-based scanner implement |
| S4 | Rewrite recursive-lm-security-audit/validator.py prosecution/defense/verdict pro | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/n8n-audit-report.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `approval:security_review` | Revert validator prompt changes to prior DSPy prom |
| S5 | Switch recursive-lm-security-audit/benchmark.py and recursive-lm-security-audit/ | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py` | `monitor:scan_cost<=0.96_per_full_scan` | Switch to the prior model/config and redeploy_prev |
| S6 | Keep recursive-lm-security-audit/cli.py backwards-compatible with prior call pat | ConsumerSubsystem | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/n8n-audit-report.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `none` | Reintroduce old CLI flags as shim. |
| S7 | Run parity checks on the committed sample reports flowise-report.md, juice-shop- | DataPlatform | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `monitor:report_diff_rate<=0.1` | Switch back to the DSPy path and stop Anthropic-on |
| S8 | Verify manual spot-check on flowise-manual-verification.md so the 4 confirmed re | DataPlatform | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `wait_for:manual spot-check on flowise-manual-verification.md findings` | Revert the migration and regenerate reports with t |
| S9 | Validate downstream consumer compatibility with adversarial-security-sim/cli.py  | ConsumerSubsystem | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `wait_for:validation against committed sample reports and downstream parser` | Restore the previous serializer/output model and r |
| S10 | Complete release communications for the Anthropic migration, including preserved | ProductPM | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `window:customer_partner_notice_before_release` | Remove migration notice and restore prior document |
| S11 | Schedule the cutover outside Friday afternoon, incident windows, launch windows, | SRE | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `approval:release_manager` | Disable Anthropic mode and fall back to the DSPy p |

## Plan: 01-safety-leaning

### Plan `01-safety-leaning`

| # | Action | Owner | Files | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Add Anthropic client plumbing and a runtime toggle in recursive-lm-security-audi | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `approval:release_manager` | Disable Anthropic mode and restore prior DSPy-back |
| S2 | Rotate Anthropic/OpenRouter secrets and verify the new env-based key fallback wo | Security | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py` | `wait_for:secrets_rotation_complete` | Revoke new keys and restore prior key material/con |
| S3 | Rewrite recursive-lm-security-audit/scanner.py and recursive-lm-security-audit/p | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py` | `monitor:confirmed_findings_retained=100%` | Switch back to the DSPy path and redeploy_previous |
| S4 | Rewrite recursive-lm-security-audit/validator.py proseuction/defense/verdict flo | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `wait_for:validator_taxonomy_checkpass_CONFIRMED_DOWNGRADED_DISMISSED` | Revert validator prompt changes to prior DSPy prom |
| S5 | Update recursive-lm-security-audit/benchmark.py and recursive-lm-security-audit/ | SRE | `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py` | `monitor:scan_cost<=0.96_per_full_scan` | Switch to prior model/config and redeploy_previous |
| S6 | Run dual-write/dual-compare on the committed sample reports by re-running scans  | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `monitor:report_diff_rate<=0.1` | Switch back to DSPy path and stop Anthropic-only e |
| S7 | Validate byte-for-byte report/schema compatibility against committed sample repo | DataPlatform | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/n8n-audit-report.md` | `wait_for:validation against committed sample reports and downstream parser` | Restore the previous serializer/output model and r |
| S8 | Perform manual spot-check on flowise-manual-verification.md confirmed findings a | Security | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `wait_for:manual spot-check on flowise-manual-verification.md findings` | Revert the migration and regenerate reports with t |
| S9 | Complete security review for the Anthropic migration, including emitted report m | Security | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `approval:security_review` | Redeploy_previous |
| S10 | Send customer/downstream communication about the preserved CONFIRMED/DOWNGRADED/ | ProductPM | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `wait_for:customer_comms_sent` | Revert prompts and outputs to the last shipped DSP |
| S11 | Obtain named rollout owner and launch a production rollout only outside incident | SRE | `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py` | `approval:named_rollout_owner` | Disable Anthropic mode and fall back to DSPy path |
| S12 | Flip the default path to Anthropic in cli.py and all LM call sites after the gua | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/n8n-audit-report.md` | `window:2 releases after merge` | Prefer DSPy client path and disable Anthropic-only |

## Agent backlog (winning plan)

### Agent backlog (plan: `01-safety-leaning`)

#### Task S1 — Add Anthropic client plumbing and a runtime toggle in recursive-lm-security-audit/cli.py, scanner.py, parallel_scanner.py, validator.py, benchmark.py, and batch_runner.py while keeping DSPy path intact; support ANTHROPIC_API_KEY and OPENROUTER_API_KEY plus model selection args.

**Files**: `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`

**Agent instructions:**

```
Touch these files: /home/user/Playground/recursive-lm-security-audit/README.md, /home/user/Playground/recursive-lm-security-audit/benchmark.py, /home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md.
  - `/home/user/Playground/recursive-lm-security-audit/README.md:27` (CLI API key environment variable plumbing): export OPENROUTER_API_KEY="your-key-here"
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:27` (Imports of DSPy framework): import dspy
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:108` (DSPy LM configuration instances): lm = dspy.LM(model, max_tokens=4000)
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:111` (DSPy ChainOfThought module instantiations): extractor = dspy.ChainOfThought(AdvisoryFetcher)
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:443` (DSPy LM configuration instances): lm = dspy.LM(model, max_tokens=max_tokens)
```

**Gate**: `approval:release_manager`
**Rollback**: Disable Anthropic mode and restore prior DSPy-backed wiring
**Observability**: CLI parses old and new flags; runtime logs show selected provider/model; no change in report schema yet

#### Task S2 — Rotate Anthropic/OpenRouter secrets and verify the new env-based key fallback works end-to-end for scan, benchmark, and batch flows.

**Files**: `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/recursive-lm-security-audit/README.md, /home/user/Playground/recursive-lm-security-audit/benchmark.py.
  - `/home/user/Playground/recursive-lm-security-audit/README.md:27` (CLI API key environment variable plumbing): export OPENROUTER_API_KEY="your-key-here"
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:27` (Imports of DSPy framework): import dspy
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:108` (DSPy LM configuration instances): lm = dspy.LM(model, max_tokens=4000)
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:111` (DSPy ChainOfThought module instantiations): extractor = dspy.ChainOfThought(AdvisoryFetcher)
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:443` (DSPy LM configuration instances): lm = dspy.LM(model, max_tokens=max_tokens)
```

**Gate**: `wait_for:secrets_rotation_complete`
**Rollback**: Revoke new keys and restore prior key material/config references
**Observability**: Auth succeeds with fresh keys; no unauthorized/401 responses; key source is recorded in logs without leaking secrets
**Depends on**: S1

#### Task S3 — Rewrite recursive-lm-security-audit/scanner.py and recursive-lm-security-audit/parallel_scanner.py to use anthropic.Anthropic().messages.create(...) with explicit prompt templates, preserving existing scanner output schema and chunking behavior.

**Files**: `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/recursive-lm-security-audit/README.md, /home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md, /home/user/Playground/recursive-lm-security-audit/parallel_scanner.py.
  - `/home/user/Playground/recursive-lm-security-audit/README.md:14` (Validator prosecution defense verdict prompt markers): 6. **(Optional) Adversarial validation**: Each finding goes through a devil's advocate pass that argues FOR and AGAINST 
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:41` (Validator prosecution defense verdict prompt markers): caused both the scanner and the adversarial validator to miss the defense-in-depth sanitization.
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:175` (Validator verdict taxonomy labels in code or prompts): | 1 | Path Traversal (CRITICAL) | CRITICAL | CONFIRMED | **FALSE POSITIVE** | Scanner WRONG, Validator WRONG |
  - `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py:21` (Imports of DSPy framework): import dspy
  - `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py:180` (DSPy LM configuration instances): lm = dspy.LM(model, max_tokens=max_tokens, **lm_kwargs)
```

**Gate**: `monitor:confirmed_findings_retained=100%`
**Rollback**: Switch back to the DSPy path and redeploy_previous
**Observability**: Report structure matches prior outputs; confirmed findings still appear; token usage and latency remain within expected bounds
**Depends on**: S1, S2

#### Task S4 — Rewrite recursive-lm-security-audit/validator.py proseuction/defense/verdict flow to direct Anthropic Messages calls, keep CONFIRMED/DOWNGRADED/DISMISSED taxonomy, and tighten prompts to reduce label drift.

**Files**: `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/recursive-lm-security-audit/README.md, /home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md, /home/user/Playground/recursive-lm-security-audit/validator.py.
  - `/home/user/Playground/recursive-lm-security-audit/README.md:14` (Validator verdict taxonomy labels in code or prompts): 6. **(Optional) Adversarial validation**: Each finding goes through a devil's advocate pass that argues FOR and AGAINST 
  - `/home/user/Playground/recursive-lm-security-audit/validator.py:81` (Validator verdict taxonomy labels in code or prompts): desc="CONFIRMED, DOWNGRADED, or DISMISSED — with a one-paragraph justification"
  - `/home/user/Playground/recursive-lm-security-audit/validator.py:91` (Validator verdict taxonomy labels in code or prompts): Only include CONFIRMED and DOWNGRADED findings. For each finding,
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:22` (Validator verdict taxonomy labels in code or prompts): | Validator Verdict | CONFIRMED |
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:50` (Validator verdict taxonomy labels in code or prompts): | Validator Verdict | CONFIRMED |
```

**Gate**: `wait_for:validator_taxonomy_checkpass_CONFIRMED_DOWNGRADED_DISMISSED`
**Rollback**: Revert validator prompt changes to prior DSPy prompts
**Observability**: Golden verdict labels on flowise-manual-verification.md remain stable; taxonomy parser sees only the allowed labels
**Depends on**: S1, S2

#### Task S5 — Update recursive-lm-security-audit/benchmark.py and recursive-lm-security-audit/batch_runner.py LM configuration paths to Anthropic models while preserving existing benchmark inputs/outputs and the $0.87 scan budget target.

**Files**: `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/recursive-lm-security-audit/benchmark.py, /home/user/Playground/recursive-lm-security-audit/parallel_scanner.py.
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:108` (DSPy LM configuration instances): lm = dspy.LM(model, max_tokens=4000)
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:443` (DSPy LM configuration instances): lm = dspy.LM(model, max_tokens=max_tokens)
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:444` (DSPy LM configuration instances): sub_lm = dspy.LM(sub_model, max_tokens=max_tokens) if sub_model else lm
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:27` (Imports of DSPy framework): import dspy
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:111` (DSPy ChainOfThought module instantiations): extractor = dspy.ChainOfThought(AdvisoryFetcher)
```

**Gate**: `monitor:scan_cost<=0.96_per_full_scan`
**Rollback**: Switch to prior model/config and redeploy_previous
**Observability**: Per-scan cost, token counts, and benchmark timings stay within budget; no regression in batch runner output format
**Depends on**: S1, S2

#### Task S6 — Run dual-write/dual-compare on the committed sample reports by re-running scans for flowise-report.md, juice-shop-audit-report.md, n8n-audit-report.md, and dvsa-audit-report.md with both paths available.

**Files**: `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/recursive-lm-security-audit/README.md, /home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md, /home/user/Playground/recursive-lm-security-audit/validator.py.
  - `/home/user/Playground/recursive-lm-security-audit/validator.py:91` (Validator verdict taxonomy labels in code or prompts): Only include CONFIRMED and DOWNGRADED findings. For each finding,
  - `/home/user/Playground/recursive-lm-security-audit/README.md:14` (Validator verdict taxonomy labels in code or prompts): 6. **(Optional) Adversarial validation**: Each finding goes through a devil's advocate pass that argues FOR and AGAINST 
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:22` (Validator verdict taxonomy labels in code or prompts): | Validator Verdict | CONFIRMED |
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:50` (Validator verdict taxonomy labels in code or prompts): | Validator Verdict | CONFIRMED |
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:89` (Validator verdict taxonomy labels in code or prompts): | Validator Verdict | CONFIRMED |
```

**Gate**: `monitor:report_diff_rate<=0.1`
**Rollback**: Switch back to DSPy path and stop Anthropic-only execution
**Observability**: Diffs in report content, verdict labels, and downstream parser outputs; confirmed findings from flowise-manual-verification.md remain detected
**Depends on**: S3, S4, S5

#### Task S7 — Validate byte-for-byte report/schema compatibility against committed sample reports and downstream adversarial-security-sim/cli.py parsing, including any external scan_*.py wrapper assumptions.

**Files**: `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/n8n-audit-report.md`

**Agent instructions:**

```
Touch these files: /home/user/Playground/recursive-lm-security-audit/README.md, /home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md, /home/user/Playground/recursive-lm-security-audit/n8n-audit-report.md.
  - `/home/user/Playground/recursive-lm-security-audit/README.md:14` (Validator verdict taxonomy labels in code or prompts): 6. **(Optional) Adversarial validation**: Each finding goes through a devil's advocate pass that argues FOR and AGAINST 
  - `/home/user/Playground/recursive-lm-security-audit/README.md:27` (CLI API key environment variable plumbing): export OPENROUTER_API_KEY="your-key-here"
  - `/home/user/Playground/recursive-lm-security-audit/README.md:131` (Validator prosecution defense verdict prompt markers): | `validator.py` | Adversarial validation (prosecution/defense/verdict per finding) |
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:41` (Validator prosecution defense verdict prompt markers): caused both the scanner and the adversarial validator to miss the defense-in-depth sanitization.
  - `/home/user/Playground/recursive-lm-security-audit/n8n-audit-report.md:350` (Validator prosecution defense verdict prompt markers): This removes a critical defense-in-depth mechanism against XSS attacks, clickjacking, and other client-side injection at
```

**Gate**: `wait_for:validation against committed sample reports and downstream parser`
**Rollback**: Restore the previous serializer/output model and redeploy_previous
**Observability**: Parser success rate, field presence/order, and exact output shape remain stable
**Depends on**: S6

#### Task S8 — Perform manual spot-check on flowise-manual-verification.md confirmed findings and verify regenerated reports still classify the 4 real findings as CONFIRMED and the false positive as not CONFIRMED.

**Files**: `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/recursive-lm-security-audit/README.md, /home/user/Playground/recursive-lm-security-audit/benchmark.py, /home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md, /home/user/Playground/recursive-lm-security-audit/validator.py.
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:175` (Validator verdict taxonomy labels in code or prompts): | 1 | Path Traversal (CRITICAL) | CRITICAL | CONFIRMED | **FALSE POSITIVE** | Scanner WRONG, Validator WRONG |
  - `/home/user/Playground/recursive-lm-security-audit/validator.py:91` (Validator verdict taxonomy labels in code or prompts): Only include CONFIRMED and DOWNGRADED findings. For each finding,
  - `/home/user/Playground/recursive-lm-security-audit/README.md:14` (Validator verdict taxonomy labels in code or prompts): 6. **(Optional) Adversarial validation**: Each finding goes through a devil's advocate pass that argues FOR and AGAINST 
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:27` (Imports of DSPy framework): import dspy
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:108` (DSPy LM configuration instances): lm = dspy.LM(model, max_tokens=4000)
```

**Gate**: `wait_for:manual spot-check on flowise-manual-verification.md findings`
**Rollback**: Revert the migration and regenerate reports with the prior DSPy pipeline
**Observability**: Manual ground truth mapping, confirmed count, and any false-positive drift
**Depends on**: S6

#### Task S9 — Complete security review for the Anthropic migration, including emitted report metadata and audit-trail coverage in scanner.py, parallel_scanner.py, and validator.py.

**Files**: `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`

**Agent instructions:**

```
Touch these files: /home/user/Playground/recursive-lm-security-audit/README.md, /home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md.
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:175` (Validator verdict taxonomy labels in code or prompts): | 1 | Path Traversal (CRITICAL) | CRITICAL | CONFIRMED | **FALSE POSITIVE** | Scanner WRONG, Validator WRONG |
  - `/home/user/Playground/recursive-lm-security-audit/README.md:14` (Validator verdict taxonomy labels in code or prompts): 6. **(Optional) Adversarial validation**: Each finding goes through a devil's advocate pass that argues FOR and AGAINST 
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:22` (Validator verdict taxonomy labels in code or prompts): | Validator Verdict | CONFIRMED |
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:41` (Validator prosecution defense verdict prompt markers): caused both the scanner and the adversarial validator to miss the defense-in-depth sanitization.
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:50` (Validator verdict taxonomy labels in code or prompts): | Validator Verdict | CONFIRMED |
```

**Gate**: `approval:security_review`
**Rollback**: Redeploy_previous
**Observability**: Review signoff notes, metadata completeness, and no loss of traceability in prompts/call paths
**Depends on**: S3, S4, S7

#### Task S10 — Send customer/downstream communication about the preserved CONFIRMED/DOWNGRADED/DISMISSED taxonomy, CLI compatibility, and any externally visible Anthropic migration behavior.

**Files**: `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/recursive-lm-security-audit/README.md, /home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md, /home/user/Playground/recursive-lm-security-audit/validator.py.
  - `/home/user/Playground/recursive-lm-security-audit/README.md:14` (Validator verdict taxonomy labels in code or prompts): 6. **(Optional) Adversarial validation**: Each finding goes through a devil's advocate pass that argues FOR and AGAINST 
  - `/home/user/Playground/recursive-lm-security-audit/validator.py:81` (Validator verdict taxonomy labels in code or prompts): desc="CONFIRMED, DOWNGRADED, or DISMISSED — with a one-paragraph justification"
  - `/home/user/Playground/recursive-lm-security-audit/validator.py:91` (Validator verdict taxonomy labels in code or prompts): Only include CONFIRMED and DOWNGRADED findings. For each finding,
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:22` (Validator verdict taxonomy labels in code or prompts): | Validator Verdict | CONFIRMED |
  - `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md:50` (Validator verdict taxonomy labels in code or prompts): | Validator Verdict | CONFIRMED |
```

**Gate**: `wait_for:customer_comms_sent`
**Rollback**: Revert prompts and outputs to the last shipped DSPy-based behavior
**Observability**: Notice delivered to downstream consumers; support inbox and release notes updated
**Depends on**: S1, S4, S7

#### Task S11 — Obtain named rollout owner and launch a production rollout only outside incident windows, Friday afternoon, launch windows, and major customer event freezes; keep the Anthropic runtime toggle available for immediate fallback.

**Files**: `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py`

**Agent instructions:**

```
Touch these files: /home/user/Playground/recursive-lm-security-audit/benchmark.py, /home/user/Playground/recursive-lm-security-audit/parallel_scanner.py.
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:27` (Imports of DSPy framework): import dspy
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:108` (DSPy LM configuration instances): lm = dspy.LM(model, max_tokens=4000)
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:111` (DSPy ChainOfThought module instantiations): extractor = dspy.ChainOfThought(AdvisoryFetcher)
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:443` (DSPy LM configuration instances): lm = dspy.LM(model, max_tokens=max_tokens)
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:444` (DSPy LM configuration instances): sub_lm = dspy.LM(sub_model, max_tokens=max_tokens) if sub_model else lm
```

**Gate**: `approval:named_rollout_owner`
**Rollback**: Disable Anthropic mode and fall back to DSPy path
**Observability**: Rollout window compliance, incident status, owner presence, and immediate rollback readiness
**Depends on**: S9, S10, S8

#### Task S12 — Flip the default path to Anthropic in cli.py and all LM call sites after the guarded rollout window, while retaining the compatibility shim for external scripts and the DSPy fallback for one release window.

**Files**: `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/n8n-audit-report.md`

**Agent instructions:**

```
Touch these files: /home/user/Playground/recursive-lm-security-audit/README.md, /home/user/Playground/recursive-lm-security-audit/benchmark.py, /home/user/Playground/recursive-lm-security-audit/n8n-audit-report.md.
  - `/home/user/Playground/recursive-lm-security-audit/README.md:27` (CLI API key environment variable plumbing): export OPENROUTER_API_KEY="your-key-here"
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:27` (Imports of DSPy framework): import dspy
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:108` (DSPy LM configuration instances): lm = dspy.LM(model, max_tokens=4000)
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:111` (DSPy ChainOfThought module instantiations): extractor = dspy.ChainOfThought(AdvisoryFetcher)
  - `/home/user/Playground/recursive-lm-security-audit/benchmark.py:443` (DSPy LM configuration instances): lm = dspy.LM(model, max_tokens=max_tokens)
```

**Gate**: `window:2 releases after merge`
**Rollback**: Prefer DSPy client path and disable Anthropic-only calls
**Observability**: Provider selection distribution, fallback rate, and downstream consumer success remain stable
**Depends on**: S11

## Plan: 02-speed-leaning

### Plan `02-speed-leaning`

| # | Action | Owner | Files | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Add Anthropic client/config plumbing and CLI shims in recursive-lm-security-audi | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py` | `wait_for:anthropic_key_and_model_selection_verified` | Restore prior argparse surface and DSPy-backed wir |
| S2 | Rotate Anthropic/OpenRouter API keys and verify secrets are available for live s | Security | `/home/user/Playground/recursive-lm-security-audit/README.md` | `wait_for:secrets_rotation_complete` | Revoke new keys and restore prior key material/con |
| S3 | Rewrite recursive-lm-security-audit/scanner.py and parallel_scanner.py to use an | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `monitor:confirmed_findings_retained=100%` | Redeploy previous DSPy-based scanner implementatio |
| S4 | Replace recursive-lm-security-audit/validator.py prosecution/defense/verdict DSP | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `wait_for:validator_taxonomy_checkpass_CONFIRMED_DOWNGRADED_DISMISSED` | Revert validator prompt changes to prior DSPy prom |
| S5 | Update recursive-lm-security-audit/benchmark.py and batch_runner.py LM configura | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py` | `monitor:scan_cost<=0.96_per_full_scan` | Switch to prior model/config and redeploy_previous |
| S6 | Run dual-write/dual-compare scans for flowise-report.md, juice-shop-audit-report | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `monitor:report_diff_rate<=0.1` | Switch back to DSPy path and stop Anthropic-only e |
| S7 | Validate committed sample reports and downstream parser compatibility in recursi | DataPlatform | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/n8n-audit-report.md` | `wait_for:validation against committed sample reports and downstream parser` | Restore the previous serializer/output model and r |
| S8 | Run manual spot-check on flowise-manual-verification.md confirmed findings and v | DataPlatform | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `wait_for:manual spot-check on flowise-manual-verification.md findings` | Revert the migration and regenerate reports with t |
| S9 | Prepare and publish migration notice and downstream consumer comms for cli.py be | ProductPM | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `approval:support_lead` | Remove migration notice and restore prior document |
| S10 | Assign a named rollout owner and confirm escalation routing for scanner.py, para | ProductPM | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `approval:named_rollout_owner` | Pause rollout and route incidents to the named own |
| S11 | Cut over production CLI/runners to the Anthropic path with the runtime toggle en | SRE | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `window:exclude_friday_afternoon_and_incident_windows` | Disable Anthropic mode and fall back to DSPy path. |
| S12 | Remove dspy-ai from recursive-lm-security-audit/requirements.txt once the Anthro | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py` | `none` | Restore dspy-ai and previous lockfile/dependency p |

## Plan: 03-safety-tilted

### Plan `03-safety-tilted`

| # | Action | Owner | Files | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Add Anthropic client plumbing and compatibility shim in recursive-lm-security-au | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `approval:named_rollout_owner` | Disable Anthropic mode and restore prior DSPy-back |
| S2 | Rotate Anthropic/OpenRouter secrets and verify credentials for a no-op Anthropic | Security | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/n8n-audit-report.md` | `wait_for:secrets_rotation_complete` | Revoke new keys and restore prior key material/con |
| S3 | Rewrite recursive-lm-security-audit/scanner.py to replace dspy.LM/dspy.Predict/d | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `monitor:confirmed_findings_retained=100%` | Switch scanner.py back to the prior DSPy implement |
| S4 | Rewrite recursive-lm-security-audit/parallel_scanner.py chunked scan and report  | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py` | `monitor:confirmed_findings_retained=100%` | Fall back to the DSPy chunked scanner path and pre |
| S5 | Rewrite recursive-lm-security-audit/validator.py prosecution/defense/verdict pro | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `wait_for:validator_taxonomy_checkpass_CONFIRMED_DOWNGRADED_DISMISSED` | Revert validator.py prompt logic to the prior DSPy |
| S6 | Update recursive-lm-security-audit/benchmark.py and batch_runner.py model config | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py` | `monitor:scan_cost<=0.96_per_full_scan` | Switch benchmark/batch runner back to the prior mo |
| S7 | Run dual-write/dual-compare scans on the committed sample reports flowise-report | DataPlatform | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `monitor:report_diff_rate<=0.1` | Switch back to the DSPy path and stop Anthropic-on |
| S8 | Validate regenerated outputs against the downstream adversarial-security-sim/cli | ConsumerSubsystem | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/n8n-audit-report.md` | `wait_for:validation against committed sample reports and downstream parser` | Restore the previous serializer/output model and r |
| S9 | Perform manual spot-check on flowise-manual-verification.md against the regenera | DataPlatform | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `wait_for:manual spot-check on flowise-manual-verification.md findings` | Revert the migration and regenerate reports with t |
| S10 | Run validator golden-diff checks to ensure the verdict taxonomy remains stable a | Security | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md`, `/home/user/Playground/recursive-lm-security-audit/validator.py` | `approval:security_review` | Restore previous verdict prompt and parser behavio |
| S11 | Publish migration notice and update CLI usage/docs in recursive-lm-security-audi | ProductPM | `/home/user/Playground/recursive-lm-security-audit/README.md`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `approval:support_lead` | Remove migration notice and restore prior document |
| S12 | Flip the runtime default to Anthropic for scanner/validator/benchmark/batch path | SRE | `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/flowise-manual-verification.md` | `window:exclude_friday_afternoon_and_incident_windows` | Disable Anthropic default and fall back to the pri |
| S13 | Remove dspy-ai from recursive-lm-security-audit/requirements.txt only after the  | BackendOwner | `/home/user/Playground/recursive-lm-security-audit/benchmark.py`, `/home/user/Playground/recursive-lm-security-audit/parallel_scanner.py` | `monitor:error_rate<X for 24h` | Re-add dspy-ai and restore the previous dependency |

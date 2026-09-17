# Jev Triage

Fast, calibrated triage of security-scanner findings using [TypeSafe's **Jev**](https://typesafe.ai/blog/introducing-system-one-models-and-jev) — a "System One" model that takes unstructured state in and returns **typed, probabilistic decisions** out (no free-form prose).

## Why

The two other Playground security experiments — [`recursive-lm-security-audit/`](../recursive-lm-security-audit/) and [`vulnllm-analyzer/`](../vulnllm-analyzer/) — both hit the classic scanner wall: **too many false positives and miscalibrated severities.**

The RLM auditor's own [`flowise-manual-verification.md`](../recursive-lm-security-audit/flowise-manual-verification.md) is the smoking gun:

- its **#1 CRITICAL** finding was a **false positive** that even an expensive adversarial-LLM validation pass "CONFIRMED";
- a hardcoded-JWT-secret issue was rated **MEDIUM** when it's really **HIGH/CRITICAL**;
- the single most dangerous real bug (an unauthenticated OAuth2 token endpoint) was **missed entirely**.

That adversarial-LLM validation costs roughly **one full LLM call per finding** and still gets calibration wrong, because it produces another paragraph of prose that then has to be re-parsed.

Jev is built for exactly this decision shape. Instead of prose it returns calibrated probabilities for typed questions, at ~70–500 ms and **$0.042/MTok input (output free)**. So we use it as a cheap triage gate that runs **before** (or instead of) the expensive validation pass:

```
raw findings ──▶ Jev triage (typed, calibrated) ──▶ keep / drop / re-rank ──▶ human review
```

## How it works

For each finding, `jev-triage` asks Jev **four typed questions in a single call**:

| Key | Type | Question |
|-----|------|----------|
| `is_real` | Noul (yes/no) | Genuine exploitable vuln, or a false positive / intended design? |
| `reachable` | Noul (yes/no) | Reachable with attacker-controlled input in a real deployment? |
| `severity` | Score (5 levels) | Calibrated severity: Informational → Low → Medium → High → Critical |
| `category` | Choice | Vulnerability class (injection, auth, crypto, path traversal, …) |

It then applies calibrated thresholds: keep a finding when `P(is_real) ≥ --is-real-threshold` **and** `P(reachable) ≥ --reachable-threshold`, and **re-label its severity from Jev's calibrated score** rather than trusting the scanner's guess. Everything is ranked by severity then confidence.

## Install

```bash
pip install -r requirements.txt
cp .env.example .env   # then set TYPESAFE_API_KEY
```

The client uses the official `typesafe-sdk` automatically when it's installed, and otherwise falls back to a raw HTTPS call against `https://api.typesafe.ai/v1/systemone`. No keys are stored in the repo — `TYPESAFE_API_KEY` is read from the environment.

## Usage

```bash
# Triage a JSON findings file
python cli.py example_findings.json

# Triage an upstream RLM auditor report (markdown), stricter thresholds
python cli.py ../recursive-lm-security-audit/dvsa-audit-report.md \
    --is-real-threshold 0.7 --reachable-threshold 0.6

# Write markdown + JSON reports
python cli.py example_findings.json -o triaged.md --json triaged.json

# Offline demo — no API key, no network (stubbed Jev backend)
python cli.py example_findings.json --demo
```

### Input formats

1. **JSON** — a list of findings (or `{"findings": [...]}`); see [`example_findings.json`](example_findings.json).
2. **Markdown** — the RLM auditor's report style, where findings are `###` headers (`VULN-01: …` / `1. …`) with `**Location**` / `**Severity**` / `**CWE**` fields.

## Demo output

```
  [1/6] KEEP  VULN-01    real=0.81 reach=0.62 sev=Critical      Remote Code Execution via eval() in admin shell
  [2/6] KEEP  VULN-02    real=1.00 reach=0.62 sev=Critical      SQL injection in login via string interpolation
  [4/6] KEEP  VULN-04    real=0.76 reach=0.60 sev=Critical      Hardcoded default JWT signing secret   ← re-rated Medium→Critical
  [5/6] drop  VULN-05    real=0.00 reach=0.65 sev=Medium        Path traversal (sanitized) — false positive
  [6/6] drop  VULN-06    real=0.00 reach=0.62 sev=Low           Verbose error messages — informational
```

The stub in `--demo` mode drops the two non-issues, keeps the four real bugs, and re-calibrates the JWT secret up to Critical — the exact class of mistake the RLM validator made by hand.

## Files

| File | Purpose |
|------|---------|
| `jev_client.py` | Jev adapter: `typesafe-sdk` when present, else raw HTTP; normalizes responses |
| `findings.py` | `Finding` model + JSON and markdown-report parsers |
| `triage.py` | Question battery, threshold logic, keep/drop + severity re-labeling |
| `report.py` | Markdown + JSON report writers |
| `cli.py` | CLI entry point |
| `demo_backend.py` | Offline stub Jev backend for `--demo` (heuristic, **not** Jev) |
| `test_triage.py` | Offline tests (no key/network) |
| `example_findings.json` | Sample findings against deliberately-vulnerable teaching apps |

## Notes & limitations

- **Jev outputs calibrated probabilities, not verdicts.** Kept findings are *prioritized leads for a human*, not confirmed bugs. This narrows the haystack; it doesn't replace review.
- Triage quality is bounded by the context each finding carries. Passing a real code snippet in `code` helps a lot; a bare one-line title helps little.
- The `--demo` backend is a crude keyword heuristic to exercise the plumbing offline. Its numbers are fabricated — use a real `TYPESAFE_API_KEY` for anything real.
- **Only feed this findings you're allowed to publish.** `example_findings.json` deliberately targets OWASP DVSA / Juice Shop (intentionally vulnerable). Do not commit triage output for real production software — see the repo's [`PUBLISHING.md`](../PUBLISHING.md).

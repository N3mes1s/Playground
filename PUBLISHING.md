# Publishability Review

_Last reviewed: 2026-09-17_

This note assesses which Playground experiments (and, importantly, which of
their **outputs**) are safe to publish, and which are not. Two separate axes
matter:

1. **Code / tooling** — is the source clean (no secrets, no private data) and
   presentable?
2. **Findings / reports** — does the output disclose real, unfixed
   vulnerabilities in software other people run? That is a **responsible-
   disclosure** question, independent of code quality.

The short version: **all the tooling is publishable; the security reports are
only publishable when the target is a deliberately-vulnerable teaching app.**
Reports against real production software must go through coordinated disclosure
first.

## Ground rules used here

- **Intentionally-vulnerable targets** (OWASP DVSA, OWASP Juice Shop) exist to
  be exploited and written about. Publishing findings against them is fine and
  is the point of those projects.
- **Real production software** (n8n, Flowise, Sliver, Bottle, …) is different.
  Publishing unverified — or even verified-but-unpatched — vulnerabilities is
  0-day disclosure. It needs a fixed version or a coordinated-disclosure
  timeline first, regardless of how interesting the finding is.
- **Reliability caveat.** These pipelines demonstrably emit false positives
  that survive their own validation, and miscalibrate severity (see
  `recursive-lm-security-audit/flowise-manual-verification.md`). Nothing here
  should be published as a security *claim* without human verification.

## Verdicts

### ✅ Publishable

| Item | Why |
|------|-----|
| `vulnllm-analyzer/` **source code** | No secrets committed (`.env` gitignored; Modal token supplied at runtime). Clean tooling. |
| `recursive-lm-security-audit/` **source code** | Same — API keys read from env, `.env.example` only. |
| `jev-triage/` **source + `example_findings.json`** | New experiment; example targets DVSA/Juice Shop only. No secrets. |
| `recursive-lm-security-audit/dvsa-audit-report.md` | Target is OWASP **DVSA**, deliberately vulnerable. |
| `recursive-lm-security-audit/juice-shop-audit-report.md` | Target is OWASP **Juice Shop**, deliberately vulnerable. |
| CVE benchmark methodology + **aggregate** metrics (`benchmark-results/summary.md`, `benchmark.py`, `benchmark_advisories.py`) | Uses public GHSA advisories; the write-up is about the method. See caveat below. |

### ⚠️ Publishable only with edits / caveats

| Item | Caveat |
|------|--------|
| CVE benchmark **numbers** | Weak and incomplete: run stopped at **45/100** advisories, **17.8%** detection, **37.8%** errored (mostly 900 s timeouts). Fine as an honest "here's what didn't work yet" post; **not** fine framed as a capability claim. Finish the run or label it clearly as partial. |
| `flowise-manual-verification.md` **as a methodology critique** | Its lesson (scanner + validator both confirmed a false positive; missed the worst real bug) is genuinely worth publishing — but the document **names real, exploitable, likely-unpatched vulnerabilities in FlowiseAI/Flowise**. Rewrite to abstract the target before publishing, or hold until disclosed/fixed. |

### ❌ Not publishable as-is (coordinated disclosure required)

| Item | Reason |
|------|--------|
| `recursive-lm-security-audit/n8n-audit-report.md` | Target is **n8n-io/n8n** (real, widely deployed). Claims Critical auth bypass, credential exfiltration via test endpoint, JWT weaknesses. Publishing = 0-day disclosure. |
| `recursive-lm-security-audit/flowise-report.md` | Target is **FlowiseAI/Flowise** (real). 18 "Critical" claims incl. RCE. Unverified and unfixed. |
| `recursive-lm-security-audit/flowise-manual-verification.md` (as-is) | Confirms **real** CRITICAL/HIGH issues in Flowise, including an unauthenticated OAuth2 token endpoint. This is exactly the material that must be disclosed privately first. |
| `vulnllm-analyzer/scan_sliver*.py` **outputs** | Target is **BishopFox/Sliver** (a real offensive-security C2 framework). Scanning + publishing findings is sensitive on both disclosure and dual-use grounds. Scripts are fine; results are not. |
| `vulnllm-analyzer/scan_bottle.py` **outputs** | Target is **bottlepy/bottle** (real, very widely used web framework). Same disclosure rule. |

## Recommendation

1. **Ship the tooling and the intentionally-vulnerable-target reports** (DVSA,
   Juice Shop) plus honestly-labeled methodology write-ups.
2. **Gate real-target reports** (n8n, Flowise, Sliver, Bottle) behind a
   `DISCLOSURE.md` process: verify manually → report to maintainers → wait for
   a fix / agreed timeline → then publish.
3. **Never publish a raw finding as a claim.** Route findings through manual
   verification — `jev-triage/` exists to make that first-pass cheaper and
   better-calibrated, but a human still confirms before anything external.
4. Consider moving the real-target report files out of the default branch (or
   into an ignored `reports/private/` path) so they aren't published by
   accident.

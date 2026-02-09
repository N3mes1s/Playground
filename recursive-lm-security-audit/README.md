# Recursive LM Security Auditor

Automated security vulnerability scanner powered by [DSPy's RLM (Recursive Language Model)](https://dspy.ai/api/modules/RLM/) module. Instead of feeding an entire codebase into a single prompt, RLM decomposes the analysis into recursive sub-tasks -- each handled by a sub-LM call -- and synthesizes results hierarchically.

Based on [Kevin Madura's experiment](https://kmad.ai/Recursive-Language-Models-Security-Audit) auditing the OWASP DVSA for ~$0.87.

## How it works

1. The codebase is loaded into a nested dictionary preserving folder/file hierarchy
2. DSPy's `RLM` module receives this dictionary as a Python variable (not in the prompt)
3. The RLM generates Python code in a sandboxed REPL to explore the source tree
4. It recursively calls `llm_query()` to analyze individual files/sections for vulnerabilities
5. Results are synthesized into a structured markdown security audit report
6. **(Optional) Adversarial validation**: Each finding goes through a devil's advocate pass that argues FOR and AGAINST the vulnerability, then delivers a verdict: CONFIRMED, DOWNGRADED, or DISMISSED

The validation phase exists because raw scanners produce ~50%+ false positives. A pattern like "read-only user triggers decryption" looks suspicious, but if that's the only way the feature can work, it's not a vulnerability -- it's the design. The validator asks: *"Does the attacker gain anything they don't already have?"*

## Setup

```bash
pip install -r requirements.txt
```

Set your API key for the model provider you want to use:

```bash
export OPENROUTER_API_KEY="your-key-here"
```

## Usage

### Scan a GitHub repository

```bash
python cli.py https://github.com/OWASP/DVSA
```

### Scan a local directory

```bash
python cli.py /path/to/your/project
```

### Use a different model

```bash
# Use grok-4 via OpenRouter
python cli.py https://github.com/org/repo --model openrouter/x-ai/grok-4

# Use a cheaper sub-model for recursive calls (cost optimization)
python cli.py ./my-app --model openrouter/x-ai/grok-4 --sub-model openrouter/moonshotai/kimi-k2.5
```

### Save report to file

```bash
python cli.py https://github.com/org/repo -o audit-report.md
```

### Scan a specific branch

```bash
python cli.py https://github.com/org/repo --branch develop
```

### Scan + validate (recommended)

Runs the scanner, then subjects each finding to adversarial validation:

```bash
python cli.py https://github.com/org/repo --validate -o report.md
```

### Validate an existing report

Already have a raw report? Run just the validation pass:

```bash
python cli.py --validate-report raw-report.md --source /path/to/source -o validated.md

# Or against a GitHub repo
python cli.py --validate-report raw-report.md --source https://github.com/org/repo -o validated.md
```

### Large repos (parallel scanning)

Auto-detected for repos >2MB of source. Force with `--parallel`:

```bash
python cli.py https://github.com/n8n-io/n8n --parallel --workers 3 --validate
```

## What it detects

From the original experiment against OWASP DVSA (6/10 vulnerability categories found):

| Detected | Missed |
|----------|--------|
| Event injection | Broken authentication |
| Sensitive data disclosure | Denial of service |
| Insecure cloud configuration | Logic vulnerabilities |
| Broken access control | Vulnerable dependencies |
| Over-privileged functions | |
| Unhandled exceptions | |

Specific findings include: RCE via `eval()`, command injection, insecure deserialization, and privilege escalation vectors.

## Architecture

```
scan phase          validate phase          output
┌─────────┐        ┌──────────────┐        ┌────────┐
│ RLM     │───────▶│ Extract      │───────▶│ Final  │
│ Scanner │ raw    │ findings     │ parsed │ Report │
│         │ report │              │        │        │
│ (or     │        │ For each:    │        │ Only   │
│ parallel│        │  Prosecution │        │ real   │
│ chunks) │        │  Defense     │        │ vulns  │
│         │        │  Verdict     │        │        │
└─────────┘        └──────────────┘        └────────┘
                   ▲ uses RLM to read
                   │ actual source code
```

### Files

| File | Purpose |
|------|---------|
| `scanner.py` | Core RLM scanner (CodeScanner signature, source tree loader) |
| `parallel_scanner.py` | Chunking + concurrent scanning for large repos |
| `validator.py` | Adversarial validation (prosecution/defense/verdict per finding) |
| `cli.py` | CLI entry point with all flags |

## Limitations

- Static analysis only -- cannot detect runtime/timing-dependent vulnerabilities
- Does not assess external dependency CVEs (use `pip-audit`, `npm audit`, etc. for that)
- Not a replacement for a proper human security audit or penetration test
- Cost and quality depend heavily on the chosen model
- Validation adds ~1 RLM call per finding (worth it for reducing false positives)

## Cost

The original experiment cost ~$0.87 for a full scan with 35 iterations using kimi-k2.5 via OpenRouter.

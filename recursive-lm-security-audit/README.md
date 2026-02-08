# Recursive LM Security Auditor

Automated security vulnerability scanner powered by [DSPy's RLM (Recursive Language Model)](https://dspy.ai/api/modules/RLM/) module. Instead of feeding an entire codebase into a single prompt, RLM decomposes the analysis into recursive sub-tasks -- each handled by a sub-LM call -- and synthesizes results hierarchically.

Based on [Kevin Madura's experiment](https://kmad.ai/Recursive-Language-Models-Security-Audit) auditing the OWASP DVSA for ~$0.87.

## How it works

1. The codebase is loaded into a nested dictionary preserving folder/file hierarchy
2. DSPy's `RLM` module receives this dictionary as a Python variable (not in the prompt)
3. The RLM generates Python code in a sandboxed REPL to explore the source tree
4. It recursively calls `llm_query()` to analyze individual files/sections for vulnerabilities
5. Results are synthesized into a structured markdown security audit report

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

### All options

```
usage: cli.py [-h] [--model MODEL] [--sub-model SUB_MODEL]
              [--max-tokens MAX_TOKENS] [--max-iterations MAX_ITERATIONS]
              [--branch BRANCH] [-o OUTPUT] [-q] target

positional arguments:
  target                Local path or GitHub/Git URL of the repository to scan

options:
  --model MODEL         Primary LM model identifier (default: openrouter/moonshotai/kimi-k2.5)
  --sub-model SUB_MODEL Model for recursive sub-queries (defaults to same as --model)
  --max-tokens N        Max tokens per LM call (default: 16000)
  --max-iterations N    Maximum REPL iterations for the RLM (default: 35)
  --branch BRANCH       Git branch to clone (default: default branch)
  -o, --output FILE     Write the report to a file instead of stdout
  -q, --quiet           Disable verbose RLM logging
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

## Limitations

- Static analysis only -- cannot detect runtime/timing-dependent vulnerabilities
- Does not assess external dependency CVEs (use `pip-audit`, `npm audit`, etc. for that)
- Not a replacement for a proper human security audit or penetration test
- Cost and quality depend heavily on the chosen model

## Cost

The original experiment cost ~$0.87 for a full scan with 35 iterations using kimi-k2.5 via OpenRouter.

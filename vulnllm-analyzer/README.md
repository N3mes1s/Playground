# VulnLLM Analyzer

Automated vulnerability analysis for GitHub repositories using [VulnLLM-R-7B](https://github.com/ucsb-mlsec/VulnLLM-R), served on [Modal](https://modal.com) GPUs.

Give it a GitHub URL -- it clones the repo, detects the language, and runs every source file through VulnLLM-R for security analysis.

## Architecture

```
┌──────────────┐      ┌──────────────────┐      ┌─────────────────────────┐
│  analyzer.py │─────▶│  repo_fetcher.py │─────▶│  modal_service.py       │
│  (CLI entry) │      │  (clone + detect)│      │  (GPU inference on A10G)│
└──────────────┘      └──────────────────┘      │  vLLM + VulnLLM-R-7B   │
                                                 └─────────────────────────┘
```

- **`repo_fetcher.py`** -- shallow-clones the repo, walks the tree, detects languages by extension, collects source files
- **`modal_service.py`** -- Modal app that loads VulnLLM-R-7B with vLLM on an A10G GPU; exposes both Modal class methods and a FastAPI endpoint
- **`analyzer.py`** -- CLI that ties it all together: fetch → detect → analyze → report

## Supported Languages

VulnLLM-R was trained on **C/C++, Python, Java** (best accuracy). The tool also recognizes JavaScript, TypeScript, Go, Rust, Ruby, PHP, C#, Swift, Kotlin, Scala, and Solidity -- the model can do zero-shot analysis on these but results may be less precise.

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Authenticate with Modal

```bash
modal token set --token-id <your-id> --token-secret <your-secret>
# or interactive:
modal setup
```

No API keys are stored in this repo. You provide your Modal token at setup time.

### 3. Deploy the GPU service

```bash
# Persistent deployment (recommended):
modal deploy modal_service.py

# Or ephemeral for testing:
modal serve modal_service.py
```

## Usage

### CLI

```bash
# Analyze a repo (auto-detects languages):
python analyzer.py https://github.com/owner/repo

# Focus on specific languages:
python analyzer.py https://github.com/owner/repo --languages python java

# Limit scope:
python analyzer.py https://github.com/owner/repo --max-files 20

# Save JSON report:
python analyzer.py https://github.com/owner/repo --output report.json

# Local inference (needs local GPU, no Modal):
python analyzer.py https://github.com/owner/repo --local
```

### REST API (via Modal web endpoint)

Once deployed, Modal provides a URL. You can call it directly:

```bash
# Health check
curl https://<your-modal-app>.modal.run/health

# Analyze a single snippet
curl -X POST https://<your-modal-app>.modal.run/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "void f(char *s) { char buf[10]; strcpy(buf, s); }",
    "language": "c",
    "filename": "vuln.c"
  }'

# Batch analysis
curl -X POST https://<your-modal-app>.modal.run/analyze/batch \
  -H "Content-Type: application/json" \
  -d '{
    "items": [
      {"code": "import pickle; pickle.loads(data)", "language": "python", "filename": "loader.py"},
      {"code": "printf(user_input);", "language": "c", "filename": "log.c"}
    ]
  }'
```

## Cost Estimate

Modal bills per-second of GPU time. With an A10G:
- Cold start (model download + load): ~2-3 min first time, ~30s after caching
- Per-file analysis: ~2-5 seconds
- A 100-file repo: ~$0.10-0.50 depending on file sizes

The container auto-scales down after 5 minutes of idle time (`container_idle_timeout=300`).

## Example Output

```
======================================================================
  VulnLLM-R Analysis Report: owner/repo
======================================================================
  Repository:   https://github.com/owner/repo
  Languages:    c (45 files), python (12 files)
  Analyzed:     57 files (3 skipped)
  Duration:     34.2s

  VULNERABLE:       4
  NOT VULNERABLE:   51
  UNCERTAIN:        2
======================================================================

  Vulnerable files:
    - src/parser.c (c)
    - src/auth.py (python)
    - lib/network.c (c)
    - util/crypto.c (c)
```

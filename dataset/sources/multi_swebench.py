"""Multi-SWE-Bench ingester (ByteDance-Seed/Multi-SWE-bench).

Multilingual coverage (Java, TypeScript, JavaScript, Python, Go, Rust,
C, C++). Same schema shape as SWE-Bench. We map per-row into our
unified schema with `language` set from the repo language metadata.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "dataset" / "data" / "real"


_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)
_TOK = re.compile(r"[A-Za-z][A-Za-z0-9_]+")


def _patch_files(patch: str) -> list[str]:
    return _FILE_RE.findall(patch or "")


def _patch_tokens(patch: str) -> list[str]:
    noise = {
        "self", "this", "return", "import", "from", "none", "null",
        "true", "false", "for", "with", "into", "test", "tests",
        "args", "kwargs", "value", "default", "class", "function",
    }
    out: dict[str, int] = {}
    for line in (patch or "").splitlines():
        if not (line.startswith("+") or line.startswith("-")):
            continue
        if line.startswith("+++") or line.startswith("---"):
            continue
        for t in _TOK.findall(line):
            tl = t.lower()
            if len(tl) > 3 and tl not in noise:
                out[tl] = out.get(tl, 0) + 1
    return [t for t, _ in sorted(out.items(), key=lambda kv: -kv[1])[:30]]


_LANG_FROM_REPO = {
    "spring": "java", "google": "java", "alibaba": "java",
    "microsoft/TypeScript": "typescript", "vercel/next.js": "typescript",
    "rust-lang": "rust", "tokio-rs": "rust",
    "golang": "go", "gin-gonic": "go",
    "nodejs": "javascript", "expressjs": "javascript",
    "python": "python", "pandas-dev": "python",
}


def _row_to_element(row: dict) -> dict:
    repo = row.get("repo", "")
    instance_id = row.get("instance_id", "")
    files = _patch_files(row.get("patch", ""))
    tokens = _patch_tokens(row.get("patch", ""))
    language = None
    for hint, lang in _LANG_FROM_REPO.items():
        if hint.lower() in repo.lower():
            language = lang
            break
    if not language:
        # Heuristic from filenames in patch
        for f in files:
            for ext, lang in {".java": "java", ".ts": "typescript",
                              ".tsx": "typescript", ".js": "javascript",
                              ".rs": "rust", ".go": "go",
                              ".py": "python", ".cpp": "cpp",
                              ".c": "c"}.items():
                if f.endswith(ext):
                    language = lang
                    break
            if language:
                break
    return {
        "id": f"multi_swebench/{instance_id}",
        "source": "multi_swebench",
        "kind": "code_change",
        "title": instance_id,
        "intent_md": (
            f"# {instance_id}\n\n"
            f"**Repository**: `{repo}`\n"
            f"**Language**: `{language or 'unknown'}`\n\n"
            f"## Problem statement\n\n"
            f"{(row.get('problem_statement') or '').strip()[:8000]}\n\n"
            f"## What we're asking\n\nProduce a plan and a diff sketch."
        ),
        "repo": repo,
        "repo_clone_url": f"https://github.com/{repo}.git" if repo else None,
        "language": language,
        "ground_truth": {
            "kind": "patch",
            "files_touched": files,
            "root_cause_keywords": tokens,
            "outcome": "shipped_clean",
            "patch_uri": None,
        },
        "metadata": {
            "patch_length": len(row.get("patch", "")),
            "tags": ["multi-swebench", language or "unknown"],
        },
    }


def ingest() -> int:
    from datasets import load_dataset

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "multi_swebench.jsonl"
    if out_path.exists() and out_path.stat().st_size > 0:
        existing = sum(1 for _ in out_path.open())
        print(f"[skip] {out_path} ({existing} rows)", file=sys.stderr)
        return existing

    n = 0
    # Multi-SWE-Bench has multiple splits per language; try all.
    print("[load] ByteDance-Seed/Multi-SWE-bench", file=sys.stderr)
    try:
        ds = load_dataset("ByteDance-Seed/Multi-SWE-bench", split="test")
    except Exception as e:
        print(f"[err] {e}", file=sys.stderr)
        # fallback: try without split
        try:
            ds_dict = load_dataset("ByteDance-Seed/Multi-SWE-bench")
            ds = []
            for s in ds_dict.values():
                ds.extend(list(s))
        except Exception as ee:
            print(f"[err2] {ee}", file=sys.stderr)
            return 0

    with out_path.open("w") as f:
        for row in ds:
            elem = _row_to_element(dict(row))
            f.write(json.dumps(elem) + "\n")
            n += 1
    print(f"[done] wrote {n} rows", file=sys.stderr)
    return n


if __name__ == "__main__":
    ingest()

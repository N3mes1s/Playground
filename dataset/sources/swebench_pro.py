"""SWE-Bench Pro + Verified ingester.

Pulls the HuggingFace datasets, normalises each row to our schema,
writes JSONL under dataset/data/real/.

Each SWE-Bench element becomes a `code_change` intent: an issue and
its problem_statement become the rollout intent body. The canonical
patch is recorded as ground truth (files touched + distinctive
tokens) for later "did the pipeline's plan touch the right files?"
scoring.
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


def _patch_distinctive_tokens(patch: str, max_n: int = 30) -> list[str]:
    noise = {
        "self", "return", "import", "from", "none", "true", "false",
        "the", "and", "for", "with", "this", "that", "into", "test",
        "tests", "args", "kwargs", "value", "default", "none",
    }
    out: dict[str, int] = {}
    for line in (patch or "").splitlines():
        if not (line.startswith("+") or line.startswith("-")):
            continue
        if line.startswith("+++") or line.startswith("---"):
            continue
        for t in _TOK.findall(line):
            tl = t.lower()
            if len(tl) <= 3 or tl in noise:
                continue
            out[tl] = out.get(tl, 0) + 1
    return [t for t, _ in sorted(out.items(), key=lambda kv: -kv[1])[:max_n]]


def _intent_from_row(row: dict, source: str) -> str:
    return (
        f"# {row['instance_id']}\n\n"
        f"**Repository**: `{row['repo']}` at `{row['base_commit'][:8]}`\n"
        f"**Source**: `{source}`\n\n"
        f"## Problem statement\n\n"
        f"{row.get('problem_statement', '').strip()[:8000]}\n\n"
        f"## What we're asking\n\nProduce a plan and a diff sketch that "
        f"would resolve this issue. Identify the file(s) you'd touch and "
        f"the key edits."
    )


def _row_to_element(row: dict, *, source: str) -> dict:
    files = _patch_files(row.get("patch", ""))
    tokens = _patch_distinctive_tokens(row.get("patch", ""))
    return {
        "id": f"{source}/{row['instance_id']}",
        "source": source,
        "kind": "code_change",
        "title": row["instance_id"],
        "intent_md": _intent_from_row(row, source),
        "repo": row["repo"],
        "repo_clone_url": f"https://github.com/{row['repo']}.git",
        "language": "python",
        "ground_truth": {
            "kind": "patch",
            "files_touched": files,
            "root_cause_keywords": tokens,
            "outcome": "shipped_clean",
            "patch_uri": None,
        },
        "metadata": {
            "patch_length": len(row.get("patch", "")),
            "tags": ["swebench", source, "github-issue"],
            "difficulty": row.get("difficulty"),
        },
    }


def ingest(*, source: str, hf_path: str, split: str = "test",
           max_rows: int | None = None) -> int:
    """Returns count of rows written. Skips if already present."""
    from datasets import load_dataset

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / f"{source}.jsonl"
    if out_path.exists() and out_path.stat().st_size > 0:
        existing = sum(1 for _ in out_path.open())
        print(f"[skip] {source} -> {out_path} ({existing} rows already)",
              file=sys.stderr)
        return existing

    print(f"[load] {hf_path}::{split}", file=sys.stderr)
    ds = load_dataset(hf_path, split=split)
    n = 0
    with out_path.open("w") as f:
        for row in ds:
            elem = _row_to_element(dict(row), source=source)
            f.write(json.dumps(elem) + "\n")
            n += 1
            if max_rows and n >= max_rows:
                break
    print(f"[done] wrote {n} rows to {out_path}", file=sys.stderr)
    return n


def main() -> None:
    total = 0
    total += ingest(source="swebench_verified",
                    hf_path="princeton-nlp/SWE-bench_Verified")
    total += ingest(source="swebench_pro",
                    hf_path="ScaleAI/SWE-bench_Pro")
    print(f"\nTotal SWE-Bench rows: {total}", file=sys.stderr)


if __name__ == "__main__":
    main()

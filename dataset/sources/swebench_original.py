"""SWE-bench original (princeton-nlp/SWE-bench) ingester. ~2294 tasks."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "dataset" / "data" / "real"

import re
_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)
_TOK = re.compile(r"[A-Za-z][A-Za-z0-9_]+")


def _patch_files(p: str) -> list[str]:
    return _FILE_RE.findall(p or "")


def _patch_tokens(p: str) -> list[str]:
    noise = {"self", "return", "import", "from", "none", "true", "false", "test", "tests"}
    o: dict[str, int] = {}
    for ln in (p or "").splitlines():
        if not (ln.startswith("+") or ln.startswith("-")) or ln.startswith("+++") or ln.startswith("---"):
            continue
        for t in _TOK.findall(ln):
            tl = t.lower()
            if len(tl) > 3 and tl not in noise:
                o[tl] = o.get(tl, 0) + 1
    return [t for t, _ in sorted(o.items(), key=lambda kv: -kv[1])[:30]]


def _row_to_element(r: dict) -> dict:
    files = _patch_files(r.get("patch", ""))
    return {
        "id": f"swebench_original/{r['instance_id']}",
        "source": "swebench_original",
        "kind": "code_change",
        "title": r["instance_id"],
        "intent_md": (
            f"# {r['instance_id']}\n\n"
            f"**Repository**: `{r.get('repo','?')}`\n\n"
            f"## Problem statement\n\n{(r.get('problem_statement') or '')[:8000]}\n\n"
            f"## What we're asking\n\nProduce a plan + diff sketch."
        ),
        "repo": r.get("repo"),
        "repo_clone_url": f"https://github.com/{r['repo']}.git" if r.get("repo") else None,
        "language": "python",
        "ground_truth": {
            "kind": "patch",
            "files_touched": files,
            "root_cause_keywords": _patch_tokens(r.get("patch", "")),
            "outcome": "shipped_clean",
            "patch_uri": None,
        },
        "metadata": {"patch_length": len(r.get("patch", "")), "tags": ["swebench-original"]},
    }


def ingest(*, max_total: int | None = None) -> int:
    from datasets import load_dataset

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "swebench_original.jsonl"
    if out.exists() and out.stat().st_size > 0:
        return sum(1 for _ in out.open())
    print("[load] princeton-nlp/SWE-bench (test+dev+train)", file=sys.stderr)
    n = 0
    with out.open("w") as f:
        for split in ("test", "dev", "train"):
            try:
                ds = load_dataset("princeton-nlp/SWE-bench", split=split)
            except Exception as e:
                print(f"  {split}: {e}", file=sys.stderr)
                continue
            for r in ds:
                f.write(json.dumps(_row_to_element(dict(r))) + "\n")
                n += 1
                if max_total and n >= max_total:
                    print(f"[done] cap reached at {n}", file=sys.stderr)
                    return n
    print(f"[done] wrote {n} rows", file=sys.stderr)
    return n


if __name__ == "__main__":
    ingest()

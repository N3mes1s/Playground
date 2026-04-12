"""Thin wrapper around upstream `examples.qa_demo`.

Runs the single-article KV-compaction QA demo from the Attention Matching
reference implementation (github.com/adamzweiger/compaction) with defaults
that match the Latent Briefing replication setup.

Usage:
    python demo.py --model Qwen/Qwen3-4B --target-size 0.1

Requires `./setup.sh` to have been run first.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
UPSTREAM = HERE / "upstream" / "compaction"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="Qwen/Qwen3-4B",
                        help="HF model id for the compaction backbone")
    parser.add_argument("--target-size", type=float, default=0.1,
                        help="Compacted KV size as fraction of original (0-1)")
    parser.add_argument("extra", nargs=argparse.REMAINDER,
                        help="Extra args forwarded to examples.qa_demo")
    args = parser.parse_args()

    if not (UPSTREAM / "examples" / "qa_demo.py").exists():
        sys.exit(
            f"Upstream not found at {UPSTREAM}. "
            "Run ./setup.sh first to clone adamzweiger/compaction."
        )

    cmd = [
        sys.executable, "-m", "examples.qa_demo",
        "--model", args.model,
        "--target-size", str(args.target_size),
        *args.extra,
    ]
    print(f"[demo] cd {UPSTREAM}")
    print(f"[demo] {' '.join(cmd)}")
    return subprocess.call(cmd, cwd=UPSTREAM, env=os.environ.copy())


if __name__ == "__main__":
    raise SystemExit(main())

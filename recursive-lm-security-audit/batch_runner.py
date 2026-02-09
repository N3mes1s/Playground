#!/usr/bin/env python3
"""
Parallel batch runner for the CVE benchmark pipeline.

Uses subprocesses (not threads) because DSPy's dspy.configure() is
thread-local and can only be called from the main thread.

Each benchmark runs as a separate `python benchmark.py GHSA-xxx` process.
Results are checkpointed after each completion.

Usage:
    python batch_runner.py benchmark-100.txt --model anthropic/claude-sonnet-4-5-20250929 --workers 5
    python batch_runner.py benchmark-100.txt --resume --workers 5
"""

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
RESULTS_DIR = SCRIPT_DIR / "benchmark-results"
CHECKPOINT_FILE = RESULTS_DIR / "checkpoint.json"
RESULTS_FILE = RESULTS_DIR / "results.json"
SUMMARY_FILE = RESULTS_DIR / "summary.md"
PATTERNS_FILE = SCRIPT_DIR / "learned_patterns.json"

# File lock for concurrent writes
import fcntl

def _locked_read_json(path: Path) -> list | dict:
    if not path.exists():
        return [] if path.name != "checkpoint.json" else {"completed": []}
    with open(path, "r") as f:
        fcntl.flock(f, fcntl.LOCK_SH)
        data = json.load(f)
        fcntl.flock(f, fcntl.LOCK_UN)
    return data


def _locked_write_json(path: Path, data):
    with open(path, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        json.dump(data, f, indent=2)
        fcntl.flock(f, fcntl.LOCK_UN)


def run_single_subprocess(
    ghsa_id: str,
    index: int,
    total: int,
    model: str,
    sub_model: str | None,
    max_tokens: int,
    max_iterations: int,
) -> dict:
    """Run benchmark.py as a subprocess and parse the JSON output."""
    cmd = [
        sys.executable, str(SCRIPT_DIR / "benchmark.py"),
        ghsa_id,
        "--model", model,
        "--max-tokens", str(max_tokens),
        "--max-iterations", str(max_iterations),
        "-q",
        "-o", "/dev/stdout",  # Write JSON result to stdout
    ]
    if sub_model:
        cmd.extend(["--sub-model", sub_model])

    env = os.environ.copy()

    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900,  # 15 min max per advisory
            cwd=str(SCRIPT_DIR),
            env=env,
        )
        duration = time.time() - start

        if proc.returncode == 0 and proc.stdout.strip():
            # benchmark.py -o /dev/stdout writes JSON
            try:
                result = json.loads(proc.stdout)
                if isinstance(result, list) and len(result) == 1:
                    result = result[0]
                result["scan_duration_s"] = duration
                return result
            except json.JSONDecodeError:
                pass

        # Parse from stderr output for status
        stderr = proc.stderr or ""
        stdout = proc.stdout or ""
        combined = stderr + stdout

        # Try to extract result from the benchmark output
        if "EXACT_MATCH" in combined:
            status = "EXACT_MATCH"
        elif "PARTIAL_MATCH" in combined:
            status = "PARTIAL_MATCH"
        elif "MISS" in combined or "FAIL" in combined:
            status = "MISS"
        else:
            status = "ERROR"

        return {
            "advisory": {"ghsa_id": ghsa_id},
            "match_status": status,
            "matched_finding": "",
            "gap_analysis": combined[-500:] if status == "ERROR" else "",
            "new_instruction": "",
            "scan_duration_s": duration,
            "improved": "Pattern saved" in combined,
        }

    except subprocess.TimeoutExpired:
        return {
            "advisory": {"ghsa_id": ghsa_id},
            "match_status": "ERROR",
            "gap_analysis": "Timeout after 900s",
            "scan_duration_s": 900,
            "improved": False,
        }
    except Exception as e:
        return {
            "advisory": {"ghsa_id": ghsa_id},
            "match_status": "ERROR",
            "gap_analysis": str(e)[:500],
            "scan_duration_s": time.time() - start,
            "improved": False,
        }


def write_summary(total: int, elapsed: float):
    """Write a markdown summary from current results."""
    results = _locked_read_json(RESULTS_FILE)
    if not isinstance(results, list):
        results = []

    exact = sum(1 for r in results if r.get("match_status") == "EXACT_MATCH")
    partial = sum(1 for r in results if r.get("match_status") == "PARTIAL_MATCH")
    missed = sum(1 for r in results if r.get("match_status") == "MISS")
    errors = sum(1 for r in results if r.get("match_status") == "ERROR")
    improved = sum(1 for r in results if r.get("improved"))

    patterns = _locked_read_json(PATTERNS_FILE) if PATTERNS_FILE.exists() else []
    if not isinstance(patterns, list):
        patterns = []

    done = len(results)
    det_rate = (exact + partial) / max(done, 1) * 100
    hours = elapsed / 3600
    avg = elapsed / max(done, 1)

    md = f"""# CVE Benchmark Results

## Progress: {done}/{total} advisories scanned ({hours:.1f}h elapsed)

## Detection Rates
| Metric | Count | Rate |
|--------|-------|------|
| Exact match | {exact} | {exact / max(done,1) * 100:.1f}% |
| Partial match | {partial} | {partial / max(done,1) * 100:.1f}% |
| **Total detected** | **{exact + partial}** | **{det_rate:.1f}%** |
| Missed | {missed} | {missed / max(done,1) * 100:.1f}% |
| Errors | {errors} | {errors / max(done,1) * 100:.1f}% |

## Self-Improvement
- Patterns learned: **{len(patterns)}**
- Scans that improved scanner: {improved}

## Timing
- Elapsed: {hours:.1f}h
- Avg per advisory: {avg:.0f}s (wall clock with {done} done)

"""

    # By ecosystem
    by_eco = {}
    for r in results:
        eco = r.get("advisory", {}).get("package_ecosystem", "unknown")
        if eco not in by_eco:
            by_eco[eco] = {"e": 0, "p": 0, "m": 0, "err": 0}
        s = r.get("match_status", "ERROR")
        k = {"EXACT_MATCH": "e", "PARTIAL_MATCH": "p", "MISS": "m"}.get(s, "err")
        by_eco[eco][k] += 1

    if by_eco:
        md += "## By Ecosystem\n\n"
        md += "| Ecosystem | Total | Exact | Partial | Miss | Error | Det% |\n"
        md += "|-----------|-------|-------|---------|------|-------|------|\n"
        for eco, c in sorted(by_eco.items()):
            t = sum(c.values())
            d = c["e"] + c["p"]
            md += f"| {eco} | {t} | {c['e']} | {c['p']} | {c['m']} | {c['err']} | {d/max(t,1)*100:.0f}% |\n"

    # All results table
    md += "\n## All Results\n\n"
    md += "| # | Status | GHSA | Package | Severity | Time |\n"
    md += "|---|--------|------|---------|----------|------|\n"

    for i, r in enumerate(results, 1):
        adv = r.get("advisory", {})
        ghsa = adv.get("ghsa_id", "?")
        pkg = adv.get("package_name", adv.get("ghsa_id", "?"))[:25]
        sev = adv.get("severity", "?")
        dur = r.get("scan_duration_s", 0)
        s = r.get("match_status", "?")
        icon = {"EXACT_MATCH": "PASS", "PARTIAL_MATCH": "PARTIAL", "MISS": "FAIL", "ERROR": "ERR"}.get(s, "?")
        md += f"| {i} | {icon} | {ghsa} | {pkg} | {sev} | {dur:.0f}s |\n"

    # Learned patterns
    if patterns:
        md += "\n## Learned Patterns\n\n"
        for i, p in enumerate(patterns, 1):
            cve = p.get("cve_id", "?")
            inst = p.get("instruction", "")[:120]
            md += f"{i}. **{cve}**: {inst}...\n"

    SUMMARY_FILE.write_text(md)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Parallel CVE benchmark runner (subprocess-based)")
    parser.add_argument("advisory_file", help="File with one GHSA ID per line")
    parser.add_argument("--model", default="anthropic/claude-sonnet-4-5-20250929")
    parser.add_argument("--sub-model", default=None)
    parser.add_argument("--max-tokens", type=int, default=16000)
    parser.add_argument("--max-iterations", type=int, default=35)
    parser.add_argument("--workers", type=int, default=5, help="Parallel workers (default: 5)")
    parser.add_argument("--no-improve", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(exist_ok=True)

    ids = [line.strip() for line in open(args.advisory_file) if line.strip()]
    total = len(ids)

    if args.resume:
        checkpoint = _locked_read_json(CHECKPOINT_FILE)
        completed = set(checkpoint.get("completed", []))
        remaining = [(i, g) for i, g in enumerate(ids) if g not in completed]
        print(f"Loaded {total} IDs. Resuming: {len(completed)} done, {len(remaining)} remaining")
    else:
        for f in [CHECKPOINT_FILE, RESULTS_FILE, SUMMARY_FILE]:
            if f.exists():
                f.unlink()
        _locked_write_json(CHECKPOINT_FILE, {"completed": []})
        _locked_write_json(RESULTS_FILE, [])
        remaining = list(enumerate(ids))
        print(f"Starting fresh: {total} advisories")

    print(f"Workers: {args.workers} | Model: {args.model}")

    if not remaining:
        print("Nothing to do!")
        return

    start_time = time.time()
    completed_count = total - len(remaining)

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {}
        for idx, ghsa_id in remaining:
            future = pool.submit(
                run_single_subprocess,
                ghsa_id, idx, total,
                args.model, args.sub_model,
                args.max_tokens, args.max_iterations,
            )
            futures[future] = (idx, ghsa_id)

        try:
            for future in as_completed(futures):
                idx, ghsa_id = futures[future]
                try:
                    result = future.result()
                except Exception as e:
                    result = {
                        "advisory": {"ghsa_id": ghsa_id},
                        "match_status": "ERROR",
                        "gap_analysis": str(e)[:500],
                        "scan_duration_s": 0,
                        "improved": False,
                    }

                # Append result
                results = _locked_read_json(RESULTS_FILE)
                if not isinstance(results, list):
                    results = []
                results.append(result)
                _locked_write_json(RESULTS_FILE, results)

                # Update checkpoint
                checkpoint = _locked_read_json(CHECKPOINT_FILE)
                if not isinstance(checkpoint, dict):
                    checkpoint = {"completed": []}
                if ghsa_id not in checkpoint.get("completed", []):
                    checkpoint.setdefault("completed", []).append(ghsa_id)
                _locked_write_json(CHECKPOINT_FILE, checkpoint)

                completed_count += 1
                elapsed = time.time() - start_time

                s = result.get("match_status", "?")
                icon = {"EXACT_MATCH": "PASS", "PARTIAL_MATCH": "PARTIAL", "MISS": "FAIL", "ERROR": "ERR"}.get(s, "?")
                pkg = result.get("advisory", {}).get("package_name", ghsa_id)
                dur = result.get("scan_duration_s", 0)

                # Running totals
                exact = sum(1 for r in results if r.get("match_status") == "EXACT_MATCH")
                partial = sum(1 for r in results if r.get("match_status") == "PARTIAL_MATCH")
                missed = sum(1 for r in results if r.get("match_status") == "MISS")
                errs = sum(1 for r in results if r.get("match_status") == "ERROR")

                print(f"[{completed_count}/{total}] {icon} {ghsa_id} ({pkg}) {dur:.0f}s | "
                      f"P:{exact} PA:{partial} F:{missed} E:{errs} | {elapsed/3600:.1f}h")

                # Update summary every 5 completions
                if completed_count % 5 == 0 or completed_count == total:
                    write_summary(total, elapsed)

        except KeyboardInterrupt:
            print("\n\nInterrupted! Progress saved.")
            print(f"Resume: python batch_runner.py {args.advisory_file} --resume --workers {args.workers}")
            pool.shutdown(wait=False, cancel_futures=True)

    # Final
    elapsed = time.time() - start_time
    write_summary(total, elapsed)

    results = _locked_read_json(RESULTS_FILE)
    if not isinstance(results, list):
        results = []
    exact = sum(1 for r in results if r.get("match_status") == "EXACT_MATCH")
    partial = sum(1 for r in results if r.get("match_status") == "PARTIAL_MATCH")
    missed = sum(1 for r in results if r.get("match_status") == "MISS")
    errs = sum(1 for r in results if r.get("match_status") == "ERROR")
    patterns = _locked_read_json(PATTERNS_FILE) if PATTERNS_FILE.exists() else []

    print(f"\n{'=' * 70}")
    print(f"COMPLETE: {len(results)}/{total}")
    print(f"{'=' * 70}")
    print(f"  PASS:      {exact}  ({exact/max(len(results),1)*100:.0f}%)")
    print(f"  PARTIAL:   {partial}  ({partial/max(len(results),1)*100:.0f}%)")
    print(f"  FAIL:      {missed}  ({missed/max(len(results),1)*100:.0f}%)")
    print(f"  ERROR:     {errs}  ({errs/max(len(results),1)*100:.0f}%)")
    print(f"  Detection: {(exact+partial)/max(len(results),1)*100:.1f}%")
    print(f"  Patterns:  {len(patterns)}")
    print(f"  Time:      {elapsed/3600:.1f}h")
    print(f"\n  {SUMMARY_FILE}")


if __name__ == "__main__":
    main()

"""
Autoresearch loop for CPU-based compression experiments.

Follows the exact autoresearch methodology:
1. Modify compress.py with an experiment
2. Run it
3. Measure val_bpb
4. If improved: keep. If not: discard (revert).
5. Log to results.tsv
6. Repeat

Usage: python run_loop.py
"""

import os
import re
import subprocess
import shutil
import time

SCRIPT = os.path.join(os.path.dirname(__file__), "compress.py")
RESULTS = os.path.join(os.path.dirname(__file__), "results.tsv")
BACKUP = SCRIPT + ".bak"


def read_file(path):
    with open(path) as f:
        return f.read()


def write_file(path, content):
    with open(path, "w") as f:
        f.write(content)


def run_experiment():
    """Run compress.py and extract val_bpb."""
    result = subprocess.run(
        ["python3", SCRIPT],
        capture_output=True, text=True, timeout=30,
    )
    output = result.stdout + "\n" + result.stderr
    match = re.search(r"val_bpb:\s+([\d.]+)", output)
    if match:
        return float(match.group(1)), result.returncode == 0
    return None, False


def init_results():
    if not os.path.exists(RESULTS):
        write_file(RESULTS, "commit\tval_bpb\tmemory_gb\tstatus\tdescription\n")


def log_result(name, val_bpb, status, description):
    with open(RESULTS, "a") as f:
        f.write(f"{name[:7]}\t{val_bpb:.6f}\t0.0\t{status}\t{description}\n")


# ---------------------------------------------------------------------------
# Experiments: each is a (name, description, modify_fn)
# modify_fn takes the source code string and returns modified source
# ---------------------------------------------------------------------------

EXPERIMENTS = [
    ("baseline", "baseline order=3 smoothing=0.1 backoff=0.4", None),
    ("order4", "increase order from 3 to 4",
     lambda s: s.replace("ORDER = 3", "ORDER = 4")),
    ("order5", "increase order from 3 to 5",
     lambda s: s.replace("ORDER = 3", "ORDER = 5")),
    ("order6", "increase order from 3 to 6",
     lambda s: s.replace("ORDER = 3", "ORDER = 6")),
    ("order7", "increase order from 3 to 7",
     lambda s: s.replace("ORDER = 3", "ORDER = 7")),
    ("smooth01", "reduce smoothing from 0.1 to 0.01",
     lambda s: s.replace("SMOOTHING = 0.1", "SMOOTHING = 0.01")),
    ("smooth001", "reduce smoothing to 0.001",
     lambda s: s.replace("SMOOTHING = 0.1", "SMOOTHING = 0.001")),
    ("backoff06", "increase backoff weight from 0.4 to 0.6",
     lambda s: s.replace("BACKOFF_WEIGHT = 0.4", "BACKOFF_WEIGHT = 0.6")),
    ("backoff08", "increase backoff weight to 0.8",
     lambda s: s.replace("BACKOFF_WEIGHT = 0.4", "BACKOFF_WEIGHT = 0.8")),
    ("backoff02", "decrease backoff weight to 0.2",
     lambda s: s.replace("BACKOFF_WEIGHT = 0.4", "BACKOFF_WEIGHT = 0.2")),
    # Compound experiments (applied to current best)
    ("o5_s01", "order=5 + smoothing=0.01",
     lambda s: s.replace("ORDER = 3", "ORDER = 5").replace("SMOOTHING = 0.1", "SMOOTHING = 0.01")),
    ("o5_s001", "order=5 + smoothing=0.001",
     lambda s: s.replace("ORDER = 3", "ORDER = 5").replace("SMOOTHING = 0.1", "SMOOTHING = 0.001")),
    ("o6_s01", "order=6 + smoothing=0.01",
     lambda s: s.replace("ORDER = 3", "ORDER = 6").replace("SMOOTHING = 0.1", "SMOOTHING = 0.01")),
    ("o6_s001_b06", "order=6 + smoothing=0.001 + backoff=0.6",
     lambda s: s.replace("ORDER = 3", "ORDER = 6").replace("SMOOTHING = 0.1", "SMOOTHING = 0.001").replace("BACKOFF_WEIGHT = 0.4", "BACKOFF_WEIGHT = 0.6")),
    ("o7_s001", "order=7 + smoothing=0.001",
     lambda s: s.replace("ORDER = 3", "ORDER = 7").replace("SMOOTHING = 0.1", "SMOOTHING = 0.001")),
    ("o8_s001", "order=8 + smoothing=0.001",
     lambda s: s.replace("ORDER = 3", "ORDER = 8").replace("SMOOTHING = 0.1", "SMOOTHING = 0.001")),
    ("o5_s0001", "order=5 + smoothing=0.0001",
     lambda s: s.replace("ORDER = 3", "ORDER = 5").replace("SMOOTHING = 0.1", "SMOOTHING = 0.0001")),
    ("o6_s0001_b08", "order=6 + smoothing=0.0001 + backoff=0.8",
     lambda s: s.replace("ORDER = 3", "ORDER = 6").replace("SMOOTHING = 0.1", "SMOOTHING = 0.0001").replace("BACKOFF_WEIGHT = 0.4", "BACKOFF_WEIGHT = 0.8")),
]


def main():
    init_results()
    original_code = read_file(SCRIPT)
    best_bpb = float("inf")
    best_code = original_code

    print("=" * 60)
    print("AUTORESEARCH LOOP: COMPRESSION OPTIMIZATION")
    print("=" * 60)
    print(f"Running {len(EXPERIMENTS)} experiments\n")

    for i, (name, desc, modify_fn) in enumerate(EXPERIMENTS):
        print(f"\n{'─' * 60}")
        print(f"[{i+1}/{len(EXPERIMENTS)}] {name}: {desc}")

        # Apply modification to the ORIGINAL code (not cumulative, like autoresearch)
        if modify_fn:
            modified = modify_fn(original_code)
        else:
            modified = original_code

        write_file(SCRIPT, modified)

        t0 = time.time()
        try:
            val_bpb, ok = run_experiment()
        except subprocess.TimeoutExpired:
            val_bpb, ok = None, False
        elapsed = time.time() - t0

        if val_bpb is None or not ok:
            print(f"  CRASHED ({elapsed:.1f}s)")
            log_result(name, 0.0, "crash", desc)
        else:
            if val_bpb < best_bpb:
                status = "keep"
                improvement = best_bpb - val_bpb if best_bpb < float("inf") else 0
                best_bpb = val_bpb
                best_code = modified
                print(f"  val_bpb={val_bpb:.6f} | KEEP >>> new best! (improved {improvement:.6f}) | {elapsed:.1f}s")
            else:
                status = "discard"
                print(f"  val_bpb={val_bpb:.6f} | discard (best={best_bpb:.6f}) | {elapsed:.1f}s")
            log_result(name, val_bpb, status, desc)

    # Restore best code
    write_file(SCRIPT, best_code)

    # Print summary
    print(f"\n{'=' * 60}")
    print("RESULTS SUMMARY")
    print(f"{'=' * 60}")
    with open(RESULTS) as f:
        print(f.read())

    kept = []
    with open(RESULTS) as f:
        next(f)  # skip header
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) >= 5 and parts[3] == "keep":
                kept.append((parts[0], float(parts[1]), parts[4]))

    print(f"Total experiments: {len(EXPERIMENTS)}")
    print(f"Kept: {len(kept)}")
    if kept:
        best = min(kept, key=lambda x: x[1])
        baseline = kept[0][1] if kept else 0
        print(f"Baseline: {baseline:.6f}")
        print(f"Best:     {best[1]:.6f} ({best[2]})")
        print(f"Improvement: {baseline - best[1]:.6f} ({(baseline - best[1])/baseline*100:.2f}%)")


if __name__ == "__main__":
    main()

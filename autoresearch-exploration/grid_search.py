#!/usr/bin/env python3
"""Grid search over compression hyperparameters.

Tests combinations of order, smoothing, and backoff_weight to find
the best BPB. Imports the model and evaluation from compress.py.
"""

import time
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from compress import ByteModel, TRAIN_DATA, evaluate_bpb

# Grid search parameters
ORDERS = [1, 2, 3, 4]
SMOOTHINGS = [0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05]
BACKOFFS = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]

def run_experiment(order, smoothing, backoff):
    """Run a single experiment and return BPB."""
    model = ByteModel(order=order, smoothing=smoothing, backoff_weight=backoff)
    model.train(TRAIN_DATA)
    return evaluate_bpb(model.predict)

def main():
    best_bpb = 1.537591  # current best
    best_config = None
    results = []

    total = len(ORDERS) * len(SMOOTHINGS) * len(BACKOFFS)
    print(f"Grid search: {total} combinations")
    print(f"Current best: {best_bpb:.6f} (order=3, smoothing=0.001, backoff=0.4)")
    print(f"{'='*70}")

    # Phase 1: Quick scan with fixed backoff=0.4 to find best order+smoothing
    print("\n--- Phase 1: Order × Smoothing (backoff=0.4) ---")
    phase1_best = []
    count = 0
    for order in ORDERS:
        for smoothing in SMOOTHINGS:
            count += 1
            t0 = time.time()
            bpb = run_experiment(order, smoothing, 0.4)
            elapsed = time.time() - t0
            status = "NEW BEST!" if bpb < best_bpb else ""
            if bpb < best_bpb:
                best_bpb = bpb
                best_config = (order, smoothing, 0.4)
            phase1_best.append((bpb, order, smoothing))
            print(f"  [{count}/{len(ORDERS)*len(SMOOTHINGS)}] order={order} smooth={smoothing:<10} bpb={bpb:.6f} ({elapsed:.1f}s) {status}")
            results.append((order, smoothing, 0.4, bpb))

    # Sort phase1 results
    phase1_best.sort()
    print(f"\n  Top 5 from Phase 1:")
    for bpb, order, smoothing in phase1_best[:5]:
        print(f"    order={order} smooth={smoothing} -> bpb={bpb:.6f}")

    # Phase 2: Fine-tune backoff for top 3 configs
    print(f"\n--- Phase 2: Backoff sweep for top 3 configs ---")
    top3 = phase1_best[:3]
    for bpb_base, order, smoothing in top3:
        print(f"\n  order={order}, smoothing={smoothing} (base bpb={bpb_base:.6f}):")
        for backoff in BACKOFFS:
            if backoff == 0.4:
                continue  # already tested
            t0 = time.time()
            bpb = run_experiment(order, smoothing, backoff)
            elapsed = time.time() - t0
            status = "NEW BEST!" if bpb < best_bpb else ""
            if bpb < best_bpb:
                best_bpb = bpb
                best_config = (order, smoothing, backoff)
            print(f"    backoff={backoff:.1f} -> bpb={bpb:.6f} ({elapsed:.1f}s) {status}")
            results.append((order, smoothing, backoff, bpb))

    # Phase 3: Ultra-fine smoothing search around best
    if best_config:
        bo, bs, bb = best_config
        print(f"\n--- Phase 3: Fine smoothing around best (order={bo}, backoff={bb}) ---")
        fine_smoothings = [bs * f for f in [0.1, 0.2, 0.3, 0.5, 0.7, 1.5, 2.0, 3.0, 5.0]]
        for smoothing in fine_smoothings:
            t0 = time.time()
            bpb = run_experiment(bo, smoothing, bb)
            elapsed = time.time() - t0
            status = "NEW BEST!" if bpb < best_bpb else ""
            if bpb < best_bpb:
                best_bpb = bpb
                best_config = (bo, smoothing, bb)
            print(f"    smooth={smoothing:<12.8f} -> bpb={bpb:.6f} ({elapsed:.1f}s) {status}")
            results.append((bo, smoothing, bb, bpb))

    # Summary
    print(f"\n{'='*70}")
    print(f"GRID SEARCH COMPLETE")
    print(f"{'='*70}")
    print(f"Total experiments: {len(results)}")
    print(f"Best BPB: {best_bpb:.6f}")
    if best_config:
        print(f"Best config: order={best_config[0]}, smoothing={best_config[1]}, backoff={best_config[2]}")

    # Top 10
    results.sort(key=lambda x: x[3])
    print(f"\nTop 10:")
    for order, smoothing, backoff, bpb in results[:10]:
        print(f"  order={order} smooth={smoothing:<12} backoff={backoff:.1f} -> bpb={bpb:.6f}")


if __name__ == "__main__":
    main()

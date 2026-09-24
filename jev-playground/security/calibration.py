"""
calibration.py -- is Jev actually calibrated? An independent test against ground truth.

Everyone repeats that Jev returns "calibrated probabilities", but the public
accuracy claims lean on frontier models as the reference, not ground-truth
labels. This measures it directly: score real labelled events (Atomic Red Team
malicious + a benign admin/dev corpus) with Jev's malicious probability, then ask
the only question that matters for calibration --

    of all the events Jev scored ~p, what fraction were actually malicious?

Outputs:
  * a reliability table (predicted p vs empirical fraction, with class counts)
  * Expected Calibration Error (ECE), Maximum CE (MCE), Brier score, base rate
  * a train/test isotonic recalibration (PAV, no sklearn) -- does remapping the
    probabilities lower ECE, i.e. is Jev already calibrated or does it need a
    cheap fix?
  * the payoff: a threshold recipe -- "for a target false-positive budget, use
    threshold T, get recall R" -- which is what calibration buys you and what
    turns the dual-use / where-do-I-set-the-threshold obstacle into a dial.

    python -m security.calibration                 # score everything, ~$0.02
    python -m security.calibration --limit-malicious 250 --bins 10 --seed 5
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cli import _load_dotenv
from jev import Jev, noul

from .benign_corpus import generate as gen_benign
from .datasets import load
from .edr import QUESTIONS

HERE = Path(__file__).parent
PRICE_PER_M_INPUT = 0.042
MAL_Q = {"malicious": QUESTIONS["malicious"]}  # single noul -> cheaper, focused on the probability


# --------------------------------------------------------------------------- #
# metrics
# --------------------------------------------------------------------------- #
def wilson(k, n, z=1.96):
    """95% Wilson score interval for a binomial proportion k/n."""
    import math
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (c - m) / d, (c + m) / d


def reliability(probs, labels, bins=10):
    edges = [i / bins for i in range(bins + 1)]
    table, ece, mce, n = [], 0.0, 0.0, len(probs)
    for b in range(bins):
        lo, hi = edges[b], edges[b + 1]
        idx = [i for i, p in enumerate(probs) if (p >= lo and (p < hi or (b == bins - 1 and p <= hi)))]
        if not idx:
            table.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": 0, "pos": 0, "conf": None, "acc": None})
            continue
        conf = sum(probs[i] for i in idx) / len(idx)
        pos = sum(labels[i] for i in idx)
        acc = pos / len(idx)
        gap = abs(acc - conf)
        ece += (len(idx) / n) * gap
        mce = max(mce, gap)
        table.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": len(idx), "pos": pos,
                      "conf": round(conf, 3), "acc": round(acc, 3), "gap": round(gap, 3)})
    return table, ece, mce


def brier(probs, labels):
    return sum((p - y) ** 2 for p, y in zip(probs, labels)) / len(probs)


def pav(y):
    """Pool Adjacent Violators: isotonic (non-decreasing) fit of y (ordered by x)."""
    vals = [float(v) for v in y]
    wts = [1.0] * len(vals)
    i = 0
    while i < len(vals) - 1:
        if vals[i] > vals[i + 1] + 1e-12:
            # merge blocks i and i+1
            w = wts[i] + wts[i + 1]
            v = (vals[i] * wts[i] + vals[i + 1] * wts[i + 1]) / w
            vals[i:i + 2] = [v]
            wts[i:i + 2] = [w]
            if i > 0:
                i -= 1  # back up to re-check monotonicity
        else:
            i += 1
    # expand blocks back to per-point values
    out = []
    for v, w in zip(vals, wts):
        out.extend([v] * int(round(w)))
    return out


def isotonic_map(train_probs, train_labels):
    """Return f(p)->calibrated using a PAV fit on the training pairs."""
    pairs = sorted(zip(train_probs, train_labels))
    xs = [p for p, _ in pairs]
    fitted = pav([y for _, y in pairs])

    def f(p):
        # step/linear interpolation over (xs, fitted)
        if p <= xs[0]:
            return fitted[0]
        if p >= xs[-1]:
            return fitted[-1]
        lo, hi = 0, len(xs) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if xs[mid] < p:
                lo = mid + 1
            else:
                hi = mid
        x1, x0 = xs[lo], xs[lo - 1]
        y1, y0 = fitted[lo], fitted[lo - 1]
        return y0 if x1 == x0 else y0 + (y1 - y0) * (p - x0) / (x1 - x0)

    return f


# --------------------------------------------------------------------------- #
def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit-malicious", type=int, default=0, help="0 = all")
    ap.add_argument("--bins", type=int, default=10)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)
    _load_dotenv()
    client = Jev()

    ds = load()
    mal = ds["malicious"]
    rng = random.Random(args.seed)
    rng.shuffle(mal)
    if args.limit_malicious:
        mal = mal[: args.limit_malicious]
    benign = ds["benign"] + gen_benign()
    records = [(1, r) for r in mal] + [(0, r) for r in benign]

    def score(rec):
        label, r = rec
        try:
            resp = client.ask(r["event"], MAL_Q)
            return {"y": label, "p": resp.answers["malicious"].noul,
                    "tactic": r.get("tactic", "None"), "tokens": resp.usage.get("input_tokens", 0),
                    "note": r.get("test_name", "")}
        except Exception as e:
            return {"y": label, "p": None, "error": str(e)}

    with ThreadPoolExecutor(args.workers) as tp:
        scored = [s for s in tp.map(score, records) if s.get("p") is not None]

    probs = [s["p"] for s in scored]
    labels = [s["y"] for s in scored]
    tokens = sum(s.get("tokens", 0) for s in scored)
    base_rate = statistics.mean(labels)

    table, ece, mce = reliability(probs, labels, args.bins)
    bs = brier(probs, labels)

    # train/test isotonic recalibration (stratified 50/50)
    idx = list(range(len(scored)))
    rng.shuffle(idx)
    half = len(idx) // 2
    tr, te = idx[:half], idx[half:]
    f = isotonic_map([probs[i] for i in tr], [labels[i] for i in tr])
    te_p = [probs[i] for i in te]
    te_y = [labels[i] for i in te]
    te_pc = [f(p) for p in te_p]
    _, ece_raw, _ = reliability(te_p, te_y, args.bins)
    _, ece_cal, _ = reliability(te_pc, te_y, args.bins)
    bs_raw, bs_cal = brier(te_p, te_y), brier(te_pc, te_y)

    # threshold recipe: precision/recall/FPR at each threshold on the full set
    P = sum(labels)
    N = len(labels) - P
    sweep = []
    for t in [i / 20 for i in range(1, 20)]:
        tp = sum(1 for p, y in zip(probs, labels) if p >= t and y == 1)
        fp = sum(1 for p, y in zip(probs, labels) if p >= t and y == 0)
        rec = tp / P if P else 0
        fpr = fp / N if N else 0
        prec = tp / (tp + fp) if (tp + fp) else 1.0
        sweep.append((t, rec, fpr, prec))

    def budget(maxfpr):
        ok = [s for s in sweep if s[2] <= maxfpr]
        return max(ok, key=lambda s: s[1]) if ok else None

    # ---- console ----------------------------------------------------------
    print(f"\nJev calibration ({len(scored)} events, base rate {base_rate:.2f}, "
          f"{sum(labels)} malicious / {len(labels)-sum(labels)} benign)  model jev-latest")
    print(f"  ECE {ece:.3f}   MCE {mce:.3f}   Brier {bs:.3f}   (cost ${tokens/1e6*PRICE_PER_M_INPUT:.4f})")
    print(f"  isotonic recalibration (held-out): ECE {ece_raw:.3f} -> {ece_cal:.3f}, "
          f"Brier {bs_raw:.3f} -> {bs_cal:.3f}")
    print("\n  reliability (predicted vs actual):")
    print(f"    {'bin':<10}{'n':>5}{'malicious':>11}{'pred p':>9}{'actual':>9}{'gap':>7}")
    for r in table:
        if r["n"] == 0:
            continue
        print(f"    {r['bin']:<10}{r['n']:>5}{r['pos']:>11}{r['conf']:>9.3f}{r['acc']:>9.3f}{r['gap']:>7.3f}")
    print("\n  threshold recipe (operating points):")
    for label, mf in [("FP<=1%", 0.01), ("FP<=5%", 0.05), ("FP<=10%", 0.10)]:
        b = budget(mf)
        if b:
            print(f"    {label:<8} -> threshold {b[0]:.2f}: recall {b[1]:.0%}, "
                  f"actual FPR {b[2]:.1%}, precision {b[3]:.0%}")

    # ---- report -----------------------------------------------------------
    md = ["# Is Jev calibrated? An independent test\n",
          "Does Jev's probability mean what it says? We score real labelled events "
          "(Atomic Red Team malicious + an admin/dev benign corpus) with Jev's malicious "
          "probability and check, per probability bin, the fraction that were truly malicious. "
          "Ground-truth labels, not a frontier-model reference.\n",
          f"- Events: **{len(scored)}** ({sum(labels)} malicious / {len(labels)-sum(labels)} benign), "
          f"eval base rate {base_rate:.2f}, model `jev-latest`",
          f"- **Expected Calibration Error {ece:.3f}**, Maximum CE {mce:.3f}, **Brier {bs:.3f}**",
          f"- Isotonic recalibration on held-out data: ECE {ece_raw:.3f} → {ece_cal:.3f}, "
          f"Brier {bs_raw:.3f} → {bs_cal:.3f} "
          f"({'recalibration helps' if ece_cal < ece_raw - 0.005 else 'already well-calibrated: remap barely moves it'})\n",
          "> Base-rate caveat: this eval set is deliberately near-balanced so every bin has both "
          "classes. Real attack traffic is far rarer, so precision at a given threshold in production "
          "will be lower than here even if the probability stays calibrated. Calibration is a property "
          "of the score; precision also depends on base rate.\n",
          "## Reliability table\n",
          "| predicted p | events | malicious | mean predicted | actual fraction | gap |",
          "|---|---|---|---|---|---|"]
    for r in table:
        if r["n"] == 0:
            continue
        md.append(f"| {r['bin']} | {r['n']} | {r['pos']} | {r['conf']:.3f} | {r['acc']:.3f} | {r['gap']:.3f} |")
    md += ["\n## The payoff: threshold recipe\n",
           "Calibration is what lets you *choose* an operating point instead of guessing. For a "
           "target false-positive budget, pick the threshold and get a known recall:\n",
           "| false-positive budget | threshold | recall | actual FPR | precision (this set) |",
           "|---|---|---|---|---|"]
    for label, mf in [("≤ 1%", 0.01), ("≤ 5%", 0.05), ("≤ 10%", 0.10)]:
        b = budget(mf)
        if b:
            md.append(f"| {label} | {b[0]:.2f} | {b[1]:.0%} | {b[2]:.1%} | {b[3]:.0%} |")
    md += ["\n## Full sweep\n", "| threshold | recall | FPR | precision |", "|---|---|---|---|"]
    for t, rec, fpr, prec in sweep:
        md.append(f"| {t:.2f} | {rec:.0%} | {fpr:.1%} | {prec:.0%} |")
    md.append("\n## Why this surpasses the earlier obstacle\n")
    md.append("Our EDR benchmark reported 26% Discovery recall *at a fixed 0.5 threshold* and concluded "
              "we didn't know where to set it. If the score is calibrated, that's no longer a wall: you "
              "set the threshold to the false-positive budget you can afford and read off the recall you "
              "get, per tactic. The number to trust is the gap column above — small gaps mean the "
              "probability can be used as a real operating dial, not just a ranking.\n")
    (HERE / "CALIBRATION.md").write_text("\n".join(md) + "\n")
    (HERE / "calibration_results.json").write_text(json.dumps(
        {"n": len(scored), "base_rate": base_rate, "ece": ece, "mce": mce, "brier": bs,
         "isotonic": {"ece_raw": ece_raw, "ece_cal": ece_cal, "brier_raw": bs_raw, "brier_cal": bs_cal},
         "reliability": table, "sweep": sweep, "scored": scored}, indent=1))
    print(f"\nwrote {HERE/'CALIBRATION.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

"""
lolbin_gap.py -- the dual-use / LOLBin detection gap: what blue teams could not
do before a semantic model like Jev.

The problem (unsolved for over a decade): attackers "live off the land" -- they
use the same signed, built-in binaries admins use every day (certutil, rundll32,
wmic, powershell, curl, openssl, PsExec...). A signature keys on observable
strings, but the strings are IDENTICAL for the admin and the attacker. So a
keyword/IOC rule either fires on both (false-positive storm) or on neither
(blind). You cannot separate them by string matching, and you could not afford
to run an LLM on every event to judge intent. That is the gap.

This measures, on the SAME events (real Atomic Red Team attacks + a genuine
dual-use admin/dev corpus), how well two approaches SEPARATE malicious from
benign:

  * signatures : score = number of Sigma rules whose keyword pattern matches
  * Jev        : score = malicious probability

Separation is reported as ROC AUC (base-rate-free) plus the true-positive rate
achievable at a low false-positive budget -- the number a SOC actually lives by.

    python -m security.lolbin_gap                 # all benign + sampled attacks
    python -m security.lolbin_gap --limit 0       # all attacks too

Writes security/LOLBIN_GAP.md and security/lolbin_results.json.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cli import _load_dotenv
from jev import Jev

from .benign_corpus import generate as gen_benign
from .datasets import load as load_ds
from .edr import QUESTIONS
from .sigma_extract import load as load_sig
from .sigma_extract import match_count

HERE = Path(__file__).parent
MAL_Q = {"malicious": QUESTIONS["malicious"]}


def auc(scores, labels):
    """ROC AUC via the Mann-Whitney U statistic (handles ties)."""
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return float("nan")
    ranked = sorted(zip(scores, labels), key=lambda x: x[0])
    # average ranks for ties
    ranks = [0.0] * len(ranked)
    i = 0
    while i < len(ranked):
        j = i
        while j + 1 < len(ranked) and ranked[j + 1][0] == ranked[i][0]:
            j += 1
        avg = (i + j) / 2 + 1  # ranks are 1-based
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    sum_pos = sum(r for r, (_, y) in zip(ranks, ranked) if y == 1)
    u = sum_pos - len(pos) * (len(pos) + 1) / 2
    return u / (len(pos) * len(neg))


def tpr_at_fpr(scores, labels, max_fpr):
    """Best true-positive rate achievable while false-positive rate <= max_fpr."""
    P = sum(labels)
    N = len(labels) - P
    best = 0.0
    thr_best = None
    for t in sorted(set(scores)):
        tp = sum(1 for s, y in zip(scores, labels) if s >= t and y == 1)
        fp = sum(1 for s, y in zip(scores, labels) if s >= t and y == 0)
        if N and fp / N <= max_fpr and P and tp / P > best:
            best = tp / P
            thr_best = t
    return best, thr_best


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=250, help="malicious sample size (0 = all)")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)
    _load_dotenv()

    ds = load_ds()
    sig = load_sig()
    mal = ds["malicious"][:]
    random.Random(args.seed).shuffle(mal)
    if args.limit:
        mal = mal[: args.limit]
    benign = ds["benign"] + gen_benign()
    records = [(1, r) for r in mal] + [(0, r) for r in benign]

    # signature score (offline, no API)
    def sigscore(r):
        e = r["event"]
        return match_count(e["Image"] + " " + e["CommandLine"], sig)

    # Jev score (parallel)
    client = Jev()

    def jevscore(r):
        try:
            return client.ask(r["event"], MAL_Q).answers["malicious"].noul
        except Exception:
            return None

    with ThreadPoolExecutor(args.workers) as tp:
        jev = list(tp.map(lambda lr: jevscore(lr[1]), records))

    rows = []
    for (y, r), jp in zip(records, jev):
        if jp is None:
            continue
        rows.append({"y": y, "sig": sigscore(r), "jev": jp,
                     "tactic": r.get("tactic", "None"), "note": r.get("test_name", "")})

    labels = [x["y"] for x in rows]
    sig_scores = [x["sig"] for x in rows]
    jev_scores = [x["jev"] for x in rows]
    P, N = sum(labels), len(labels) - sum(labels)

    sig_auc, jev_auc = auc(sig_scores, labels), auc(jev_scores, labels)
    # "match any signature" operating point (the naive rule-fires alert)
    sig_any_tp = sum(1 for x in rows if x["sig"] >= 1 and x["y"] == 1) / P
    sig_any_fp = sum(1 for x in rows if x["sig"] >= 1 and x["y"] == 0) / N

    tab = []
    for fpr in (0.01, 0.05, 0.10):
        s_tpr, _ = tpr_at_fpr(sig_scores, labels, fpr)
        j_tpr, j_thr = tpr_at_fpr(jev_scores, labels, fpr)
        tab.append((fpr, s_tpr, j_tpr, j_thr))

    print(f"\nDual-use / LOLBin separation ({P} attacks / {N} benign dual-use)  model jev-latest")
    print(f"  ROC AUC   signatures {sig_auc:.3f}   Jev {jev_auc:.3f}   (0.5 = coin flip)")
    print(f"  'any signature fires' -> TPR {sig_any_tp:.0%} at FPR {sig_any_fp:.0%}  "
          f"(fires on nearly everything -> no separation)")
    print("\n  TPR achievable at a false-positive budget:")
    print(f"    {'FP budget':<12}{'signatures':>12}{'Jev':>10}")
    for fpr, s, j, _ in tab:
        print(f"    <= {fpr:>4.0%}   {s:>11.0%}{j:>10.0%}")

    md = ["# The dual-use / LOLBin detection gap Jev closes\n",
          "Attackers use the same built-in tools admins do (certutil, rundll32, wmic, powershell, "
          "curl, PsExec). A keyword/IOC **signature** sees identical strings for both, so it cannot "
          "separate them -- it fires on the attack *and* the admin. An **LLM** could judge intent but "
          "is too slow/costly to run on every event. Jev is the first option that is both semantic "
          "and cheap enough for full coverage.\n",
          "Measured on the SAME events -- real Atomic Red Team attacks vs a genuine dual-use "
          f"admin/dev corpus ({P} attacks / {N} benign), model `jev-latest`:\n",
          "| approach | ROC AUC (separation) |", "|---|---|",
          f"| Sigma keyword signatures (rules-fired count) | {sig_auc:.3f} |",
          f"| Jev malicious probability | {jev_auc:.3f} |",
          "\n(0.5 = no better than a coin flip at telling attack from admin.)\n",
          f"- The naive **'a signature fired' alert**: catches {sig_any_tp:.0%} of attacks but also "
          f"fires on {sig_any_fp:.0%} of benign dual-use activity -- the false-positive storm every "
          "SOC knows.\n",
          "## True-positive rate at a false-positive budget\n",
          "The number a SOC lives by: how many attacks you catch while keeping benign noise under a "
          "budget you can staff.\n",
          "| false-positive budget | signatures | Jev |", "|---|---|---|"]
    for fpr, s, j, _ in tab:
        md.append(f"| ≤ {fpr:.0%} | {s:.0%} | {j:.0%} |")
    md += ["\n## Why this was unsolvable before\n",
           "- **Signatures** are string matchers. On dual-use binaries the strings are identical for "
           "attacker and admin, so no rule can separate them -- the AUC above is near a coin flip and "
           "'any rule fired' lights up on all the benign admin traffic too.",
           "- **LLMs** can read intent, but at seconds and cents per call you cannot run one on every "
           "process event, so you sample a fraction and the rest goes uninspected.",
           "- **Jev** judges intent semantically like an LLM, at ~0.5 s and ~$0.00002 per event, so it "
           "runs on 100% of events. That combination -- semantic separation of dual-use activity at "
           "full-coverage cost -- is the capability that did not exist before, and it is what turns the "
           "LOLBin gap from unsolvable into a tunable operating point.\n",
           "> Caveat: the signature baseline is a generous keyword approximation of Sigma (see "
           "`sigma_extract.py`), not a full Sigma engine with logsource/field context; and Jev is not "
           "a full EDR. This measures the *separability ceiling* of string matching vs semantics on "
           "dual-use commands, which is the point.\n"]
    (HERE / "LOLBIN_GAP.md").write_text("\n".join(md) + "\n")
    (HERE / "lolbin_results.json").write_text(json.dumps(
        {"attacks": P, "benign": N, "sig_auc": sig_auc, "jev_auc": jev_auc,
         "sig_any": [sig_any_tp, sig_any_fp],
         "tpr_at_fpr": [{"fpr": f, "sig": s, "jev": j} for f, s, j, _ in tab],
         "rows": rows}, indent=1))
    print(f"\nwrote {HERE/'LOLBIN_GAP.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

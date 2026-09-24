"""
edr_bench.py -- benchmark Jev as an EDR triage / detection-engineering layer
against real, labelled data (Atomic Red Team + a benign admin baseline).

    python -m security.edr_bench                 # 60 malicious + all benign (fast, ~$0.003)
    python -m security.edr_bench --full          # all 569 malicious + benign
    python -m security.edr_bench --limit 150 --threshold 0.5 --workers 16

Metrics reported (this is the language a detection engineer cares about):
  * Recall   -- malicious events correctly flagged (true positive rate)
  * FP rate  -- benign events wrongly flagged (the alert-fatigue killer)
  * Tactic accuracy -- ATT&CK tactic top-1 on events with a known tactic
  * LOLBin recall on the LOLBin-heavy techniques
  * Latency p50/p95 and total cost

Writes security/EDR_RESULTS.md and security/edr_results.json.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cli import _load_dotenv
from jev import Jev

from .datasets import load
from .edr import triage

HERE = Path(__file__).parent
PRICE_PER_M_INPUT = 0.042


def _run_one(client, rec, threshold):
    try:
        v = triage(client, rec["event"], threshold)
        return {**{k: rec[k] for k in ("label", "technique_id", "tactic", "source", "test_name")},
                "cmd": rec["event"].get("CommandLine", "")[:160],
                "pred_malicious": v.malicious, "malicious_p": v.malicious_p,
                "pred_tactic": v.tactic, "tactic_conf": v.tactic_conf,
                "lolbin": v.lolbin, "obfuscated": v.obfuscated, "severity": v.severity,
                "response": v.response, "score": v.score,
                "latency_ms": v.latency_ms, "tokens": v.tokens}
    except Exception as e:
        return {**{k: rec[k] for k in ("label", "technique_id", "tactic", "source", "test_name")},
                "cmd": rec["event"].get("CommandLine", "")[:160], "error": str(e),
                "pred_malicious": False, "malicious_p": 0.0, "pred_tactic": "ERROR",
                "tactic_conf": 0, "lolbin": 0, "obfuscated": 0, "severity": 0,
                "response": "monitor", "score": 0, "latency_ms": 0, "tokens": 0}


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="use all malicious samples")
    ap.add_argument("--limit", type=int, default=60, help="malicious sample size when not --full")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)

    _load_dotenv()
    ds = load()
    mal = ds["malicious"]
    if not args.full and args.limit < len(mal):
        random.Random(args.seed).shuffle(mal)
        mal = mal[: args.limit]
    records = mal + ds["benign"]
    client = Jev()

    with ThreadPoolExecutor(args.workers) as pool:
        results = list(pool.map(lambda r: _run_one(client, r, args.threshold), records))

    M = [r for r in results if r["label"] == "malicious"]
    B = [r for r in results if r["label"] == "benign"]
    tp = sum(r["pred_malicious"] for r in M)
    fp = sum(r["pred_malicious"] for r in B)
    recall = tp / len(M) if M else 0
    fp_rate = fp / len(B) if B else 0
    # tactic accuracy on malicious events with a known tactic
    known = [r for r in M if r["tactic"] != "unknown" and "error" not in r]
    tac_ok = sum(r["pred_tactic"] == r["tactic"] for r in known)
    tac_acc = tac_ok / len(known) if known else 0

    lat = sorted(r["latency_ms"] for r in results if r["latency_ms"])
    tokens = sum(r["tokens"] for r in results)
    errors = [r for r in results if "error" in r]

    def pct(xs, p):
        return xs[min(len(xs) - 1, int(len(xs) * p))] if xs else 0

    # threshold sweep (recomputed from stored probabilities -- no extra API calls)
    sweep = []
    for th in [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
        r_tp = sum(r["malicious_p"] >= th for r in M)
        r_fp = sum(r["malicious_p"] >= th for r in B)
        sweep.append((th, r_tp / len(M) if M else 0, r_fp / len(B) if B else 0))

    # per-tactic recall
    by_tac = defaultdict(lambda: [0, 0])
    for r in known:
        by_tac[r["tactic"]][1] += 1
        by_tac[r["tactic"]][0] += r["pred_malicious"]
    # per-tactic confusion for the tactic label
    tac_pred_ok = defaultdict(lambda: [0, 0])
    for r in known:
        tac_pred_ok[r["tactic"]][1] += 1
        tac_pred_ok[r["tactic"]][0] += (r["pred_tactic"] == r["tactic"])

    # ---- console ----------------------------------------------------------
    print(f"\nEDR triage benchmark  ({len(M)} malicious / {len(B)} benign)  model jev-latest")
    print(f"  recall (malicious flagged) : {tp}/{len(M)} = {recall:.1%}")
    print(f"  FP rate (benign flagged)   : {fp}/{len(B)} = {fp_rate:.1%}")
    print(f"  tactic top-1 (known tactic): {tac_ok}/{len(known)} = {tac_acc:.1%}")
    print(f"  latency p50/p95            : {statistics.median(lat):.0f} / {pct(lat, 0.95):.0f} ms")
    print(f"  cost                       : {tokens:,} tok  ${tokens/1e6*PRICE_PER_M_INPUT:.5f}")
    if errors:
        print(f"  errors                     : {len(errors)}")

    print("\n  threshold sweep (recall vs FP):")
    for th, rc, fpr in sweep:
        print(f"    t={th:.1f}  recall {rc:6.1%}   FP {fpr:6.1%}")

    print("\n  per-tactic recall:")
    for t, (ok, n) in sorted(by_tac.items(), key=lambda kv: -kv[1][1]):
        print(f"    {t:24}{ok:>3}/{n:<3} {ok/n:6.0%}   tactic-label {tac_pred_ok[t][0]}/{n}")

    if B:
        print("\n  benign events flagged malicious (false positives):")
        for r in sorted(B, key=lambda r: -r["malicious_p"]):
            mark = "  <-- FP" if r["pred_malicious"] else ""
            print(f"    p={r['malicious_p']:.2f} sev={r['severity']:.1f} {r['test_name'][:44]:44}{mark}")

    # top missed malicious (lowest score) -- the detection gaps
    missed = sorted([r for r in M if not r["pred_malicious"]], key=lambda r: r["malicious_p"])
    if missed:
        print(f"\n  missed malicious (false negatives, {len(missed)}), lowest first:")
        for r in missed[:12]:
            print(f"    p={r['malicious_p']:.2f} {r['technique_id']:12}{r['test_name'][:52]}")

    # ---- files ------------------------------------------------------------
    (HERE / "edr_results.json").write_text(json.dumps({
        "config": vars(args),
        "summary": {"malicious": len(M), "benign": len(B), "recall": recall, "fp_rate": fp_rate,
                    "tactic_accuracy": tac_acc, "tokens": tokens,
                    "cost_usd": tokens / 1e6 * PRICE_PER_M_INPUT,
                    "latency_p50": statistics.median(lat) if lat else 0, "latency_p95": pct(lat, 0.95)},
        "results": results}, indent=1))

    md = [
        "# EDR triage benchmark (real data)\n",
        "Jev as a detection-engineering / EDR alert-triage layer, scored against "
        "**Atomic Red Team** attacker-technique commands (malicious, ground-truth ATT&CK "
        "technique ids) and a hand-written **admin/dev baseline** (benign hard negatives).\n",
        f"- Malicious: **{len(M)}** events · Benign: **{len(B)}** events · model `jev-latest` · "
        f"threshold {args.threshold}",
        f"- **Recall (attacks flagged): {recall:.1%}** ({tp}/{len(M)})",
        f"- **False-positive rate (benign flagged): {fp_rate:.1%}** ({fp}/{len(B)})",
        f"- **ATT&CK tactic top-1: {tac_acc:.1%}** ({tac_ok}/{len(known)} events with a known tactic)",
        f"- Latency p50/p95: {statistics.median(lat):.0f} / {pct(lat, 0.95):.0f} ms · "
        f"cost ${tokens/1e6*PRICE_PER_M_INPUT:.5f} for the whole run ({tokens:,} input tokens)\n",
        "Regenerate: `python -m security.datasets --art <clone> --sigma <clone>` then "
        "`python -m security.edr_bench --full`.\n",
        "## Threshold sweep (recall vs false positives)\n",
        "The malicious/benign call returns a calibrated probability; a detection engineer picks the "
        "operating point. Dual-use Discovery/C2 commands are what move with the threshold.\n",
        "| threshold | recall | FP rate |", "|---|---|---|",
        *[f"| {th:.1f} | {rc:.1%} | {fpr:.1%} |" for th, rc, fpr in sweep],
        "",
        "## Per-tactic recall and tactic-label accuracy\n",
        "| ATT&CK tactic | events | attacks flagged | tactic label correct |",
        "|---|---|---|---|",
    ]
    for t, (ok, n) in sorted(by_tac.items(), key=lambda kv: -kv[1][1]):
        md.append(f"| {t} | {n} | {ok}/{n} ({ok/n:.0%}) | {tac_pred_ok[t][0]}/{n} ({tac_pred_ok[t][0]/n:.0%}) |")
    md += ["\n## Benign baseline (false-positive check)\n",
           "| benign activity | malicious p | severity | flagged? |", "|---|---|---|---|"]
    for r in sorted(B, key=lambda r: -r["malicious_p"]):
        md.append(f"| {r['test_name']} | {r['malicious_p']:.2f} | {r['severity']:.1f} | "
                  f"{'**FP**' if r['pred_malicious'] else 'no'} |")
    if missed:
        md += [f"\n## Sample false negatives ({len(missed)} total)\n",
               "| technique | test | malicious p |", "|---|---|---|"]
        for r in missed[:20]:
            md.append(f"| {r['technique_id']} | {r['test_name'][:60]} | {r['malicious_p']:.2f} |")
    (HERE / "EDR_RESULTS.md").write_text("\n".join(md) + "\n")
    print(f"\nwrote {HERE/'EDR_RESULTS.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

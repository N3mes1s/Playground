"""
mutation_bench.py -- WHY signatures lose: brittleness under behaviour-preserving change.

Takes real attack commands that a signature covers, applies each mild mutation from
mutations.py (which changes the string but not the behaviour), and measures whether
detection survives:

  * sig_tight : the precise, low-false-positive signature (the most specific Sigma
                keyword pattern that covered the original) still literally matches
  * sig_broad : ANY Sigma rule that covered the original still matches (a huge, noisy
                ruleset -- the one that already fires on 100% of benign, see LOLBIN_GAP)
  * jev       : Jev still flags the mutated command as malicious

The gap between sig_tight and jev is the mechanism behind the LOLBin result: string
matching breaks under trivial mutation; behavioural judgement does not.

    python -m security.mutation_bench                # ~50 covered attacks
    python -m security.mutation_bench --n 80

Writes security/MUTATION_RESULTS.md and security/mutation_results.json.
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

from .datasets import load as load_ds
from .edr import QUESTIONS
from .mutations import MUTATIONS
from .sigma_extract import load as load_sig
from .sigma_extract import matched_patterns, pattern_matches, tightest_pattern

HERE = Path(__file__).parent
MAL_Q = {"malicious": QUESTIONS["malicious"]}


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=50, help="number of signature-covered attacks")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)
    _load_dotenv()
    client = Jev()

    ds = load_ds()
    sig = load_sig()
    mal = ds["malicious"][:]
    random.Random(args.seed).shuffle(mal)

    # keep attacks that have a precise (tight) covering signature
    covered = []
    for e in mal:
        text = e["event"]["Image"] + " " + e["event"]["CommandLine"]
        mp = matched_patterns(text, sig)
        tight = tightest_pattern(mp)
        if tight:
            covered.append({"event": e["event"], "tight": tight[1],
                            "all_pats": [p for _, p in mp]})
        if len(covered) >= args.n:
            break

    def jev_flag(cmdline, image):
        try:
            ev = {"EventID": 1, "Image": image, "CommandLine": cmdline}
            return client.ask(ev, MAL_Q).answers["malicious"].noul >= args.threshold
        except Exception:
            return None

    # build all jev jobs (clean + mutations) to run in parallel
    jobs = []  # (idx, mutation_name_or_clean, cmdline, image)
    per_mut_applicable = {m: 0 for m in MUTATIONS}
    for i, c in enumerate(covered):
        image = c["event"]["Image"]
        base = c["event"]["CommandLine"]
        jobs.append((i, "clean", base, image))
        for mname, fn in MUTATIONS.items():
            mutated, changed = fn(base, args.seed)
            if changed:
                per_mut_applicable[mname] += 1
                jobs.append((i, mname, mutated, image))

    with ThreadPoolExecutor(args.workers) as tp:
        jev_res = list(tp.map(lambda j: jev_flag(j[2], j[3]), jobs))

    # signature survival (offline) + collect jev results
    # scenario -> {"sig_tight":[hits,n], "sig_broad":[hits,n], "jev":[hits,n]}
    agg = {name: {"sig_tight": [0, 0], "sig_broad": [0, 0], "jev": [0, 0]}
           for name in ["clean", *MUTATIONS]}

    for (i, scen, cmdline, image), jflag in zip(jobs, jev_res):
        c = covered[i]
        text = image + " " + cmdline
        st = pattern_matches(c["tight"], text)
        sb = any(pattern_matches(p, text) for p in c["all_pats"])
        agg[scen]["sig_tight"][0] += st
        agg[scen]["sig_tight"][1] += 1
        agg[scen]["sig_broad"][0] += sb
        agg[scen]["sig_broad"][1] += 1
        if jflag is not None:
            agg[scen]["jev"][0] += jflag
            agg[scen]["jev"][1] += 1

    def pct(pair):
        h, n = pair
        return f"{h/n:.0%}" if n else "-"

    print(f"\nMutation robustness ({len(covered)} signature-covered attacks)  model jev-latest")
    print(f"{'scenario':<16}{'sig (tight)':>13}{'sig (broad)':>13}{'Jev':>8}{'n':>6}")
    for scen in ["clean", *MUTATIONS]:
        a = agg[scen]
        print(f"{scen:<16}{pct(a['sig_tight']):>13}{pct(a['sig_broad']):>13}{pct(a['jev']):>8}"
              f"{a['sig_tight'][1]:>6}")

    md = ["# Why signatures lose: brittleness under behaviour-preserving mutation\n",
          "The mechanism behind the LOLBin result. We take real attack commands that a **precise "
          "signature covers**, apply mild behaviour-preserving mutations (mutations.py), and check "
          "whether detection survives. `sig (tight)` = the specific low-false-positive signature still "
          "matches; `sig (broad)` = any rule from the huge noisy ruleset still matches (the one that "
          "already fires on all benign traffic); `jev` = Jev still flags malicious. Model `jev-latest`.\n",
          f"- Signature-covered attacks tested: **{len(covered)}**, threshold {args.threshold}\n",
          "| mutation | sig (tight) | sig (broad) | Jev | n |", "|---|---|---|---|---|"]
    for scen in ["clean", *MUTATIONS]:
        a = agg[scen]
        md.append(f"| {scen} | {pct(a['sig_tight'])} | {pct(a['sig_broad'])} | {pct(a['jev'])} | "
                  f"{a['sig_tight'][1]} |")
    md += ["\n## Reading this (the honest, and surprising, result)\n",
           "We expected mild mutation to collapse signatures. It did not -- and that is the finding.\n",
           "- **clean**: the tight signature matches 100% by construction; Jev's rate is its natural "
           "recall on these commands.",
           "- **case_flip** (control): good signatures are case-insensitive, so it does not hurt them.",
           "- **flag_alias / whitespace_pad / quote_insert** change the spelling but not the behaviour, "
           "yet the *precise* signature mostly survives (93-100%). Why: the tightest signature keys on "
           "a **durable artifact** -- a full path, a binary name, an API like `comsvcs.dll MiniDump` -- "
           "that these mild mutations do not touch. The folklore that any mutation defeats signatures "
           "is overstated for durable-artifact rules.",
           "- On these **signature-covered** attacks, Jev's recall is *lower* than the precise "
           "signature. That is expected: these are exactly the attacks signatures were built for.\n",
           "## What this means for where Jev fits\n",
           "Jev does not replace good signatures. Where a precise, durable signature exists, it is "
           "cheap, exact and mutation-robust -- keep it. Jev earns its place on what signatures "
           "*cannot* express: the dual-use / LOLBin space where the strings are identical for attacker "
           "and admin (LOLBIN_GAP.md, AUC 0.65 vs 0.94) and novel behaviour with no rule yet. The two "
           "are complementary: signatures for the known and durable, Jev for the ambiguous and novel, "
           "both at full coverage.",
           "- The **sig (broad)** column stays ~100% only because that ruleset matches almost "
           "everything, including 100% of benign activity (LOLBIN_GAP.md). High recall there is noise, "
           "not detection.\n",
           "> Caveat: mild, textbook transformations and a keyword approximation of Sigma, not a full "
           "engine. Stronger obfuscation (tool renaming for bring-your-own tools, encoding chains) "
           "would erode even durable-artifact signatures further; this run deliberately stays mild.\n"]
    (HERE / "MUTATION_RESULTS.md").write_text("\n".join(md) + "\n")
    (HERE / "mutation_results.json").write_text(json.dumps(
        {"n": len(covered), "applicable": per_mut_applicable,
         "agg": {k: v for k, v in agg.items()}}, indent=1))
    print(f"\nwrote {HERE/'MUTATION_RESULTS.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

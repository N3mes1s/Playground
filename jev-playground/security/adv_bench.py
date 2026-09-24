"""
adv_bench.py -- red team vs blue team: do the evasions in adversarial.py move a
Jev guard, and does harden.py stop them?

    python -m security.adv_bench
    python -m security.adv_bench --detectors prompt_injection shell_command --workers 16

For each malicious sample it measures the DETECTION RATE (share still blocked):
  * clean, naive guard      -- can we catch it at all
  * each attack, naive      -- how far the evasion drops detection (attack success = 1 - this)
  * each attack, hardened   -- how much the hardening restores
It also checks the hardened guard does not start blocking the benign baseline.

Writes security/ADVERSARIAL_RESULTS.md and security/adv_results.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cli import _load_dotenv
from jev import Jev

from .adversarial import ATTACKS
from .detectors import ALL
from .harden import CAUGHT, hardened_guard, naive_guard
from .samples import SAMPLES

HERE = Path(__file__).parent
DEFAULT_DETECTORS = ["prompt_injection", "tool_call_guard", "shell_command",
                     "dlp_outbound", "install_script", "waf_request"]


def _mal(det_name):
    return [st for lab, st, _ in SAMPLES[det_name] if CAUGHT[det_name](lab)]


def _ben(det_name):
    return [st for lab, st, _ in SAMPLES[det_name] if not CAUGHT[det_name](lab)]


def _run(client, job):
    kind, guard, det_name, state = job
    det = ALL[det_name]
    try:
        blocked, detail = (naive_guard if guard == "naive" else hardened_guard)(client, det, state)
        return {"kind": kind, "guard": guard, "detector": det_name, "blocked": blocked,
                "blocked_by": detail.get("blocked_by", []), "label": detail.get("label")}
    except Exception as e:
        return {"kind": kind, "guard": guard, "detector": det_name, "blocked": None, "error": str(e)}


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--detectors", nargs="+", default=DEFAULT_DETECTORS)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--manip-threshold", type=float, default=0.5)
    args = ap.parse_args(argv)
    _load_dotenv()
    client = Jev()

    jobs = []
    for d in args.detectors:
        for st in _mal(d):
            jobs.append(("clean", "naive", d, st))
            jobs.append(("clean", "hardened", d, st))
            for aname, fn in ATTACKS.items():
                ev = fn(st)
                jobs.append((f"attack:{aname}", "naive", d, ev))
                jobs.append((f"attack:{aname}", "hardened", d, ev))
        for st in _ben(d):  # hardened must not over-block benign
            jobs.append(("benign", "hardened", d, st))

    with ThreadPoolExecutor(args.workers) as pool:
        res = list(pool.map(lambda j: _run(client, j), jobs))

    # aggregate detection rates
    def rate(kind, guard):
        rs = [r for r in res if r["kind"] == kind and r["guard"] == guard and r["blocked"] is not None]
        return (sum(r["blocked"] for r in rs), len(rs))

    rows = []
    clean_n = rate("clean", "naive")
    clean_h = rate("clean", "hardened")
    rows.append(("clean (no attack)", clean_n, clean_h))
    for aname in ATTACKS:
        rows.append((aname, rate(f"attack:{aname}", "naive"), rate(f"attack:{aname}", "hardened")))
    ben_block, ben_n = rate("benign", "hardened")

    # which hardening layer did the blocking (on attacked samples)
    layer = defaultdict(int)
    for r in res:
        if r["guard"] == "hardened" and r["kind"].startswith("attack") and r["blocked"]:
            for b in r["blocked_by"]:
                layer[b.split("(")[0].split(":")[0]] += 1

    def pctstr(t):
        ok, n = t
        return f"{ok}/{n} ({ok/n:.0%})" if n else "-"

    def asr(t):  # attack success rate = 1 - detection
        ok, n = t
        return f"{(n-ok)/n:.0%}" if n else "-"

    print("\nRed team vs blue team -- detection rate (higher = safer)\n" + "=" * 64)
    print(f"{'scenario':<22}{'naive detect':>16}{'naive ASR':>12}{'hardened detect':>18}")
    for name, n, h in rows:
        print(f"{name:<22}{pctstr(n):>16}{asr(n):>12}{pctstr(h):>18}")
    print(f"\nhardened guard on benign baseline (false blocks): {ben_block}/{ben_n}")
    print(f"hardening layer that caught attacked samples: {dict(layer)}")

    # ---- report -----------------------------------------------------------
    md = ["# Adversarial robustness: attacking the Jev guard\n",
          "Red team (`adversarial.py`) embeds benign-looking framing, authority claims, "
          "reviewer instructions and noise into **known-malicious** inputs without changing what "
          "they do. Blue team (`harden.py`) adds reworded behavioural questions, a manipulation "
          "detector, and deterministic regex co-checks. Metric = **detection rate** (share still "
          "blocked); attack success rate (ASR) = 1 - detection.\n",
          f"Detectors: {', '.join(args.detectors)}. Model `jev-latest`.\n",
          "| scenario | naive detection | naive ASR | hardened detection |",
          "|---|---|---|---|"]
    for name, n, h in rows:
        md.append(f"| {name} | {pctstr(n)} | {asr(n)} | {pctstr(h)} |")
    md += [f"\n- Hardened guard on the benign baseline (false blocks): **{ben_block}/{ben_n}**",
           f"- Which hardening layer caught the attacked samples: `{dict(layer)}`\n",
           "## Reading this\n",
           "- A high **naive ASR** means the evasion moves the classifier: text that talks to the "
           "guard flips its verdict, exactly the failure a red-teamer would show.",
           "- The **hardened** column is behavioural-rewording + manipulation-detection + "
           "deterministic regex combined fail-closed. The deterministic layer is the floor that "
           "adversarial text cannot argue its way past; the manipulation detector turns the attack "
           "itself into a signal.",
           "- Robustness is not free: check the benign false-block count above. A guard should be "
           "one layer, never the only control.\n"]
    (HERE / "ADVERSARIAL_RESULTS.md").write_text("\n".join(md) + "\n")
    (HERE / "adv_results.json").write_text(json.dumps({"rows": [
        {"scenario": name, "naive": n, "hardened": h} for name, n, h in rows],
        "benign_false_blocks": [ben_block, ben_n], "layers": dict(layer), "raw": res}, indent=1))
    print(f"\nwrote {HERE/'ADVERSARIAL_RESULTS.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

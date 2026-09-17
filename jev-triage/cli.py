"""
jev-triage: fast, calibrated triage of security-scanner findings with Jev.

Takes findings from an upstream scanner (a JSON list, or an RLM auditor
markdown report) and asks TypeSafe's Jev to decide, per finding, whether it is
a real & reachable vulnerability and what its calibrated severity is. Prints a
filtered + re-ranked report and (optionally) writes JSON/markdown.

Examples
--------
    # Triage a JSON findings file
    python cli.py example_findings.json

    # Triage an RLM auditor report, keep only high-confidence real findings
    python cli.py ../recursive-lm-security-audit/dvsa-audit-report.md \\
        --is-real-threshold 0.7 --reachable-threshold 0.6

    # Write both a markdown and a JSON report
    python cli.py example_findings.json -o triaged.md --json triaged.json

    # Offline demo: no API key / network, uses a stub Jev backend
    python cli.py example_findings.json --demo
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from findings import SEVERITIES, load_findings
from jev_client import JevClient
from report import write_json, write_markdown
from triage import triage_all

_SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def _progress(i: int, total: int, res) -> None:
    mark = "KEEP" if res.keep else "drop"
    sev = res.severity_label or "?"
    print(
        f"  [{i}/{total}] {mark:4}  {res.finding.id:<10} "
        f"real={_fmt(res.is_real)} reach={_fmt(res.reachable)} "
        f"sev={sev:<13} {res.finding.title[:52]}",
        file=sys.stderr,
    )


def _fmt(x) -> str:
    return f"{x:.2f}" if isinstance(x, (int, float)) else " n/a"


def main() -> int:
    p = argparse.ArgumentParser(
        description="Triage security-scanner findings with TypeSafe Jev.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("findings", help="Path to a .json findings file or a .md report")
    p.add_argument("--is-real-threshold", type=float, default=0.6,
                   help="Min P(real) to keep a finding (default 0.6)")
    p.add_argument("--reachable-threshold", type=float, default=0.5,
                   help="Min P(reachable) to keep a finding (default 0.5)")
    p.add_argument("--model", default="jev-latest", help="Jev model id")
    p.add_argument("-o", "--output", help="Write a markdown report here")
    p.add_argument("--json", dest="json_out", help="Write a JSON report here")
    p.add_argument("--no-sdk", action="store_true",
                   help="Force the raw-HTTP transport (ignore typesafe-sdk)")
    p.add_argument("--demo", action="store_true",
                   help="Use a local stub Jev backend (no API key / network)")
    args = p.parse_args()

    path = Path(args.findings)
    if not path.exists():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2

    findings = load_findings(path)
    if not findings:
        print(f"error: no findings parsed from {path}", file=sys.stderr)
        return 1
    print(f"Parsed {len(findings)} finding(s) from {path.name}", file=sys.stderr)

    if args.demo:
        from demo_backend import StubJevClient
        client: JevClient = StubJevClient(model=args.model)
    else:
        client = JevClient(model=args.model, prefer_sdk=not args.no_sdk)

    results = triage_all(
        client,
        findings,
        is_real_threshold=args.is_real_threshold,
        reachable_threshold=args.reachable_threshold,
        on_progress=_progress,
    )

    kept = [r for r in results if r.keep]
    kept.sort(
        key=lambda r: (
            -_SEV_ORDER.get(r.severity_label or "", -1),
            -(r.is_real or 0.0),
        )
    )
    dropped = [r for r in results if not r.keep]

    # -- console summary --------------------------------------------------- #
    print(f"\n{'=' * 68}")
    print(f"  Jev triage: {len(kept)} kept / {len(dropped)} dropped "
          f"of {len(results)}")
    print(f"{'=' * 68}")
    for r in kept:
        print(f"  KEEP  {r.severity_label:<13} {r.finding.id:<10} "
              f"real={_fmt(r.is_real)}  {r.finding.title[:46]}")
    if dropped:
        print(f"  {'-' * 64}")
    for r in dropped:
        print(f"  drop  {'':<13} {r.finding.id:<10} {r.reason}")

    total_in = sum(r.usage.get("input_tokens", 0) for r in results)
    total_out = sum(r.usage.get("output_tokens", 0) for r in results)
    if total_in or total_out:
        # Jev pricing at time of writing: $0.042/MTok input, output free.
        cost = total_in / 1_000_000 * 0.042
        print(f"  {'-' * 64}")
        print(f"  tokens: {total_in} in / {total_out} out  "
              f"(~${cost:.5f} at $0.042/MTok in, output free)")

    if args.output:
        write_markdown(args.output, results, args)
        print(f"\n  Markdown report -> {args.output}", file=sys.stderr)
    if args.json_out:
        write_json(args.json_out, results, args)
        print(f"  JSON report     -> {args.json_out}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

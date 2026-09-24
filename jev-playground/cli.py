#!/usr/bin/env python3
"""
cli.py -- a generic command-line front-end for Jev.

Two ways to use it:

1. Inline, quick single question:

     # yes/no probability
     python cli.py --state "My card was charged twice" \
                   --noul "The customer wants a refund"

     # pick one option
     python cli.py --state "The app crashes on login" \
                   --choice "Which team" billing="Payments" technical="Bugs" account="Login"

     # score on a spectrum (levels are comma-separated, lowest first)
     python cli.py --state "I am absolutely furious" \
                   --score "Frustration" "Calm,Annoyed,Angry,Furious"

   You can pass any mix of --noul/--choice/--score to ask several questions in one
   round trip. State can be repeated (--state a --state b) to send a list.

2. From a JSON spec file (full control, structured state, many questions):

     python cli.py --file request.json

   where request.json looks like:

     {
       "state": {"subject": "...", "body": "..."},
       "questions": {
         "team":  {"type": "choice", "instructions": "...", "criteria": {"a": "..."}},
         "anger": {"type": "score",  "instructions": "...", "criteria": ["Calm", "Angry"]},
         "urgent":{"type": "noul",   "instructions": "..."}
       }
     }

Output is human-readable by default, or newline-delimited JSON with --json.
The API key comes from TYPESAFE_API_KEY (see .env.example).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

from jev import Jev, JevError, choice, noul, score


def _load_dotenv() -> None:
    """Minimal .env loader so `TYPESAFE_API_KEY=...` in ./.env just works."""
    env_path = Path(__file__).with_name(".env")
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def _parse_kv(pairs: List[str]) -> Dict[str, str]:
    """Turn ['billing=Payments', 'technical=Bugs'] into a criteria dict."""
    out: Dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"--choice options must look like label=description (got {pair!r})")
        label, _, desc = pair.partition("=")
        out[label.strip()] = desc.strip()
    return out


def _build_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    questions: Dict[str, Any] = {}
    if args.noul:
        for i, instr in enumerate(args.noul):
            questions[f"noul_{i}" if len(args.noul) > 1 else "noul"] = noul(instr)
    if args.choice:
        instr, *pairs = args.choice
        questions["choice"] = choice(instr, _parse_kv(pairs))
    if args.score:
        instr, levels = args.score
        questions["score"] = score(instr, [s.strip() for s in levels.split(",")])
    if not questions:
        raise SystemExit("Provide at least one of --noul / --choice / --score, or use --file.")

    state: Any = args.state if len(args.state) > 1 else args.state[0]
    return {"state": state, "questions": questions}


def _render(resp) -> None:
    print(f"model: {resp.model}   latency: {resp.latency_ms:.0f} ms   "
          f"tokens: {resp.usage.get('input_tokens', '?')} in / "
          f"{resp.usage.get('output_tokens', '?')} out\n")
    for ans in resp:
        print(f"[{ans.name}]  ({ans.type})")
        if ans.type == "noul":
            verdict = "YES" if ans.is_yes() else "no"
            print(f"    {verdict}  (p = {ans.noul:.3f})")
        elif ans.type == "choice":
            print(f"    -> {ans.choice}   (confidence {ans.confidence:.2f})")
            for label, p in sorted(ans.probabilities.items(), key=lambda kv: -kv[1]):
                print(f"        {label:<20} {p:6.1%}")
        elif ans.type == "score":
            print(f"    -> {ans.score:.2f}  ~ {ans.label()}   (confidence {ans.confidence:.2f})")
            for i, p in sorted(ans.probabilities.items(), key=lambda kv: int(kv[0])):
                print(f"        {ans.legend.get(i, i):<20} {p:6.1%}")
        print()


def main(argv: List[str]) -> int:
    p = argparse.ArgumentParser(
        description="Generic CLI for TypeSafe AI's Jev System One model.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--state", action="append", default=[],
                   help="Context to evaluate. Repeat to send a list of strings.")
    p.add_argument("--noul", action="append",
                   help="Add a yes/no (probability) question. Repeatable.")
    p.add_argument("--choice", nargs="+", metavar="INSTR label=desc",
                   help="Add a choice question: instructions then label=description pairs.")
    p.add_argument("--score", nargs=2, metavar=("INSTR", "L1,L2,.."),
                   help="Add a score question: instructions then comma-separated levels.")
    p.add_argument("--file", type=Path, help="Read a full {state, questions} spec from JSON.")
    p.add_argument("--model", default="jev-latest", help="Model id (default: jev-latest).")
    p.add_argument("--json", action="store_true", help="Emit raw JSON instead of pretty text.")
    args = p.parse_args(argv)

    _load_dotenv()

    if args.file:
        spec = json.loads(args.file.read_text())
    elif args.state:
        spec = _build_from_args(args)
    else:
        p.error("Provide --state (with a question) or --file.")

    try:
        client = Jev(model=args.model)
        resp = client.ask(spec["state"], spec["questions"])
    except (ValueError, JevError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(resp.raw, indent=2))
    else:
        _render(resp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

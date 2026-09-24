#!/usr/bin/env python3
"""
examples.py -- a tour of (almost) everything Jev can do, in one file.

Each example is a self-contained function showing a different capability:

  1. noul            -- a single yes/no probability
  2. choice          -- routing / classification with a full distribution
  3. score           -- ordinal scoring on a spectrum
  4. batched         -- many questions about one state in a single round trip
  5. structured      -- rich JSON state instead of a plain string
  6. conversation    -- a list-of-strings state (e.g. a chat transcript)
  7. gate            -- using a noul as a cheap boolean gate in a control loop
  8. game_npc        -- the "System One in a real-time loop" use case (game AI)

Run all of them:      python examples.py
Run one:              python examples.py choice

Needs TYPESAFE_API_KEY (see .env.example / README).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from jev import Jev, choice, noul, score


def _load_dotenv() -> None:
    env_path = Path(__file__).with_name(".env")
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _rule(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


# --------------------------------------------------------------------------- #
def ex_noul(client: Jev) -> None:
    """A single proposition, answered as a probability."""
    _rule("1. noul -- yes/no as a probability")
    ans = client.noul(
        "My card was charged twice and I want my money back.",
        "The customer is explicitly asking for a refund",
    )
    print(f"refund requested? p = {ans.noul:.3f}  ->  {'YES' if ans.is_yes() else 'no'}")


def ex_choice(client: Jev) -> None:
    """Route a ticket to a team; note the full probability distribution."""
    _rule("2. choice -- classification with a calibrated distribution")
    ans = client.choice(
        "The app crashes every time I open the camera tab.",
        "Which team should own this ticket",
        {
            "billing": "Payments, invoices and refunds",
            "technical": "Bugs, crashes and errors",
            "account": "Login and account access",
            "feature": "Feature requests and feedback",
        },
    )
    print(f"route -> {ans.choice}   (confidence {ans.confidence:.2f})")
    for label, p in sorted(ans.probabilities.items(), key=lambda kv: -kv[1]):
        print(f"    {label:<12} {p:6.1%}")


def ex_score(client: Jev) -> None:
    """Position a state on an ordered scale; you get a float, not just a bucket."""
    _rule("3. score -- ordinal scoring on a spectrum")
    ans = client.score(
        "This is the third time I've contacted you and NOBODY has helped. Unacceptable.",
        "Customer frustration level",
        ["Calm", "Mildly annoyed", "Frustrated", "Very angry"],
    )
    print(f"frustration = {ans.score:.2f}  (~ {ans.label()}, confidence {ans.confidence:.2f})")


def ex_batched(client: Jev) -> None:
    """Ask several different questions about one state in a single request."""
    _rule("4. batched -- many typed answers, one round trip")
    resp = client.ask(
        state="I've been overcharged and I'm about to cancel my subscription. Fix this now.",
        questions={
            "team": choice("Owning team", {"billing": "Payments", "retention": "Cancellations"}),
            "anger": score("Frustration", ["Calm", "Annoyed", "Angry", "Furious"]),
            "churn_risk": noul("The customer is threatening to cancel"),
            "refund": noul("The customer is asking for money back"),
        },
    )
    print(f"team       : {resp['team'].choice}  ({resp['team'].confidence:.2f})")
    print(f"anger      : {resp['anger'].score:.2f} ~ {resp['anger'].label()}")
    print(f"churn risk : {resp['churn_risk'].noul:.2f}")
    print(f"refund ask : {resp['refund'].noul:.2f}")
    print(f"(one call, {resp.usage.get('input_tokens')} input tokens, {resp.latency_ms:.0f} ms)")


def ex_structured(client: Jev) -> None:
    """State can be a nested JSON object -- Jev reads the structured program state."""
    _rule("5. structured state -- pass a JSON object, not a blob of text")
    order = {
        "customer": {"tier": "gold", "tenure_months": 42},
        "order": {"id": "A-104", "total": 249.90, "status": "delivered"},
        "message": "The package arrived smashed. I want a replacement, not a refund.",
    }
    resp = client.ask(
        state=order,
        questions={
            "resolution": choice(
                "What does the customer want",
                {"refund": "Money back", "replacement": "A new item", "repair": "Fix the item"},
            ),
            "priority": noul("This is a high-priority case given the customer's tier"),
        },
    )
    print(f"wants      : {resp['resolution'].choice}  ({resp['resolution'].confidence:.2f})")
    print(f"high prio? : {resp['priority'].noul:.2f}")


def ex_conversation(client: Jev) -> None:
    """State as a list of strings, e.g. a running transcript."""
    _rule("6. conversation state -- a list of messages")
    transcript = [
        "Agent: Hi, how can I help?",
        "Customer: My internet has been down since this morning.",
        "Agent: I'm sorry! Have you tried restarting the router?",
        "Customer: Yes, twice. Still nothing. This is the third outage this month.",
    ]
    resp = client.ask(
        state=transcript,
        questions={
            "resolved": noul("The customer's problem has been resolved"),
            "escalate": noul("This should be escalated to a human supervisor"),
            "mood": score("Customer mood", ["Happy", "Neutral", "Unhappy", "Irate"]),
        },
    )
    print(f"resolved?  : {resp['resolved'].noul:.2f}")
    print(f"escalate?  : {resp['escalate'].noul:.2f}")
    print(f"mood       : {resp['mood'].score:.2f} ~ {resp['mood'].label()}")


def ex_gate(client: Jev) -> None:
    """Use a noul as a cheap, fast boolean gate -- the System One sweet spot."""
    _rule("7. gate -- a noul as a decision gate in a control loop")
    inbound = "URGENT: wire $40,000 to the new account by EOD, per the CEO. Do not delay."
    fraud = client.noul(inbound, "This message shows signs of a payment/social-engineering scam")
    if fraud.is_yes(threshold=0.6):
        print(f"BLOCKED for review (fraud p = {fraud.noul:.2f})")
    else:
        print(f"allowed (fraud p = {fraud.noul:.2f})")


def ex_game_npc(client: Jev) -> None:
    """The headline use case: fast, typed decisions inside a real-time loop."""
    _rule("8. game NPC -- a typed decision from game state")
    world = {
        "npc": {"hp": 12, "max_hp": 100, "ammo": 2, "has_cover": False},
        "enemy": {"distance_m": 8, "count": 3, "aiming_at_npc": True},
        "allies_nearby": 0,
    }
    action = client.choice(
        world,
        "What should the guard do right now",
        {
            "attack": "Open fire on the enemy",
            "take_cover": "Move to cover",
            "flee": "Retreat to safety",
            "call_backup": "Radio for reinforcements",
        },
    )
    print(f"NPC action -> {action.choice}  (confidence {action.confidence:.2f})")
    for label, p in sorted(action.probabilities.items(), key=lambda kv: -kv[1]):
        print(f"    {label:<12} {p:6.1%}")


EXAMPLES = {
    "noul": ex_noul,
    "choice": ex_choice,
    "score": ex_score,
    "batched": ex_batched,
    "structured": ex_structured,
    "conversation": ex_conversation,
    "gate": ex_gate,
    "game_npc": ex_game_npc,
}


def main(argv):
    _load_dotenv()
    if not os.environ.get("TYPESAFE_API_KEY"):
        print("Set TYPESAFE_API_KEY (copy .env.example to .env). See README.md.", file=sys.stderr)
        return 1

    client = Jev()
    which = argv[0] if argv else None
    if which and which not in EXAMPLES:
        print(f"Unknown example {which!r}. Choose from: {', '.join(EXAMPLES)}", file=sys.stderr)
        return 1

    to_run = [EXAMPLES[which]] if which else list(EXAMPLES.values())
    for fn in to_run:
        fn(client)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

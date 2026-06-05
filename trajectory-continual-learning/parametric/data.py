"""Generate a preference/SFT dataset from the user's hidden preferences.

Each example is (context, prompt, chosen, rejected):
  * prompt   -- a plain instruction with NO rule hints ("Write an email to ...")
  * chosen   -- a draft that satisfies all of the context's hidden rules
                (this is the "user-edited" target)
  * rejected -- a draft that violates them (a generic default)

`chosen` is verified against text_rules.check_text so the training signal is
clean. The model must learn the *style* (the rules) from many varied examples --
it never sees the rule list, only examples of edited vs un-edited text. This is
the supervised/preference data the parametric path trains on (cf. "Principled
Fine-tuning of LLMs from User-Edits", arXiv:2601.19055).
"""

from __future__ import annotations

import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from text_rules import check_text, features_of  # noqa: E402

R = random.Random(7)

NAMES = ["Sarah", "James", "Priya", "Marco", "Lena", "Omar", "Yuki", "Tom",
         "Ana", "Raj", "Maya", "Leo", "Nina", "Sam", "Ivan", "Zoe"]
SENDER = "Giuseppe"
DATES = ["Monday", "Friday", "June 12", "next week", "the 20th", "Thursday",
         "EOD today", "this Friday"]
EMOJI = ["🚀", "✅", "🔥", "📦", "🛠️", "⚠️", "🎉", "📊", "🙌", "🐛"]

# (instruction-topic, concrete-ask, reason, ps) building blocks for emails
EMAIL_TOPICS = [
    ("ask for a one-week deadline extension", "could we move the deadline to {d}",
     "a few priorities shifted this week", "happy to share a quick plan if useful"),
    ("follow up on an unpaid invoice", "any update on invoice 4021 due {d}",
     "just making sure it didn't slip through", "no rush if it's already in motion"),
    ("reschedule the kickoff call", "can we push the kickoff to {d}",
     "a conflict came up on my end", "I'll send a couple of backup slots"),
    ("decline a meeting invite", "I'll have to skip the sync on {d}",
     "I'm double-booked then", "I'll catch up from the notes after"),
    ("request feedback on the draft", "could you skim the draft by {d}",
     "I'd value your eye on the intro", "even a few inline notes would help"),
    ("ask to approve time off", "could you approve my leave for {d}",
     "everything on my plate is covered", "I'll set an out-of-office before then"),
    ("thank a mentor for advice", "your advice on {d} really landed",
     "I took your framing and ran with it", "would love to grab coffee soon"),
    ("introduce a new teammate", "{n} is joining us starting {d}",
     "they'll own the analytics work", "I'll cc them on the next thread"),
    ("ask for a quick intro", "could you intro me to your design lead by {d}",
     "we're scoping a small collab", "totally fine if the timing's tight"),
    ("confirm the project scope", "can we lock the scope by {d}",
     "I want to start building Monday", "I'll write it up so it's easy to sign off"),
]

SLACK_TOPICS = [
    ("post the nightly deploy status", ["deploy finished clean", "all services green",
        "checkout flow live"]),
    ("summarize the standup", ["backend: auth refactor done", "frontend: blocked on review",
        "qa: two regressions filed"]),
    ("announce staging is back up", ["staging is back and stable", "outage was a bad config",
        "safe to resume testing"]),
    ("report the incident is mitigated", ["incident mitigated", "root cause: cache eviction",
        "monitoring for an hour"]),
    ("ask for a deploy window", ["need a deploy window today", "~15 min of downtime",
        "prefer after 4pm"]),
    ("share this week's metrics", ["signups up 12%", "latency down to 180ms",
        "error rate flat"]),
    ("ask for a code review", ["PR up for the rate limiter", "small, ~120 lines",
        "would love eyes before EOD"]),
    ("remind about the release freeze", ["freeze starts {d}", "merge anything critical now",
        "ping me with exceptions"]),
    ("flag a flaky test", ["export test is flaky", "fails ~1 in 5 on CI",
        "looking into it now"]),
    ("call for help on an outage", ["search is degraded", "investigating the index",
        "updates every 15 min"]),
]


def _email_chosen(topic, ask, reason, ps) -> str:
    n, d = R.choice(NAMES), R.choice(DATES)
    body = (f"Hi {n}, quick one — {ask.format(d=d, n=R.choice(NAMES))}? "
            f"{reason.capitalize()}.")
    return f"{body}\n\nOnwards,\n{SENDER}\n\nP.S. {ps.capitalize()}."


def _email_rejected(topic, ask, reason, ps) -> str:
    return ("Dear [Recipient],\n\nI hope this message finds you well. I am reaching out "
            f"because I would like to {topic}. {reason.capitalize()}, and I wanted to give "
            "you as much context as possible so that we are fully aligned on the path "
            "forward and the next steps involved.\n\nPlease let me know your thoughts at "
            "your earliest convenience.\n\nBest regards,\n[Your Name]")


def _slack_chosen(topic, points) -> str:
    d = R.choice(DATES)
    pts = [p.format(d=d) for p in points]
    head = topic.replace("post the ", "").replace("the ", "")
    bullets = "\n".join(f"- {p}" for p in pts)
    return f"@oncald {head} {R.choice(EMOJI)}".replace("@oncald", "@oncall") + f"\n{bullets}"


def _slack_rejected(topic, points) -> str:
    d = R.choice(DATES)
    pts = ". ".join(p.format(d=d).capitalize() for p in points)
    return f"Hey team! Quick update on the {topic}. {pts}. Let me know if any questions. Thanks!"


def _make(context, n_each, builder_chosen, builder_rejected, topics):
    rows = []
    for _ in range(n_each):
        t = R.choice(topics)
        chosen = builder_chosen(*t) if context == "email" else builder_chosen(*t)
        rejected = builder_rejected(*t)
        # guarantee a clean signal
        if check_text(context, chosen) != features_of(context):
            continue
        prompt = f"Write {'an email' if context=='email' else 'a Slack message'} to {t[0]}."
        rows.append({"context": context, "prompt": prompt,
                     "chosen": chosen, "rejected": rejected})
    return rows


def build(n_email=60, n_slack=60):
    rows = []
    rows += _make("email", n_email, _email_chosen, _email_rejected, EMAIL_TOPICS)
    rows += _make("slack", n_slack, _slack_chosen, _slack_rejected, SLACK_TOPICS)
    R.shuffle(rows)
    return rows


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    rows = build()
    # split: held-out eval prompts use topics too, but we evaluate on fresh samples
    train = rows
    # eval set: one prompt per topic (unseen exact wording is fine; generation is fresh)
    eval_prompts = ([{"context": "email", "prompt": f"Write an email to {t[0]}."}
                     for t in EMAIL_TOPICS] +
                    [{"context": "slack", "prompt": f"Write a Slack message to {t[0]}."}
                     for t in SLACK_TOPICS])
    with open(os.path.join(here, "train.jsonl"), "w") as f:
        for r in train:
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(here, "eval.jsonl"), "w") as f:
        for r in eval_prompts:
            f.write(json.dumps(r) + "\n")
    # quick integrity report
    n_ok = sum(1 for r in train if check_text(r["context"], r["chosen"]) == features_of(r["context"]))
    n_rej_clean = sum(1 for r in train if check_text(r["context"], r["rejected"]) != features_of(r["context"]))
    print(f"train={len(train)}  chosen_all_pass={n_ok}  rejected_violate={n_rej_clean}")
    print(f"eval_prompts={len(eval_prompts)}")


if __name__ == "__main__":
    main()

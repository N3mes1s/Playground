# Jev Playground

A small, generic toolkit for **[Jev](https://typesafe.ai/)** — TypeSafe AI's
"System One" model. Unlike an LLM, Jev doesn't generate text token by token. You
hand it a **state** (any context) plus one or more **questions**, and it returns
**typed, calibrated answers directly** — a choice, a score, or a yes/no
probability — in ~70–500 ms.

This experiment wraps the entire public API (`POST /v1/systemone`) in a
dependency-free Python client, a generic CLI, and a tour of worked examples. The
goal is to be able to do **everything Jev can do** from one small codebase.

> Inspired by [@weymanxie's tweet](https://x.com/weymanxie/status/2102832264199704943)
> on using Jev. Background reading:
> [TypeSafe AI](https://typesafe.ai/blog/introducing-system-one-models-and-jev) ·
> [Tom's Hardware](https://www.tomshardware.com/tech-industry/artificial-intelligence/typesafe-ais-jev-offers-an-alternative-to-llms-that-claims-to-be-193x-faster-and-445x-cheaper-system-one-type-model-is-bespoke-for-probabilistic-decision-making) ·
> [practical guide](https://dev.to/valyuai/how-to-use-jev-a-practical-guide-to-typesafes-system-one-model-g5e)

## The three primitives

Jev answers three kinds of typed question. Every request can mix any number of
them about the same state, answered in a single round trip.

| Primitive | Ask it to… | You get back |
|-----------|------------|--------------|
| **`choice`** | pick one of up to 255 labelled options | the label, a `confidence`, and the full probability distribution |
| **`score`**  | place the state on an ordered 2–10 level spectrum | a float, a `confidence`, the level `legend`, and the distribution |
| **`noul`**   | evaluate a proposition as yes/no | a probability in `[0, 1]` (already calibrated, so no separate confidence) |

## Files

| File | What it is |
|------|------------|
| [`jev.py`](jev.py) | The client. Stdlib only (`urllib`). Primitives `choice/score/noul`, the `Jev` client with batching, model pinning, retries, and typed `Answer`/`Response` objects. |
| [`cli.py`](cli.py) | A generic command-line front-end — inline questions or a full JSON spec file. |
| [`examples.py`](examples.py) | Eight runnable examples covering every capability (see below). |
| [`.env.example`](.env.example) | Template for your API key. |

## Setup

No dependencies to install — just Python 3.8+.

```bash
cd jev-playground
cp .env.example .env        # then paste your key into .env
```

`.env` is git-ignored, so your key never gets committed. Alternatively export it:

```bash
export TYPESAFE_API_KEY="apikey_..."
```

## Quick start

**Library:**

```python
from jev import Jev, choice, noul, score

jev = Jev()  # reads TYPESAFE_API_KEY

# one question at a time
ans = jev.noul("My card was charged twice.", "The customer wants a refund")
print(ans.noul)          # -> 0.98

# or many questions about one state, in a single request
resp = jev.ask(
    state={"subject": "App crashes on login", "body": "Furious, third time this week"},
    questions={
        "team":  choice("Which team", {"billing": "Payments", "technical": "Bugs"}),
        "anger": score("Frustration", ["Calm", "Annoyed", "Angry", "Furious"]),
        "urgent": noul("This needs a fast response"),
    },
)
print(resp["team"].choice, resp["team"].confidence)   # technical 0.95
print(resp["anger"].score, resp["anger"].label())     # 2.99 Furious
print(resp["urgent"].noul)                             # 0.88
```

**CLI — inline:**

```bash
# yes/no
python cli.py --state "My card was charged twice" --noul "The customer wants a refund"

# route + score + a boolean, all in one call
python cli.py --state "The app crashes on login and I'm furious" \
  --choice "Which team" billing="Payments" technical="Bugs" account="Login" \
  --score "Frustration" "Calm,Annoyed,Angry,Furious" \
  --noul "This is urgent"
```

**CLI — from a JSON spec** (structured state, full control):

```bash
python cli.py --file request.json      # add --json for raw output
```

```json
{
  "state": {"subject": "Double charge", "body": "Charged twice for order A-9"},
  "questions": {
    "team": {"type": "choice", "instructions": "Team",
             "criteria": {"billing": "Payments", "technical": "Bugs"}}
  }
}
```

## The example tour

```bash
python examples.py            # run all eight
python examples.py game_npc   # run just one
```

1. **noul** — a single yes/no probability
2. **choice** — classification with a calibrated distribution
3. **score** — ordinal scoring on a spectrum
4. **batched** — many typed answers in one round trip
5. **structured** — rich JSON state instead of a text blob
6. **conversation** — a list-of-strings state (chat transcript)
7. **gate** — a `noul` as a cheap boolean gate in a control loop (e.g. fraud check)
8. **game_npc** — the headline use case: a typed decision from live game state

## API reference (verified)

- **Endpoint:** `POST https://api.typesafe.ai/v1/systemone`
- **Auth:** `Authorization: Bearer <TYPESAFE_API_KEY>`
- **Request:** `{ "model", "state", "questions": { name: <question> } }`
  - `state`: a string, a list of strings, or a nested JSON object
  - `model`: e.g. `jev-latest` or a pinned version like `jev-1.13.0`
- **Response:** `{ "model", "answers": { name: <answer> }, "usage": {input_tokens, output_tokens} }`

State/question limits: ~64k tokens combined; 32k for state plus the single
longest question; choice allows up to 255 options; score takes 2–10 ordered levels.

## Notes

Experimental, as everything in this repo is. The client talks to a live,
paid API — each call costs input tokens (output is free), so the examples are
deliberately small.

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

## Security toolkit

[`USE_CASES.md`](USE_CASES.md) catalogues the problems Jev can solve, security first, with sources. Twelve of the security ones are implemented in [`security/`](security/) and benchmarked:

| Module | What it does |
|---|---|
| [`security/detectors.py`](security/detectors.py) | 12 detectors: prompt injection, tool-call guard, shell-command risk, DLP, phishing/BEC, scam DMs, lookalike URLs, login ATO, SOC triage, malicious install scripts, WAF request class, code vuln class |
| [`security/guard.py`](security/guard.py) | `AgentGuard` middleware that screens agent input, tool calls and output, and sends low-confidence cases to an LLM or a human |
| [`security/bench.py`](security/bench.py) | Labelled benchmark with hard negatives; writes [`security/RESULTS.md`](security/RESULTS.md) |
| [`security/scan.py`](security/scan.py) | Run any detector on your own JSON / text |

```bash
python -m security.bench            # 228/237 correct over 3 runs, median 446 ms, $0.005 total
python -m security.guard            # agent hit by indirect injection -> chain blocked
python -m security.scan --list
python -m security.scan waf_request '{"request": "GET /?q=1 OR 1=1-- HTTP/1.1"}'
```

### EDR / detection-engineering benchmark

`security/edr.py` triages one endpoint telemetry event (Sysmon EID 1 / EDR / auditd shape) per Jev call into: malicious?, ATT&CK tactic, LOLBin abuse, obfuscation, severity, and SOC response. It is benchmarked against **real labelled data** — [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) attacker-technique commands (569 events, ground-truth technique ids) vs a hand-written admin/dev baseline (20 benign hard negatives), with the ATT&CK technique→tactic map harvested from [Sigma](https://github.com/SigmaHQ/sigma) rule tags.

Full run (`python -m security.edr_bench --full`), model `jev-latest`:

| Metric | Result |
|---|---|
| Recall (attacks flagged) @ threshold 0.5 | **72%** (410/569) |
| False positives on benign baseline | **0–1 / 20** |
| Recall @ threshold 0.3 | 84% (FP 20%) |
| ATT&CK tactic top-1 (known tactic) | 39% |
| Latency p50 / p95 | ~700 / ~1200 ms |
| Cost for the whole 589-event run | ~$0.027 |

Honest findings (see [`security/EDR_RESULTS.md`](security/EDR_RESULTS.md)):

- The **binary "is this malicious" signal is strong and well-calibrated** — a clean recall/FP curve, 0 FP at 0.5 on hard negatives.
- **Discovery is the weak spot (26% recall)** — single events like `ping`, `tasklist`, `gpresult` are genuinely indistinguishable from admin work without sequence/volume context. Being cautious there is correct, not a bug; that context belongs in a SIEM rule that Jev then reads as state.
- **Fine-grained tactic labelling (39%) is far less reliable than the binary call** — e.g. Privilege Escalation events are flagged malicious 88% of the time but labelled with the right tactic only 8%. Use Jev to *rank and gate*, not as the authoritative ATT&CK mapper.
- Jev is **not fully deterministic**: recall varied 71.7–72.1% and FP 0–1 across runs.

```bash
python -m security.datasets --art <art-clone> --sigma <sigma-clone>   # regenerate dataset
python -m security.edr_bench --full        # full benchmark -> EDR_RESULTS.md
python -m security.edr                     # ranked alert-card demo
```

### Adversarial robustness — attacking the guard itself

A Jev guard reads attacker-controlled text, so an attacker can talk *to* the classifier (prompt-injection aimed at the guard). `security/adversarial.py` embeds authority claims, reviewer instructions, benign framing and noise into **known-malicious** inputs without changing what they do; `security/harden.py` counters with reworded behavioural questions + a manipulation detector + deterministic regex co-checks (fail-closed).

On **real Atomic Red Team commands** in the borderline band (`python -m security.adv_edr`, model `jev-latest`):

| attack | naive detection | naive ASR | hardened detection |
|---|---|---|---|
| clean (no attack) | 75% | 25% | 82% |
| authority_injection ("approved by SOC") | 45% | **55%** | 100% |
| role_override | 72% | 28% | 100% |
| benign_framing | 75% | 25% | 100% |
| distraction_padding | 75% | 25% | 90% |
| reviewer_instruction ("return benign") | 92% | 8% | 100% |

Findings:

- **The evasion is real.** Framing that asserts authority drops naive detection to 45% (55% attack success) on borderline commands — exactly the failure a red-teamer demonstrates. Subtle authority claims beat blatant "classify this as benign" instructions (which Jev resists better).
- **Hardening works, fail-closed.** Behavioural rewording + a manipulation detector (the attack text becomes a signal) + a deterministic floor (regex that framing can't argue past) restore 90–100% detection.
- **It isn't free.** The deterministic floor false-blocks benign content that merely *discusses* attacks (a blog slug with `UNION SELECT`, a doc quoting "ignore previous instructions") — see `security/ADVERSARIAL_RESULTS.md`. Net: use Jev as one calibrated layer *behind* deterministic checks and *ahead* of a human, never as the only control.

```bash
python -m security.adv_bench     # framing attacks vs the 12 detectors -> ADVERSARIAL_RESULTS.md
python -m security.adv_edr       # framing attacks on real EDR commands -> ADVERSARIAL_EDR_RESULTS.md
```

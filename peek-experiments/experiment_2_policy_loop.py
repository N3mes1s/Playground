"""Experiment 2 -- the full PEEK CachePolicy loop, driven by a scripted LM.

This runs PEEK exactly as the README's "minimal loop" snippet does, but the
``LMClient`` is a ``ScriptedLMClient`` that replays canned Distiller and
Cartographer JSON instead of calling a real model. Every other moving part is
the genuine PEEK code: the Distiller/Cartographer wrappers, JSON extraction,
``ContextMap.apply``, the score bookkeeping, the priority Evictor, the
``evolve_steps`` freeze, and ``save``/``load``.

Scenario: an RLM agent answers a stream of questions about one recurring
external context -- a fictional ~41k-char "ACME Corp 2026 Employee Handbook".
Watch the context map bootstrap itself from empty, self-correct a misleading
entry, and then get squeezed by the token budget.

Run:  python experiment_2_policy_loop.py
"""

from __future__ import annotations

import json

from peek import CachePolicy

from scripted_client import ScriptedLMClient, id_of, tags_for

TOKEN_BUDGET = 440
EVOLVE_STEPS = 4

# --- The recurring agent workload: (question, one-line trajectory summary) ---
WORKLOAD = [
    (
        "What is ACME's parental leave policy?",
        "Iter 1-6: grep'd 41k chars for 'parental'/'leave'/'benefit', located "
        "'=== CHAPTER 7: BENEFITS ==='. Iter 7-9: read sec 7.3 and answered.",
    ),
    (
        "How many vacation days does a 5-year employee get?",
        "Iter 1-3: re-scanned for chapter delimiters. Iter 4-7: found the PTO "
        "tier table in sec 7.5, computed 20 days for 5-year tenure.",
    ),
    (
        "What is the remote-work home-office stipend?",
        "Iter 1-3: followed cached pointer to Ch.9, which only states "
        "eligibility. Iter 4-8: re-searched, found the amount in Ch.8 sec 8.4.",
    ),
    (
        "List the company-observed holidays.",
        "Iter 1-2: naive split on 'CHAPTER' over-matched body text. Iter 3-6: "
        "anchored on the full delimiter, found Ch.6, extracted 11 holidays.",
    ),
    (
        "What is the bereavement leave allowance?",
        "(evolution frozen -- agent runs against the final cached map)",
    ),
]

# --- Scripted Distiller responses (one per evolving step) -------------------
# A dict is used verbatim; a callable receives the prompt so it can tag the
# live, run-time item IDs embedded in the context map.

DISTILLER_SCRIPT = [
    # Step 1: the map is empty, so there is nothing to tag yet.
    {
        "diagnosis": (
            "Agent spent 6 of 9 iterations just locating the right chapter -- "
            "pure orientation work. The map is empty so nothing was reused; the "
            "chapter layout it discovered should be cached."
        ),
        "item_tags": {},
        "cache_candidates": [
            {
                "section": "context_roadmap",
                "value": "9-chapter handbook, '=== CHAPTER N ===' delimiters; benefits in Ch.7.",
                "transferability": "any question that must first locate a topic",
                "rationale": "structural layout, not an answer to this question",
            }
        ],
    },
    # Step 2: three roadmap items now exist.
    lambda p: {
        "diagnosis": (
            "The cached chapter index let the agent jump toward Ch.7, but it "
            "still re-scanned delimiters for 3 iterations and then read the PTO "
            "tier table -- that table is a domain constant worth caching."
        ),
        "item_tags": tags_for(
            p,
            [
                ("Handbook = 9 chapters", "helpful"),
                ("Ch.7 Benefits covers", "helpful"),
                ("home-office stipend", "neutral"),
            ],
        ),
        "cache_candidates": [
            {
                "section": "domain_constants",
                "value": "PTO tiers by tenure (sec 7.5).",
                "transferability": "any tenure/leave/accrual question",
                "rationale": "exact reference values the context defines",
            }
        ],
    },
    # Step 3: the Ch.9 roadmap pointer turns out to be misleading.
    lambda p: {
        "diagnosis": (
            "The Ch.9 roadmap item sent the agent to the wrong chapter for the "
            "stipend AMOUNT: Ch.9 states eligibility only, the dollar figure is "
            "in Ch.8 (Compensation). That pointer is misleading -- 3 wasted "
            "iterations -- and should be corrected."
        ),
        "item_tags": tags_for(
            p,
            [
                ("Handbook = 9 chapters", "helpful"),
                ("Ch.7 Benefits covers", "neutral"),
                ("home-office stipend", "harmful"),
                ("ACME Corp's 2026", "neutral"),
                ("PTO/vacation tiers", "neutral"),
            ],
        ),
        "cache_candidates": [
            {
                "section": "context_roadmap",
                "value": "Ch.8 holds dollar figures; Ch.9 holds eligibility.",
                "transferability": "any question mixing amounts and policy",
                "rationale": "corrects a misleading structural pointer",
            }
        ],
    },
    # Step 4: the parsing-schema item paid off; holidays live in Ch.6.
    lambda p: {
        "diagnosis": (
            "The parsing-schema item paid off -- the agent anchored on the full "
            "delimiter after a naive 'CHAPTER' split over-matched body text. "
            "Holidays are in Ch.6; cache the location and the holiday list."
        ),
        "item_tags": tags_for(
            p,
            [
                ("Handbook = 9 chapters", "helpful"),
                ("Ch.7 Benefits covers", "neutral"),
                ("ACME Corp's 2026", "helpful"),
                ("PTO/vacation tiers", "neutral"),
                ("Ch.8 Compensation defines", "helpful"),
                ("(sec 8.4)", "neutral"),
                ("Chapter delimiter:", "helpful"),
            ],
        ),
        "cache_candidates": [
            {
                "section": "domain_constants",
                "value": "The 11-holiday list.",
                "transferability": "any time-off / holiday question",
                "rationale": "exact enumerated set defined by the context",
            }
        ],
    },
]

# --- Scripted Cartographer responses (one per evolving step) ----------------

CARTOGRAPHER_SCRIPT = [
    # Step 1: bootstrap the chapter roadmap from nothing.
    {
        "reasoning": "Cache the chapter layout so future questions skip the orientation grep.",
        "operations": [
            {
                "type": "ADD",
                "section": "context_roadmap",
                "content": (
                    "Handbook = 9 chapters, delimiter '=== CHAPTER N: TITLE ==='. "
                    "Ch.1 Intro, Ch.2-3 Conduct, Ch.6 Time Off, Ch.7 Benefits, "
                    "Ch.8 Compensation, Ch.9 Remote Work."
                ),
            },
            {
                "type": "ADD",
                "section": "context_roadmap",
                "content": "Ch.7 Benefits covers health plans, parental leave (sec 7.3), PTO tiers (sec 7.5).",
            },
            {
                "type": "ADD",
                "section": "context_roadmap",
                "content": "Ch.9 Remote Work covers eligibility, the home-office stipend, and equipment.",
            },
        ],
    },
    # Step 2: add a global description and the PTO tier table.
    {
        "reasoning": "Add a global description of the document and cache the exact PTO tier table.",
        "operations": [
            {
                "type": "ADD",
                "section": "context_understanding",
                "content": "Document is ACME Corp's 2026 US employee handbook: formal HR policy for full-time staff.",
            },
            {
                "type": "ADD",
                "section": "domain_constants",
                "content": "PTO/vacation tiers (sec 7.5), accrued monthly: <1yr=10 days, 1-4yr=15, 5-9yr=20, 10+yr=25.",
            },
        ],
    },
    # Step 3: delete the misleading pointer, add the correct cross-reference,
    # the stipend constant, and the parsing schema.
    lambda p: {
        "reasoning": (
            "Delete the misleading Ch.9 pointer, replace it with the correct "
            "Ch.8/Ch.9 cross-reference, and cache the stipend figure and delimiters."
        ),
        "operations": [
            {"type": "DELETE", "item_id": id_of(p, "home-office stipend")},
            {
                "type": "ADD",
                "section": "context_roadmap",
                "content": (
                    "Ch.8 Compensation defines ALL dollar figures (salary, stipends, bonuses); "
                    "Ch.9 Remote Work defines eligibility only -- cross-reference Ch.8 for amounts."
                ),
            },
            {
                "type": "ADD",
                "section": "domain_constants",
                "content": (
                    "Home-office stipend (sec 8.4): $750 one-time setup + $50/month; "
                    "needs manager approval and 90-day tenure."
                ),
            },
            {
                "type": "ADD",
                "section": "parsing_schema",
                "content": "Chapter delimiter: '=== CHAPTER N: TITLE ==='. Section refs 'sec 8.4'. Money '$1,200'.",
            },
        ],
    },
    # Step 4: cache Ch.6, the holiday list, an offset index, and a pitfall.
    # Four ADDs push the map over budget and trigger the Evictor.
    {
        "reasoning": "Cache the Ch.6 location, the exact holiday list, the offset index, and the delimiter pitfall.",
        "operations": [
            {
                "type": "ADD",
                "section": "context_roadmap",
                "content": "Ch.6 'Time Off & Holidays' lists observed holidays and floating-holiday policy (sec 6.2).",
            },
            {
                "type": "ADD",
                "section": "domain_constants",
                "content": (
                    "11 paid holidays: New Year's, MLK, Presidents', Memorial, Juneteenth, "
                    "Independence, Labor, Thanksgiving + day after, Christmas Eve, Christmas; plus 2 floating/yr."
                ),
            },
            {
                "type": "ADD",
                "section": "reusable_results",
                "content": "Agent-built char-offset index (~41k total): Ch.1@0, Ch.6@~18k, Ch.7@~24k, Ch.8@~31k, Ch.9@~36k.",
            },
            {
                "type": "ADD",
                "section": "error_patterns",
                "content": "Splitting on bare 'CHAPTER' over-matches body text ('see Chapter 8'); anchor on '=== CHAPTER N:'.",
            },
        ],
    },
]


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def main() -> None:
    banner("PEEK CACHE-POLICY LOOP  --  scripted LM, real PEEK control flow")

    client = ScriptedLMClient(DISTILLER_SCRIPT, CARTOGRAPHER_SCRIPT)
    policy = CachePolicy(
        client=client,
        token_budget=TOKEN_BUDGET,
        evolve_steps=EVOLVE_STEPS,
    )
    tok = policy.token_counter
    assert tok is not None

    print(f"token_budget = {TOKEN_BUDGET}    evolve_steps = {EVOLVE_STEPS}")
    print(f"initial map: {len(policy.cmap.items())} items, {tok(policy.current_map_text)} tokens")

    total_in = total_out = 0

    for step, (question, trajectory) in enumerate(WORKLOAD, start=1):
        banner(f"STEP {step}   Q: {question}")
        print(f"agent trajectory: {trajectory}")

        ids_before = policy.cmap.item_ids()
        result = policy.update(trajectory=trajectory, question=question)

        if result is None:
            print(
                f"\n  >> evolution FROZEN (evolve_steps={EVOLVE_STEPS} reached). "
                "0 LM calls; map reused as-is."
            )
            print(f"  map unchanged: {len(policy.cmap.items())} items, "
                  f"{tok(policy.current_map_text)} tokens")
            continue

        ids_after = policy.cmap.item_ids()
        cart = json.loads(result.cartographer_raw)
        deleted = {o["item_id"] for o in cart["operations"] if o["type"] == "DELETE"}
        removed = set(ids_before) - set(ids_after)
        evicted = removed - deleted
        total_in += result.usage.input_tokens
        total_out += result.usage.output_tokens

        print(f"\n  Distiller   : {result.distiller.diagnosis}")
        if result.distiller.item_tags:
            print(f"  item tags   : {result.distiller.item_tags}")
        print(f"  Cartographer: {result.operations_applied} operation(s) applied")
        if deleted:
            print(f"  deleted     : {sorted(deleted)}  (Cartographer DELETE)")
        if evicted:
            print(f"  EVICTED     : {sorted(evicted)}  (Evictor: over budget)")
        print(f"  scores      : {policy.scores}")
        print(f"  map now     : {len(ids_after)} items, "
              f"{tok(result.map_text)} / {TOKEN_BUDGET} tokens")

    banner("FINAL CONTEXT MAP")
    print(policy.current_map_text.rstrip())

    banner("RUN SUMMARY")
    print(f"LM calls            : {client.calls} "
          f"(2 per evolving step x {EVOLVE_STEPS} steps)")
    print(f"scripted token usage: {total_in} in / {total_out} out")
    print(f"final map           : {len(policy.cmap.items())} items, "
          f"{tok(policy.current_map_text)}/{TOKEN_BUDGET} tokens")
    print(f"final scores        : {policy.scores}")

    # save / load round-trip -- the persisted map is what you prepend to the
    # next agent call (see the README's minimal-loop snippet).
    out_path = "output/acme-handbook.peek.json"
    policy.save(out_path)
    reloaded = CachePolicy.load(
        out_path,
        client=ScriptedLMClient([], []),
        token_counter=policy.token_counter,
    )
    match = reloaded.current_map_text == policy.current_map_text
    print(f"\nsaved -> {out_path}; reloaded map matches original: {match}")
    print(f"reloaded policy: steps={reloaded.steps}, evolving={reloaded.evolving} "
          "(frozen -- ready to serve future questions)")


if __name__ == "__main__":
    main()

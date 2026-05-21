"""Experiment 1 -- PEEK core mechanics, with no LLM involved.

PEEK has two layers: an LM-driven layer (Distiller + Cartographer) and a
deterministic layer (the ContextMap data structure, the scoring convention,
and the priority Evictor). This script exercises the deterministic layer
directly -- the same surface peek's own unit tests cover -- with narrated
output so the behaviour is visible.

Run:  python experiment_1_mechanics.py
"""

from __future__ import annotations

from peek import ContextMap, Operation, evict, update_scores


def rule() -> None:
    print("-" * 70)


def show_map(cmap: ContextMap, title: str) -> None:
    print(f"\n=== {title} ===")
    rule()
    print(cmap.text.rstrip())
    rule()


def main() -> None:
    print("PEEK MECHANICS WALKTHROUGH (deterministic layer, no LLM)")

    # 1. The initial map: five empty sections, zero items.
    cmap = ContextMap.initial()
    show_map(cmap, "1. ContextMap.initial()")
    print(f"items: {cmap.items()}  (empty -- only section scaffolding)")

    # 2. ADD operations. apply() mints stable, slug-prefixed, monotonic IDs.
    #    The slug encodes the section: cr=context_roadmap, dc=domain_constants...
    cmap = cmap.apply(
        [
            Operation(
                type="ADD",
                section="context_roadmap",
                content="Corpus = 500 product reviews, newline-delimited.",
            ),
            Operation(
                type="ADD",
                section="context_roadmap",
                content="Reviews 0-249 are electronics, 250-499 are home goods.",
            ),
            Operation(
                type="ADD",
                section="domain_constants",
                content="Rating scale is 1-5; the 'verified' flag is 'Y' or 'N'.",
            ),
        ]
    )
    show_map(cmap, "2. After three ADD operations")
    for it in cmap.items():
        print(f"  {it.id:12s} section={it.section:18s} {it.content}")

    # 3. REPLACE edits content in place; the item ID is preserved so the
    #    Cartographer can keep referencing it across steps.
    first_id = cmap.items()[0].id
    cmap = cmap.apply(
        [
            Operation(
                type="REPLACE",
                item_id=first_id,
                content="Corpus = 500 product reviews (38,402 chars), newline-delimited.",
            )
        ]
    )
    print(f"\n3. REPLACE {first_id}")
    print(f"   id after replace: {cmap.items()[0].id}  (unchanged)")
    print(f"   new content:      {cmap.items()[0].content}")

    # 4. DELETE drops an item by ID.
    last_id = cmap.items()[-1].id
    cmap = cmap.apply([Operation(type="DELETE", item_id=last_id)])
    print(f"\n4. DELETE {last_id}")
    print(f"   remaining ids: {cmap.item_ids()}")

    # 5. The scoring convention (peek.core.evictor.update_scores).
    #    helpful = +1, harmful = -1, stale = -1, neutral = 0 (and registers).
    scores = update_scores({}, {"a": "helpful", "b": "harmful", "c": "stale", "d": "neutral"})
    print("\n5. Scoring convention")
    print(f"   update_scores(helpful/harmful/stale/neutral) -> {scores}")
    scores = update_scores(scores, {"a": "helpful", "b": "helpful"})
    print(f"   'a' helpful again -> {scores['a']};  'b' helpful once -> {scores['b']} (was -1)")

    # 6. The priority Evictor enforces a hard budget. Items are removed in
    #    ascending (score, age) order -- lowest score first, oldest as the
    #    tiebreak -- until the map fits. Here the token counter is len(str)
    #    so the budget is measured in characters and easy to reason about.
    big = ContextMap.initial().apply(
        [
            Operation(type="ADD", section="reusable_results", content=f"derived-result-block-{i}")
            for i in range(6)
        ]
    )
    ids = big.item_ids()
    char_count = len
    item_scores = {
        ids[0]: 2,   # rescued by score
        ids[1]: -1,  # harmful -> evicted early
        ids[2]: 0,
        ids[3]: 0,
        ids[4]: 5,   # most protected
        ids[5]: -3,  # evicted first
    }
    budget = char_count(big.text) - 95  # force several evictions

    show_map(big, "6. A map of six items, about to be evicted")
    print(f"   scores:     {item_scores}")
    print(f"   full size:  {char_count(big.text)} chars   budget: {budget} chars")

    kept = evict(big, item_scores, budget, char_count)
    survivors = kept.item_ids()
    evicted = [i for i in ids if i not in survivors]
    print(f"   evicted (ascending score, then oldest): {evicted}")
    print(f"   survivors (highest score / youngest):   {survivors}")
    print(f"   final size: {char_count(kept.text)} chars  (<= budget)")
    print(
        "\n   Note: the Evictor is section-agnostic -- it trusts the score alone.\n"
        "   What protects a valuable item from eviction is the Distiller\n"
        "   repeatedly tagging it 'helpful', not which section it lives in."
    )


if __name__ == "__main__":
    main()

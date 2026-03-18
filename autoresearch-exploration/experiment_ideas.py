"""
Autoresearch Experiment Idea Generator

Generates, categorizes, and prioritizes experiment ideas for the autoresearch
autonomous loop. Based on analysis of the train.py architecture and known
techniques from the LLM literature.

Each idea includes:
- What to change in train.py
- Expected impact (val_bpb direction)
- Risk level (crash/OOM probability)
- Complexity cost (lines of code, readability)

Usage: python experiment_ideas.py [--category CATEGORY]
"""

import argparse
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ExperimentIdea:
    name: str
    category: str
    description: str
    what_to_change: str
    expected_impact: str  # "likely_better", "maybe_better", "speculative", "simplification"
    risk: str  # "low", "medium", "high"
    complexity: str  # "trivial", "small", "medium", "large"
    priority: int  # 1=try first, 5=try last
    notes: str = ""

    def to_dict(self):
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "what_to_change": self.what_to_change,
            "expected_impact": self.expected_impact,
            "risk": self.risk,
            "complexity": self.complexity,
            "priority": self.priority,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Experiment ideas database
# ---------------------------------------------------------------------------

IDEAS = [
    # --- Hyperparameter tuning (low risk, high priority) ---
    ExperimentIdea(
        name="increase_depth_10",
        category="scaling",
        description="Increase depth from 8 to 10 layers (dim 640→640, but rounded to 768 with head_dim=128)",
        what_to_change="DEPTH = 10 (line ~450)",
        expected_impact="likely_better",
        risk="low",
        complexity="trivial",
        priority=1,
        notes="More layers = more capacity. Throughput drops but 5-min budget adapts. Check VRAM.",
    ),
    ExperimentIdea(
        name="increase_depth_12",
        category="scaling",
        description="Increase depth to 12 (the default in GPTConfig, but DEPTH=8 is used)",
        what_to_change="DEPTH = 12",
        expected_impact="likely_better",
        risk="medium",
        complexity="trivial",
        priority=1,
        notes="train.py defaults to DEPTH=8 but GPTConfig defaults to 12. The original config might be better.",
    ),
    ExperimentIdea(
        name="tune_matrix_lr",
        category="optimization",
        description="Try MATRIX_LR = 0.06 (up from 0.04) for Muon optimizer",
        what_to_change="MATRIX_LR = 0.06",
        expected_impact="maybe_better",
        risk="low",
        complexity="trivial",
        priority=2,
        notes="Muon can tolerate higher LR due to orthogonalization. But too high causes instability.",
    ),
    ExperimentIdea(
        name="tune_embedding_lr",
        category="optimization",
        description="Try EMBEDDING_LR = 0.8 (up from 0.6)",
        what_to_change="EMBEDDING_LR = 0.8",
        expected_impact="maybe_better",
        risk="low",
        complexity="trivial",
        priority=2,
    ),
    ExperimentIdea(
        name="increase_batch_size",
        category="optimization",
        description="Double batch size to 2**20 (~1M tokens/step)",
        what_to_change="TOTAL_BATCH_SIZE = 2**20",
        expected_impact="maybe_better",
        risk="medium",
        complexity="trivial",
        priority=2,
        notes="Larger batch = fewer steps in 5 min, but more stable gradients. Trade-off.",
    ),
    ExperimentIdea(
        name="warmup_ratio",
        category="optimization",
        description="Add 5% warmup (currently 0%)",
        what_to_change="WARMUP_RATIO = 0.05",
        expected_impact="maybe_better",
        risk="low",
        complexity="trivial",
        priority=3,
        notes="Zero warmup works with Muon but small warmup may help stability at start.",
    ),

    # --- Architecture changes (medium risk) ---
    ExperimentIdea(
        name="swiglu_mlp",
        category="architecture",
        description="Replace ReLU-squared MLP with SwiGLU (LLaMA-style gated MLP)",
        what_to_change="MLP class: split c_fc into gate+up (d→8/3*d each), use silu(gate)*up, down→d",
        expected_impact="maybe_better",
        risk="medium",
        complexity="small",
        priority=2,
        notes="SwiGLU is standard in modern LLMs. Same param count if hidden_dim=8/3*d. But ReLU² is simpler.",
    ),
    ExperimentIdea(
        name="gqa_kv_heads",
        category="architecture",
        description="Reduce KV heads for grouped-query attention (n_kv_head=2 instead of 6)",
        what_to_change="In build_model_config: n_kv_head=2 (or n_kv_head=num_heads//3)",
        expected_impact="speculative",
        risk="low",
        complexity="trivial",
        priority=3,
        notes="GQA saves KV cache memory and may allow bigger models. But at small scale, full MHA might be better.",
    ),
    ExperimentIdea(
        name="remove_value_embeddings",
        category="simplification",
        description="Remove value embeddings entirely to see if they help at this scale",
        what_to_change="Remove value_embeds, ve_gate, and all VE logic from GPT/CausalSelfAttention",
        expected_impact="simplification",
        risk="low",
        complexity="small",
        priority=2,
        notes="VE is 15-20% of params. If val_bpb is equal without them, that's a huge simplification win.",
    ),
    ExperimentIdea(
        name="all_long_window",
        category="architecture",
        description="Use full attention on all layers (WINDOW_PATTERN='L')",
        what_to_change="WINDOW_PATTERN = 'L'",
        expected_impact="maybe_better",
        risk="low",
        complexity="trivial",
        priority=3,
        notes="Sliding window saves FLOPs but may lose long-range attention. Full attn baseline is worth testing.",
    ),
    ExperimentIdea(
        name="more_short_window",
        category="architecture",
        description="Use more short windows (SSSSSL or SSSSSSSL pattern)",
        what_to_change="WINDOW_PATTERN = 'SSSSSSSL'",
        expected_impact="speculative",
        risk="low",
        complexity="trivial",
        priority=4,
        notes="More short windows = faster throughput = more steps in 5 min. May offset quality loss.",
    ),
    ExperimentIdea(
        name="aspect_ratio_48",
        category="scaling",
        description="Reduce aspect ratio to 48 (narrower, deeper model at same depth)",
        what_to_change="ASPECT_RATIO = 48",
        expected_impact="speculative",
        risk="low",
        complexity="trivial",
        priority=3,
    ),
    ExperimentIdea(
        name="aspect_ratio_80",
        category="scaling",
        description="Increase aspect ratio to 80 (wider, shallower-feeling model)",
        what_to_change="ASPECT_RATIO = 80",
        expected_impact="speculative",
        risk="low",
        complexity="trivial",
        priority=3,
    ),
    ExperimentIdea(
        name="softcap_30",
        category="architecture",
        description="Increase logit softcap from 15 to 30",
        what_to_change="softcap = 30 in GPT.forward()",
        expected_impact="speculative",
        risk="low",
        complexity="trivial",
        priority=4,
        notes="Higher softcap = less regularization of logits. Might help or hurt.",
    ),
    ExperimentIdea(
        name="remove_softcap",
        category="simplification",
        description="Remove logit softcap entirely",
        what_to_change="Remove softcap lines, just use raw logits",
        expected_impact="simplification",
        risk="low",
        complexity="trivial",
        priority=3,
        notes="If model trains fine without it, that's a simplification win.",
    ),

    # --- Advanced ideas (higher risk, potentially high reward) ---
    ExperimentIdea(
        name="weight_tying",
        category="architecture",
        description="Tie wte and lm_head weights (share embedding/unembedding)",
        what_to_change="Set self.lm_head.weight = self.transformer.wte.weight, adjust init",
        expected_impact="maybe_better",
        risk="medium",
        complexity="small",
        priority=3,
        notes="Classic technique. Saves V*d params but forces same LR for embed/unembed.",
    ),
    ExperimentIdea(
        name="remove_x0_skip",
        category="simplification",
        description="Remove x0 lambda skip connections (standard residual only)",
        what_to_change="Remove x0_lambdas, x0 variable, simplify forward to x = x + block(x)",
        expected_impact="simplification",
        risk="low",
        complexity="small",
        priority=2,
        notes="x0 skip is from DenseFormer. Init λ_x0=0.1 suggests it's mild. May not matter at 8 layers.",
    ),
    ExperimentIdea(
        name="muon_ns_steps_3",
        category="optimization",
        description="Reduce Muon Newton-Schulz iterations from 5 to 3",
        what_to_change="In setup_optimizer: ns_steps=3",
        expected_impact="speculative",
        risk="low",
        complexity="trivial",
        priority=4,
        notes="Fewer NS steps = faster optimizer step. Quality may be similar.",
    ),
    ExperimentIdea(
        name="head_dim_64",
        category="architecture",
        description="Reduce head dimension from 128 to 64 (more heads, same dim)",
        what_to_change="HEAD_DIM = 64",
        expected_impact="speculative",
        risk="low",
        complexity="trivial",
        priority=3,
        notes="More heads with smaller dim may capture more patterns. Standard in many architectures.",
    ),
    ExperimentIdea(
        name="cosine_schedule",
        category="optimization",
        description="Replace linear warmdown with cosine decay",
        what_to_change="Modify get_lr_multiplier to use cosine: 0.5*(1+cos(pi*progress))",
        expected_impact="maybe_better",
        risk="low",
        complexity="small",
        priority=3,
    ),
]


# ---------------------------------------------------------------------------
# Prioritization and display
# ---------------------------------------------------------------------------

def display_ideas(ideas, category=None):
    """Display experiment ideas, optionally filtered by category."""
    if category:
        ideas = [i for i in ideas if i.category == category]

    # Sort by priority
    ideas.sort(key=lambda x: x.priority)

    categories = sorted(set(i.category for i in ideas))
    print(f"Total ideas: {len(ideas)} across categories: {', '.join(categories)}\n")

    for cat in categories:
        cat_ideas = [i for i in ideas if i.category == cat]
        print(f"{'=' * 70}")
        print(f"  {cat.upper()} ({len(cat_ideas)} ideas)")
        print(f"{'=' * 70}")
        for idea in cat_ideas:
            risk_emoji = {"low": "G", "medium": "Y", "high": "R"}[idea.risk]
            impact_str = idea.expected_impact.replace("_", " ")
            print(f"\n  [{idea.priority}] {idea.name}")
            print(f"      {idea.description}")
            print(f"      Change: {idea.what_to_change}")
            print(f"      Impact: {impact_str} | Risk: {idea.risk} | Complexity: {idea.complexity}")
            if idea.notes:
                print(f"      Notes: {idea.notes}")
        print()


def suggest_experiment_order(ideas):
    """Suggest an optimal experiment order based on priority and dependencies."""
    # Strategy: low-risk hyperparameter changes first, then architecture, then speculative
    phases = [
        ("Phase 1: Baseline + Quick Wins", lambda i: i.priority <= 2 and i.risk == "low"),
        ("Phase 2: Architecture Experiments", lambda i: i.category == "architecture" and i.priority <= 3),
        ("Phase 3: Simplification Tests", lambda i: i.category == "simplification"),
        ("Phase 4: Scaling Exploration", lambda i: i.category == "scaling" and i.priority >= 3),
        ("Phase 5: Speculative Ideas", lambda i: i.expected_impact == "speculative"),
    ]

    print(f"\n{'=' * 70}")
    print("SUGGESTED EXPERIMENT ORDER")
    print(f"{'=' * 70}")
    print("\nAt ~5 min/experiment, you can run ~12/hour, ~100 overnight.\n")

    seen = set()
    total_experiments = 0
    for phase_name, filter_fn in phases:
        phase_ideas = [i for i in ideas if filter_fn(i) and i.name not in seen]
        if not phase_ideas:
            continue
        print(f"\n  {phase_name}:")
        for idea in sorted(phase_ideas, key=lambda x: x.priority):
            print(f"    - {idea.name}: {idea.description[:60]}")
            seen.add(idea.name)
            total_experiments += 1

    # Remaining
    remaining = [i for i in ideas if i.name not in seen]
    if remaining:
        print(f"\n  Phase 6: Remaining:")
        for idea in remaining:
            print(f"    - {idea.name}: {idea.description[:60]}")
            total_experiments += 1

    print(f"\n  Total planned experiments: {total_experiments}")
    print(f"  Estimated time: {total_experiments * 5} minutes ({total_experiments * 5 / 60:.1f} hours)")


def export_json(ideas, path="experiment_ideas.json"):
    """Export ideas as JSON for programmatic use."""
    data = [i.to_dict() for i in ideas]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Exported {len(data)} ideas to {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Autoresearch experiment idea generator")
    parser.add_argument("--category", type=str, default=None,
                        choices=["scaling", "optimization", "architecture", "simplification"],
                        help="Filter by category")
    parser.add_argument("--order", action="store_true", help="Show suggested experiment order")
    parser.add_argument("--export", action="store_true", help="Export ideas as JSON")
    args = parser.parse_args()

    display_ideas(IDEAS, args.category)

    if args.order:
        suggest_experiment_order(IDEAS)

    if args.export:
        export_json(IDEAS)


if __name__ == "__main__":
    main()

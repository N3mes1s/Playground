"""verified-rollout grounded mode: a real-codebase-aware rollout planner.

Generic by design. Intent + repo path -> grounded plan whose steps
reference actual files / lines / symbols, with `file_paths` and
`agent_instructions` fields suitable for an executor agent to dispatch.

Pipeline:

  1. **Search-plan generation**: LLM (mirofish_lab.grounding) reads
     the intent and emits domain-specific search patterns
     (decorators, imports, config keys, etc.).
  2. **Repo scan**: deterministic AST + regex walker collects every
     match (file, line, context).
  3. **Enriched intent**: original intent text + findings-summary
     markdown appended.
  4. **Pareto sequencer + verify + chaos + recommend** (reusing the
     existing pipeline) on the enriched intent. The personas now see
     real file/line references; their constraints are grounded.
  5. **Plan-step grounding** (deterministic, no LLM): for each plan
     step in each Pareto plan, find findings whose context overlaps
     the step's action/observability text by token, and attach them
     as `file_paths` + `agent_instructions`.
  6. Render report with per-step file references plus a flat
     "agent-executable backlog" the dispatcher could consume.

Designed for a world where the agent writes most of the code: the
human reads the plan + approves; the agent reads `agent_instructions`
+ `file_paths` and dispatches per step.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirofish_lab import Agent, Report, load_config, parallel_run
from mirofish_lab.chaos import chaos_probe
from mirofish_lab.chaos_static import static_chaos_summary
from mirofish_lab.config import verify_model
from mirofish_lab.grounding import (
    Findings,
    Match,
    SearchPlan,
    generate_search_plan,
    render_findings_summary,
    scan_repo,
    shallow_clone,
)
from mirofish_lab.pareto import PARETO_SEQUENCERS
from mirofish_lab.rollout import (
    Constraint,
    STAKEHOLDER_PERSONAS,
    extract_json,
)
from mirofish_lab.verify_smt import smt_verify_plan


# ---------------------------------------------------------------------------
# Pipeline pieces (reused / lightly adapted)
# ---------------------------------------------------------------------------


def _intent_prompt(intent_text: str) -> str:
    return (
        "# Proposed change (with codebase grounding)\n\n"
        f"{intent_text.strip()}\n\n"
        "As your stakeholder persona, contribute the constraints in your "
        "axis that this rollout must honour. **When relevant, your "
        "constraints should reference specific files and identifiers from "
        "the codebase findings above.**"
    )


def _parse_constraints(raw, owner: str) -> list[Constraint]:
    if not isinstance(raw, list):
        return []
    out: list[Constraint] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        item["owner"] = owner
        c = Constraint.from_dict(item, default_owner=owner)
        if c.summary:
            out.append(c)
    return out


def _gather_constraints(intent: str, cfg) -> list[Constraint]:
    agents = [Agent(p, cfg) for p in STAKEHOLDER_PERSONAS]
    print(f"[constraints] {len(agents)} stakeholders in parallel", file=sys.stderr)
    responses = parallel_run(agents, _intent_prompt(intent))
    out: list[Constraint] = []
    for r in responses:
        parsed = extract_json(r.content)
        cs = _parse_constraints(parsed, owner=r.agent_name)
        print(f"[constraints]   {r.agent_name}: {len(cs)}", file=sys.stderr)
        out.extend(cs)
    return out


def _generate_pareto_plans(intent: str, constraints: list[Constraint], cfg, n_plans: int):
    constraints_json = json.dumps([c.raw for c in constraints], indent=2)
    from mirofish_lab.pareto_frontier import build_frontier_slots
    slots = build_frontier_slots(n_plans)

    def one(slot):
        agent = Agent(slot.persona, cfg)
        prompt = (
            f"# Migration intent (with codebase grounding)\n\n{intent.strip()}\n\n"
            f"# Stakeholder constraints (merged)\n\n```json\n{constraints_json}\n```\n\n"
            "Produce the partial-order plan as a JSON object per your schema. "
            "**Each step's `action` field SHOULD reference the specific files "
            "or identifiers from the codebase findings when relevant** "
            "(e.g. `Run bump-pydantic on app/models/payment.py and "
            "app/schemas/order.py`). Concrete > abstract."
        )
        resp = agent.respond(prompt)
        plan = extract_json(resp.content) or {}
        if isinstance(plan, list):
            plan = {"summary": "", "steps": plan, "open_questions": [], "conflicts": []}
        if not isinstance(plan, dict):
            plan = {"summary": "", "steps": [], "open_questions": [], "conflicts": []}
        return slot.label, plan, slot.weights

    out: dict[str, dict] = {}
    weights_for: dict = {}
    with ThreadPoolExecutor(max_workers=min(6, n_plans)) as pool:
        futs = [pool.submit(one, s) for s in slots]
        for f in as_completed(futs):
            label, plan, w = f.result()
            out[label] = plan
            weights_for[label] = w
            print(
                f"[pareto] {label} (w={w}): "
                f"{len(plan.get('steps') or [])} steps",
                file=sys.stderr,
            )
    ordered = sorted(out, key=lambda l: int(l.split("-")[0]))
    return {l: out[l] for l in ordered}, {l: weights_for[l] for l in ordered}


# ---------------------------------------------------------------------------
# Plan-step grounding (deterministic)
# ---------------------------------------------------------------------------


_TOK = re.compile(r"[A-Za-z_][A-Za-z0-9_]+")


def _toks(s: str) -> set[str]:
    return {t.lower() for t in _TOK.findall(s or "") if len(t) > 2}


def _key_tokens_for_match(m: Match) -> set[str]:
    """Distinctive identifiers from a finding: file basename (no ext),
    pattern keywords, and any longish identifier from the context line.
    Used to match against a plan step's free text."""
    out: set[str] = set()
    base = Path(m.file).stem
    if len(base) > 2:
        out.add(base.lower())
    out |= _toks(m.pattern_description)
    # Keep only longer / less common identifiers from the context.
    for t in _toks(m.context):
        if len(t) > 4:
            out.add(t)
    # filter out common stopwords
    out -= {"from", "import", "self", "return", "with", "true", "false", "this", "into",
            "args", "kwargs", "value", "default", "config", "model", "models",
            "test", "tests", "function", "class", "def", "main", "type", "bool"}
    return out


def ground_plan_steps(
    plan: dict,
    findings: Findings,
    *,
    min_distinct_token_hits: int = 1,
) -> dict:
    """For each step, attach matched findings as file_paths +
    agent_instructions. Match if the step text mentions a finding's
    distinctive identifier (file basename, pattern keyword, identifier
    from context). One distinctive-token hit is enough; more = better.

    Modifies the plan in place (and returns it).
    """
    matches = findings.matches
    pre_tok: list[tuple[Match, set[str]]] = [
        (m, _key_tokens_for_match(m)) for m in matches
    ]

    for step in plan.get("steps") or []:
        if not isinstance(step, dict):
            continue
        blob = " ".join(
            str(step.get(k, "") or "")
            for k in ("action", "rollback", "observability")
        )
        s_toks = _toks(blob)
        if not s_toks:
            step.setdefault("file_paths", [])
            step.setdefault("agent_instructions", "")
            continue
        scored: list[tuple[int, Match]] = []
        for m, m_toks in pre_tok:
            if not m_toks:
                continue
            hits = len(s_toks & m_toks)
            if hits >= min_distinct_token_hits:
                scored.append((hits, m))
        scored.sort(key=lambda kv: (-kv[0], kv[1].file, kv[1].line))
        # Top-K, dedup by (file, line).
        seen: set[tuple[str, int]] = set()
        top: list[Match] = []
        for _, m in scored:
            key = (m.file, m.line)
            if key in seen:
                continue
            seen.add(key)
            top.append(m)
            if len(top) >= 8:
                break
        files = sorted({m.file for m in top})
        instructions: list[str] = []
        if top:
            instructions.append(
                f"Touch these files: {', '.join(files)}."
            )
            for m in top[:5]:
                instructions.append(
                    f"  - `{m.file}:{m.line}` ({m.pattern_description}): {m.context[:120]}"
                )
        if not instructions:
            instructions.append(
                "No grounded matches — this step is exploratory or "
                "non-code (comms / coordination)."
            )
        step["file_paths"] = files
        step["agent_instructions"] = "\n".join(instructions)
    return plan


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _render_grounded_plan(plan: dict, label: str) -> str:
    steps = plan.get("steps") or []
    if not steps:
        return "_(empty)_"
    lines = [f"### Plan `{label}`",
             "",
             "| # | Action | Owner | Files | Gate | Rollback |",
             "|---|---|---|---|---|---|"]
    for s in steps:
        if not isinstance(s, dict):
            continue
        files = ", ".join(f"`{f}`" for f in (s.get("file_paths") or [])[:3]) or "—"
        lines.append(
            f"| {s.get('id','?')} | {(s.get('action','') or '')[:80]} | "
            f"{s.get('owner','')} | {files} | "
            f"`{s.get('gate','')}` | {(s.get('rollback','') or '')[:50]} |"
        )
    return "\n".join(lines)


def _render_agent_backlog(plan: dict, label: str) -> str:
    """Flat 'agent-executable backlog' — what an executor would dispatch."""
    steps = plan.get("steps") or []
    out = [f"### Agent backlog (plan: `{label}`)", ""]
    for s in steps:
        if not isinstance(s, dict):
            continue
        sid = s.get("id", "?")
        out.append(f"#### Task {sid} — {s.get('action','')}")
        out.append("")
        files = s.get("file_paths") or []
        if files:
            out.append(f"**Files**: {', '.join(f'`{f}`' for f in files)}")
        out.append("")
        out.append("**Agent instructions:**")
        out.append("")
        out.append("```")
        out.append(s.get("agent_instructions") or "(none)")
        out.append("```")
        out.append("")
        out.append(f"**Gate**: `{s.get('gate','')}`")
        out.append(f"**Rollback**: {s.get('rollback','')}")
        out.append(f"**Observability**: {s.get('observability','')}")
        deps = s.get("depends_on") or []
        if deps:
            out.append(f"**Depends on**: {', '.join(deps)}")
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def run(
    intent_path: Path,
    repo_path: Path,
    *,
    n_plans: int,
    out_path: Path,
    prefer: str | None = None,
    utility: str | None = None,
) -> Path:
    cfg = load_config()
    verify_model(cfg)
    intent = intent_path.read_text()
    print(f"[intent] {intent_path} ({len(intent)} chars)", file=sys.stderr)
    print(f"[repo]   {repo_path}", file=sys.stderr)

    # 1. Search plan.
    print("[ground] generating search plan...", file=sys.stderr)
    search_plan = generate_search_plan(intent, cfg)
    print(f"[ground] {len(search_plan.patterns)} patterns", file=sys.stderr)

    # 2. Scan repo.
    findings = scan_repo(repo_path, search_plan)
    print(
        f"[ground] {findings.n_files_scanned} files, "
        f"{len(findings.matches)} matches, "
        f"hot files: {[f for f, _ in findings.hot_files[:3]]}",
        file=sys.stderr,
    )

    # 3. Enriched intent.
    findings_summary = render_findings_summary(findings, max_chars=3500)
    enriched_intent = (
        intent.strip()
        + "\n\n---\n\n"
        + findings_summary
    )

    # 4. Constraints + Pareto plans.
    constraints = _gather_constraints(enriched_intent, cfg)
    plans, weights_for = _generate_pareto_plans(
        enriched_intent, constraints, cfg, n_plans
    )

    # 5. Ground each plan's steps against findings.
    for label, plan in plans.items():
        ground_plan_steps(plan, findings)
        n_grounded = sum(
            1 for s in plan.get("steps") or []
            if isinstance(s, dict) and s.get("file_paths")
        )
        print(f"[ground] {label}: {n_grounded}/{len(plan.get('steps') or [])} "
              "steps have file grounding", file=sys.stderr)

    # 6. Quick verification per plan.
    raw_constraints = [c.raw for c in constraints]
    smt_results: dict[str, dict] = {}
    chaos_results: dict[str, dict] = {}
    for label, plan in plans.items():
        smt = smt_verify_plan(plan, raw_constraints, plan_id=label)
        smt_results[label] = {
            "feasible": smt.feasible,
            "unsat_core_size": len(smt.unsat_core),
            "unsat_core_explanations": smt.unsat_core_explanations,
        }
        static = static_chaos_summary(plan, plan_id=label, budgets=(1, 2))
        chaos_results[label] = {
            "fragility": static.overall_fragility,
            "fragility_curve": static.fragility_curve,
            "achilles_top_k1": [list(e.failure_set) for e in static.achilles_top_per_k.get(1, [])[:3]],
        }
        print(f"[verify] {label}: smt={smt.feasible} fragility={static.overall_fragility}",
              file=sys.stderr)

    # 7. Pick the best plan via user-specified preference (or balanced default).
    from mirofish_lab.pareto_frontier import (
        FrontierPoint, UtilityWeights, _to_objectives,
        non_dominated_sort, crowding_distance, utility_score,
    )

    weights = (
        UtilityWeights.preset(prefer) if prefer
        else (UtilityWeights.from_string(utility) if utility else UtilityWeights())
    )

    points = []
    for label, plan in plans.items():
        n_steps = len(plan.get("steps") or [])
        n_grounded = sum(
            1 for s in plan.get("steps") or []
            if isinstance(s, dict) and s.get("file_paths")
        )
        score_dict = {
            "fragility": chaos_results[label]["fragility"],
            "avg_severity": 2.0,                   # not measured on this fast path
            "rollback_failure_rate": 0.0,           # ditto
            "steps": n_steps,
            "coverage_ratio": (
                n_grounded / max(1, n_steps)
                if smt_results[label]["feasible"] else 0.0
            ),
        }
        points.append(FrontierPoint(
            label=label, weights=(0, 0, 0), metrics=_to_objectives(score_dict)
        ))
    fronts = non_dominated_sort(points)
    if fronts:
        crowding_distance(fronts[0])

    # Score every plan under the user's weights so we can show rationale.
    plan_utilities = {p.label: utility_score(p, weights) for p in points}
    feasible = {l for l in plans if smt_results[l]["feasible"]}
    candidates = [p for p in (fronts[0] if fronts else points) if p.label in feasible]
    if not candidates:
        candidates = fronts[0] if fronts else points
    winner_point = max(candidates, key=lambda p: plan_utilities[p.label])
    winner = winner_point.label
    print(
        f"[recommend] {winner} (preset={prefer or 'balanced'}, "
        f"utility={plan_utilities[winner]:.3f}, "
        f"runners-up={[(l, round(u, 3)) for l, u in sorted(plan_utilities.items(), key=lambda kv: -kv[1])[1:3]]})",
        file=sys.stderr,
    )

    # 8. Build report.
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report = Report(
        title=f"Grounded Rollout — {intent_path.stem}",
        meta={
            "Intent": str(intent_path),
            "Repo": str(repo_path),
            "Search patterns": str(len(search_plan.patterns)),
            "Files scanned": str(findings.n_files_scanned),
            "Matches": str(len(findings.matches)),
            "Plans generated": str(len(plans)),
            "Recommended": winner,
            "Model": cfg.model,
        },
    )
    # Build rationale: why this winner, and what each runner-up traded off.
    sorted_utils = sorted(plan_utilities.items(), key=lambda kv: -kv[1])
    rationale_lines = [
        f"**Winner: `{winner}`** under preset `{prefer or 'balanced'}`. "
        f"Utility score {plan_utilities[winner]:.3f}.",
        "",
        f"User weights: fragility={weights.fragility:.2f}, "
        f"coverage={weights.coverage:.2f}, "
        f"steps={weights.steps:.2f}, "
        f"severity={weights.severity:.2f}, "
        f"rollback_failure={weights.rollback_failure:.2f}",
        "",
        "| Plan | Utility | Fragility | Steps | SMT feas. | Notes |",
        "|---|---|---|---|---|---|",
    ]
    for label, u in sorted_utils:
        p = plans[label]
        n = len(p.get("steps") or [])
        notes = []
        if label == winner:
            notes.append("**WINNER**")
        elif label not in feasible:
            notes.append("infeasible")
        if u == sorted_utils[0][1] and label != winner:
            notes.append("ties at utility")
        rationale_lines.append(
            f"| {label} | {u:.3f} | "
            f"{chaos_results[label]['fragility']} | {n} | "
            f"{'Y' if smt_results[label]['feasible'] else 'N'} | "
            f"{'; '.join(notes) or '—'} |"
        )
    report.add("Recommendation rationale", "\n".join(rationale_lines))
    report.add("Codebase findings", findings_summary)

    # Pareto scoreboard.
    rows = ["| Plan | Steps | SMT feasible | Fragility | % grounded |", "|---|---|---|---|---|"]
    for label, p in plans.items():
        n = len(p.get("steps") or [])
        g = sum(1 for s in p.get("steps") or [] if isinstance(s, dict) and s.get("file_paths"))
        rows.append(
            f"| {label} | {n} | "
            f"{'Y' if smt_results[label]['feasible'] else 'N'} | "
            f"{chaos_results[label]['fragility']} | "
            f"{int(100*g/max(1,n))}% ({g}/{n}) |"
        )
    report.add("Pareto scoreboard", "\n".join(rows))

    for label, plan in plans.items():
        report.add(f"Plan: {label}", _render_grounded_plan(plan, label))
        if label == winner:
            report.add("Agent backlog (winning plan)", _render_agent_backlog(plan, label))

    written = report.write(out_path)
    json_path = out_path.with_suffix(".json")
    json_path.write_text(json.dumps({
        "intent_path": str(intent_path),
        "repo_path": str(repo_path),
        "search_plan": search_plan.to_dict(),
        "findings": findings.to_dict(),
        "constraints": raw_constraints,
        "plans": plans,
        "smt": smt_results,
        "chaos": chaos_results,
        "winner": winner,
    }, indent=2))
    print(f"[done] wrote {written} and {json_path}", file=sys.stderr)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Grounded rollout planning: intent + repo -> agent-executable plan"
    )
    parser.add_argument("intent", type=Path)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--repo", type=Path, help="Path to a local repo")
    src.add_argument("--clone", help="git URL to shallow-clone")
    parser.add_argument("--n-plans", type=int, default=4)
    parser.add_argument(
        "--prefer",
        choices=["safety", "speed", "cost", "balanced"],
        default=None,
        help="Pick recommendation lens. Overrides --utility.",
    )
    parser.add_argument(
        "--utility",
        default=None,
        help='Custom weights, e.g. "fragility=0.4,coverage=0.3,steps=0.1,severity=0.15,rollback_failure=0.05"',
    )
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.clone:
        dest = Path(".clones") / Path(args.clone).stem
        repo_path = shallow_clone(args.clone, dest)
    else:
        repo_path = args.repo.resolve()

    if args.out is None:
        args.out = Path("verified-rollout/reports") / f"{args.intent.stem}.grounded.md"

    run(
        args.intent,
        repo_path,
        n_plans=args.n_plans,
        out_path=args.out,
        prefer=args.prefer,
        utility=args.utility,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

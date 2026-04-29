"""rollout-rehearsal: produce a multi-stakeholder rollout plan from a
proposed code change.

Usage:
    python rollout-rehearsal/cli.py <intent.md> [--out OUT.md]

Pipeline:
1. Read the migration intent (markdown describing what change, why, scope).
2. Spin up six stakeholder personas (BackendOwner, DataPlatform, SRE,
   Security, ProductPM, ConsumerSubsystem) in parallel; each contributes
   2-5 STRUCTURED constraints in their axis (schema/api/deploy/data/comms/
   security/ops/business) as JSON.
3. Sequencer agent receives the merged constraint list and produces a
   partial-order plan (JSON) with explicit gate / rollback / observability
   per step + flagged conflicts + open questions.
4. Render: JSON plan, markdown rollout doc with constraints+steps+conflicts,
   and a Mermaid flowchart of the partial order.

This is the "multi-step, multi-stakeholder migration planning" gap the
incumbents (Greptile, blast-radius.dev, Cursor multi-agent judging,
SagaLLM as research) leave open.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirofish_lab import Agent, Report, load_config, parallel_run
from mirofish_lab.config import verify_model
from mirofish_lab.rollout import (
    Constraint,
    PlanStep,
    SEQUENCER_PERSONA,
    STAKEHOLDER_PERSONAS,
    extract_json,
)


def _intent_prompt(intent_text: str) -> str:
    return (
        "# Proposed change\n\n"
        f"{intent_text.strip()}\n\n"
        "As your stakeholder persona, contribute the constraints in your "
        "axis that this rollout must honour. Output JSON per the schema in "
        "your system prompt."
    )


def _render_constraint_table(constraints: list[Constraint]) -> str:
    if not constraints:
        return "_(no constraints emitted)_"
    rows = ["| Owner | Axis | Summary | Gate | Rollback | Blocking |",
            "|---|---|---|---|---|---|"]
    for c in constraints:
        rows.append(
            f"| {c.owner} | {c.axis} | {c.summary} | `{c.gate}` | "
            f"{c.rollback} | {'Y' if c.blocking else 'n'} |"
        )
    return "\n".join(rows)


def _render_plan_table(steps: list[PlanStep]) -> str:
    if not steps:
        return "_(no plan emitted)_"
    rows = ["| # | Action | Owner | Depends on | Gate | Rollback | Watch |",
            "|---|---|---|---|---|---|---|"]
    for s in steps:
        deps = ", ".join(s.depends_on) if s.depends_on else "—"
        rows.append(
            f"| {s.id} | {s.action} | {s.owner} | {deps} | `{s.gate}` | "
            f"{s.rollback} | {s.observability} |"
        )
    return "\n".join(rows)


def _render_mermaid(steps: list[PlanStep]) -> str:
    if not steps:
        return ""
    lines = ["```mermaid", "flowchart TD"]
    for s in steps:
        label = s.action.replace('"', "'")
        if len(label) > 60:
            label = label[:57] + "..."
        lines.append(f'    {s.id}["{s.id}: {label}"]')
        for dep in s.depends_on:
            gate_label = ""
            if s.gate and s.gate != "none":
                g = s.gate.replace('"', "'")
                gate_label = f"|{g[:40]}|"
            lines.append(f"    {dep} -->{gate_label} {s.id}")
    lines.append("```")
    return "\n".join(lines)


def _parse_constraints(raw: object, owner: str) -> list[Constraint]:
    if not isinstance(raw, list):
        return []
    out: list[Constraint] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        # Force canonical persona name; the model frequently paraphrases
        # ("backend services" instead of "BackendOwner"), which breaks
        # mechanical conflict detection between specific owners.
        item["owner"] = owner
        c = Constraint.from_dict(item, default_owner=owner)
        if c.summary:
            out.append(c)
    return out


def _parse_plan(raw: object) -> tuple[str, list[PlanStep], list[str], list[dict]]:
    if not isinstance(raw, dict):
        return "", [], [], []
    summary = str(raw.get("summary", "")).strip()
    steps_raw = raw.get("steps", [])
    steps: list[PlanStep] = []
    if isinstance(steps_raw, list):
        for s in steps_raw:
            if not isinstance(s, dict):
                continue
            steps.append(
                PlanStep(
                    id=str(s.get("id", "")).strip() or f"S{len(steps)+1}",
                    action=str(s.get("action", "")).strip(),
                    owner=str(s.get("owner", "")).strip(),
                    depends_on=[str(d) for d in s.get("depends_on", []) if d],
                    gate=str(s.get("gate", "none")),
                    rollback=str(s.get("rollback", "")).strip(),
                    observability=str(s.get("observability", "")).strip(),
                    raw=s,
                )
            )
    open_qs = [str(q) for q in raw.get("open_questions", []) if q]
    conflicts = [c for c in raw.get("conflicts", []) if isinstance(c, dict)]
    return summary, steps, open_qs, conflicts


def run(intent_path: Path, *, out_path: Path) -> Path:
    cfg = load_config()
    print(f"[config] model={cfg.model}", file=sys.stderr)
    verify_model(cfg)

    intent_text = intent_path.read_text()
    print(f"[intent] {intent_path} ({len(intent_text)} chars)", file=sys.stderr)

    agents = [Agent(p, cfg) for p in STAKEHOLDER_PERSONAS]
    print(f"[constraints] running {len(agents)} stakeholders in parallel",
          file=sys.stderr)
    responses = parallel_run(agents, _intent_prompt(intent_text))

    all_constraints: list[Constraint] = []
    raw_responses: dict[str, str] = {}
    for r in responses:
        raw_responses[r.agent_name] = r.content
        parsed = extract_json(r.content)
        cs = _parse_constraints(parsed, owner=r.agent_name)
        print(f"[constraints]   {r.agent_name}: {len(cs)} constraints",
              file=sys.stderr)
        all_constraints.extend(cs)

    if not all_constraints:
        print("[warn] no constraints extracted; sequencer will receive empty list",
              file=sys.stderr)

    sequencer = Agent(SEQUENCER_PERSONA, cfg)
    seq_prompt = (
        "# Migration intent\n\n"
        f"{intent_text.strip()}\n\n"
        "# Stakeholder constraints (merged from all personas)\n\n"
        f"```json\n{json.dumps([c.raw for c in all_constraints], indent=2)}\n```\n\n"
        "Produce the partial-order plan as a JSON object per your schema."
    )
    print("[sequencer] composing plan", file=sys.stderr)
    seq_resp = sequencer.respond(seq_prompt)
    plan_raw = extract_json(seq_resp.content)
    summary, steps, open_qs, conflicts = _parse_plan(plan_raw)
    print(f"[sequencer] plan: {len(steps)} steps, {len(conflicts)} conflicts, "
          f"{len(open_qs)} open questions", file=sys.stderr)

    # Build markdown report.
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report = Report(
        title=f"Rollout Rehearsal — {intent_path.stem}",
        meta={
            "Intent": str(intent_path),
            "Stakeholders": str(len(STAKEHOLDER_PERSONAS)),
            "Constraints": str(len(all_constraints)),
            "Steps": str(len(steps)),
            "Model": cfg.model,
        },
    )
    report.add("Summary", summary or "_(sequencer did not emit a summary)_")
    report.add("Stakeholder constraints", _render_constraint_table(all_constraints))
    report.add("Rollout plan", _render_plan_table(steps))
    report.add("Mermaid graph", _render_mermaid(steps))
    if conflicts:
        body = "\n".join(
            f"- between **{', '.join(c.get('between', []))}**: {c.get('issue', '')}"
            for c in conflicts
        )
        report.add("Conflicts (resolved by sequencer)", body)
    if open_qs:
        report.add("Open questions for the human", "\n".join(f"- {q}" for q in open_qs))

    written = report.write(out_path)

    # Sidecar JSON.
    json_path = out_path.with_suffix(".json")
    json_path.write_text(
        json.dumps(
            {
                "intent_path": str(intent_path),
                "constraints": [c.raw for c in all_constraints],
                "plan": plan_raw if plan_raw is not None else {},
            },
            indent=2,
        )
    )
    print(f"[done] wrote {written} and {json_path}", file=sys.stderr)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rehearse a multi-stakeholder rollout plan."
    )
    parser.add_argument("intent", type=Path, help="Markdown file describing the proposed change")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.out is None:
        args.out = Path("rollout-rehearsal/reports") / f"{args.intent.stem}.md"

    run(args.intent, out_path=args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

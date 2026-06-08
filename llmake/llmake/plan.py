"""
Planning — expand a workflow's targets into concrete build steps.

A target is the *authored* unit. A **step** is the *executed* unit. They differ
only for ``foreach`` targets, which fan out into one step per matched file:

    paper_summary:
      foreach: inputs/papers/*.md      # ── expands to ──►
      prompt: summarize_paper          #   paper_summary[a.md]
                                       #   paper_summary[b.md]  ...

Downstream targets fan back in: a target that ``needs: [paper_summary]`` depends
on *all* of paper_summary's steps and, in its prompt, ``{{needs:paper_summary}}``
resolves to all their artifacts concatenated.

This module is pure (no I/O beyond globbing the workspace) so the expansion is
easy to reason about and test. The runner consumes the resulting steps; the DAG,
cache, and providers never need to know that fan-out happened.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .spec import SpecError, Target, Workflow


@dataclass
class Step:
    """One concrete, buildable unit."""

    name: str                       # unique id, e.g. "paper_summary[smith.md]"
    group: str                      # authored target name it belongs to
    target: Target                  # the authored target (for provider/model/...)
    deps: list = field(default_factory=list)        # concrete step names (scheduling)
    need_groups: list = field(default_factory=list)  # authored need names (for render)
    item_name: str | None = None    # foreach: the matched file's name
    item_path: str | None = None    # foreach: workspace-relative path of the match


def expand(wf: Workflow) -> tuple[dict, dict]:
    """Expand authored targets into steps.

    Returns ``(steps, groups)`` where ``steps`` maps step-name -> Step and
    ``groups`` maps authored-target-name -> list of its step names.
    """
    steps: dict[str, Step] = {}
    groups: dict[str, list] = {}

    # First pass: create steps and the group membership map.
    for tname, target in wf.targets.items():
        if target.foreach:
            matches = [p for p in sorted(wf.root.glob(target.foreach)) if p.is_file()]
            if not matches:
                raise SpecError(
                    f"target {tname!r} foreach pattern {target.foreach!r} "
                    f"matched no files"
                )
            members = []
            for path in matches:
                rel = path.relative_to(wf.root).as_posix()
                sname = f"{tname}[{path.name}]"
                steps[sname] = Step(
                    name=sname, group=tname, target=target,
                    item_name=path.name, item_path=rel,
                )
                members.append(sname)
            groups[tname] = members
        else:
            steps[tname] = Step(name=tname, group=tname, target=target)
            groups[tname] = [tname]

    # Second pass: resolve dependencies through the group map.
    for step in steps.values():
        step.need_groups = list(step.target.needs)
        deps: list = []
        for g in step.target.needs:
            deps.extend(groups[g])      # validated to exist by spec._validate
        step.deps = deps

    return steps, groups


def resolve_goals(goals: list | None, groups: dict) -> list | None:
    """Translate user-requested goal names (which may be authored target names)
    into concrete step names."""
    if goals is None:
        return None
    resolved: list = []
    for g in goals:
        if g in groups:
            resolved.extend(groups[g])
        else:
            resolved.append(g)          # already a concrete step name
    return resolved

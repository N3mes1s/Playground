"""
Dependency graph — turn a workflow's targets into a buildable DAG.

Pure, dependency-free graph utilities: topological ordering, cycle detection,
and computing the set of targets reachable from a requested goal. This keeps
the "what order do I build things in" logic isolated and unit-testable.
"""

from __future__ import annotations


class CycleError(ValueError):
    """Raised when the target graph contains a dependency cycle."""


def topo_order(deps: dict[str, list]) -> list:
    """Return target names in dependency order (dependencies first).

    ``deps`` maps each target to the list of targets it needs.
    """
    visited: dict[str, int] = {}  # 0 = visiting, 1 = done
    order: list = []

    def visit(node: str, stack: list) -> None:
        state = visited.get(node)
        if state == 1:
            return
        if state == 0:
            cycle = " -> ".join(stack + [node])
            raise CycleError(f"dependency cycle detected: {cycle}")
        visited[node] = 0
        for dep in deps.get(node, []):
            visit(dep, stack + [node])
        visited[node] = 1
        order.append(node)

    for node in deps:
        visit(node, [])
    return order


def reachable(deps: dict[str, list], goals: list) -> set:
    """All targets that must be built to satisfy ``goals`` (incl. the goals)."""
    seen: set = set()
    stack = list(goals)
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(deps.get(node, []))
    return seen


def build_plan(deps: dict[str, list], goals: list | None = None) -> list:
    """Topologically-ordered list of targets to build for ``goals``.

    If ``goals`` is ``None``, plan the whole graph.
    """
    order = topo_order(deps)
    if goals is None:
        return order
    needed = reachable(deps, goals)
    return [n for n in order if n in needed]

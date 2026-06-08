"""
Tests for llmake core: graph ordering, rendering, and incremental builds.

Runs fully offline with the `echo` provider — no API keys, no network.
Run with:  python -m pytest tests/   (or: python tests/test_llmake.py)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llmake.graph import CycleError, build_plan, topo_order  # noqa: E402
from llmake.render import render  # noqa: E402
from llmake.runner import build  # noqa: E402
from llmake.spec import load_workflow  # noqa: E402

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "research-notes"


def test_topo_order_respects_deps():
    deps = {"a": [], "b": ["a"], "c": ["a", "b"]}
    order = topo_order(deps)
    assert order.index("a") < order.index("b") < order.index("c")


def test_topo_order_detects_cycle():
    deps = {"a": ["b"], "b": ["a"]}
    try:
        topo_order(deps)
    except CycleError:
        pass
    else:
        raise AssertionError("expected CycleError")


def test_build_plan_subgraph():
    deps = {"a": [], "b": ["a"], "c": []}
    plan = build_plan(deps, ["b"])
    assert plan == ["a", "b"]
    assert "c" not in plan


def test_render_placeholders_and_autoappend():
    out = render("Q: {{needs:summary}}",
                 inputs={}, context={}, needs={"summary": "S"})
    assert "Q: S" in out

    # No placeholder referencing inputs -> they get auto-appended.
    out2 = render("Just a prompt.",
                  inputs={"a.md": "hello"}, context={}, needs={})
    assert "hello" in out2


def test_incremental_build(tmp_path):
    # Copy the example into a temp workspace so we can mutate inputs.
    import shutil
    ws = tmp_path / "ws"
    shutil.copytree(EXAMPLE, ws)
    wf = load_workflow(ws)

    # First build: everything is built.
    r1 = build(wf, log=lambda *_: None)
    assert {s.target for s in r1} == {"summary", "critique", "report"}
    assert all(s.status == "built" for s in r1)

    # Second build with no changes: everything is cached.
    wf2 = load_workflow(ws)
    r2 = build(wf2, log=lambda *_: None)
    assert all(s.status == "cached" for s in r2)

    # Change one input -> summary + its descendants rebuild; nothing else.
    (ws / "inputs" / "notes.md").write_text("# changed\n\nnew content")
    wf3 = load_workflow(ws)
    r3 = {s.target: s.status for s in build(wf3, log=lambda *_: None)}
    assert r3["summary"] == "built"
    assert r3["critique"] == "built"   # depends on summary
    assert r3["report"] == "built"     # depends on both


def test_force_rebuild(tmp_path):
    import shutil
    ws = tmp_path / "ws2"
    shutil.copytree(EXAMPLE, ws)
    build(load_workflow(ws), log=lambda *_: None)
    forced = build(load_workflow(ws), force=True, log=lambda *_: None)
    assert all(s.status == "built" for s in forced)


if __name__ == "__main__":
    import tempfile

    test_topo_order_respects_deps()
    test_topo_order_detects_cycle()
    test_build_plan_subgraph()
    test_render_placeholders_and_autoappend()
    with tempfile.TemporaryDirectory() as d:
        test_incremental_build(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_force_rebuild(Path(d))
    print("all tests passed")

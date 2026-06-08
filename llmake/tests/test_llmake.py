"""
Tests for llmake.

* Build mechanics (graph, render, incremental cache, parallel, retry) run
  offline via the deterministic `echo` provider — no API keys, no network.
* The DSPy provider is exercised with DSPy's `DummyLM`, so the real provider
  code path is covered without calling a model.

Run with:  python -m pytest tests/   (or: python tests/test_llmake.py)
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llmake.graph import CycleError, build_plan, topo_order  # noqa: E402
from llmake.providers import get_provider, register  # noqa: E402
from llmake.providers.base import InferenceRequest, InferenceResult, Provider  # noqa: E402
from llmake.render import render  # noqa: E402
from llmake.runner import BuildError, build  # noqa: E402
from llmake.spec import load_workflow  # noqa: E402

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "research-notes"


# --------------------------------------------------------------------------- #
# graph + render
# --------------------------------------------------------------------------- #
def test_topo_order_respects_deps():
    deps = {"a": [], "b": ["a"], "c": ["a", "b"]}
    order = topo_order(deps)
    assert order.index("a") < order.index("b") < order.index("c")


def test_topo_order_detects_cycle():
    try:
        topo_order({"a": ["b"], "b": ["a"]})
    except CycleError:
        pass
    else:
        raise AssertionError("expected CycleError")


def test_build_plan_subgraph():
    plan = build_plan({"a": [], "b": ["a"], "c": []}, ["b"])
    assert plan == ["a", "b"]
    assert "c" not in plan


def test_render_placeholders_and_autoappend():
    out = render("Q: {{needs:summary}}", inputs={}, context={}, needs={"summary": "S"})
    assert "Q: S" in out
    out2 = render("Just a prompt.", inputs={"a.md": "hello"}, context={}, needs={})
    assert "hello" in out2


# --------------------------------------------------------------------------- #
# build engine (offline via echo)
# --------------------------------------------------------------------------- #
def _workspace(tmp_path, name="ws"):
    ws = tmp_path / name
    shutil.copytree(EXAMPLE, ws)
    return ws


def test_incremental_build(tmp_path):
    ws = _workspace(tmp_path)

    r1 = build(load_workflow(ws), provider_override="echo", log=lambda *_: None)
    assert {s.target for s in r1} == {"summary", "critique", "report"}
    assert all(s.status == "built" for s in r1)

    r2 = build(load_workflow(ws), provider_override="echo", log=lambda *_: None)
    assert all(s.status == "cached" for s in r2)

    (ws / "inputs" / "notes.md").write_text("# changed\n\nnew content")
    r3 = {s.target: s.status for s in
          build(load_workflow(ws), provider_override="echo", log=lambda *_: None)}
    assert r3["summary"] == "built"
    assert r3["critique"] == "built"   # depends on summary
    assert r3["report"] == "built"     # depends on both


def test_force_rebuild(tmp_path):
    ws = _workspace(tmp_path, "ws2")
    build(load_workflow(ws), provider_override="echo", log=lambda *_: None)
    forced = build(load_workflow(ws), provider_override="echo",
                   force=True, log=lambda *_: None)
    assert all(s.status == "built" for s in forced)


def test_parallel_matches_sequential(tmp_path):
    seq_ws = _workspace(tmp_path, "seq")
    par_ws = _workspace(tmp_path, "par")
    seq = build(load_workflow(seq_ws), provider_override="echo",
                jobs=1, log=lambda *_: None)
    par = build(load_workflow(par_ws), provider_override="echo",
                jobs=4, log=lambda *_: None)
    assert [s.target for s in seq] == [s.target for s in par]   # plan order preserved
    for s, p in zip(seq, par):
        assert s.status == p.status == "built"
        assert (seq_ws / "build" / f"{s.target}.md").read_text() == \
               (par_ws / "build" / f"{p.target}.md").read_text()


# --------------------------------------------------------------------------- #
# retry / backoff
# --------------------------------------------------------------------------- #
class _FlakyProvider(Provider):
    name = "flaky"
    _fails_remaining = 2

    def run(self, request):
        if _FlakyProvider._fails_remaining > 0:
            _FlakyProvider._fails_remaining -= 1
            raise RuntimeError("transient boom")
        return InferenceResult(text="recovered", provider=self.name)


def test_retry_recovers(tmp_path):
    register(_FlakyProvider)
    ws = _workspace(tmp_path, "flaky")
    # one target, flaky provider, no backoff delay
    (ws / "llmake.yaml").write_text(
        "version: 1\nproject: f\n"
        "defaults: {provider: flaky, model: x, params: {retries: 3, retry_backoff: 0}}\n"
        "inputs: [inputs/*.md]\n"
        "targets:\n  only: {prompt: 'do it'}\n"
    )
    _FlakyProvider._fails_remaining = 2
    res = build(load_workflow(ws), log=lambda *_: None)
    assert res[0].status == "built"
    assert (ws / "build" / "only.md").read_text() == "recovered"


def test_retry_exhausted(tmp_path):
    register(_FlakyProvider)
    ws = _workspace(tmp_path, "flaky2")
    (ws / "llmake.yaml").write_text(
        "version: 1\nproject: f\n"
        "defaults: {provider: flaky, model: x, params: {retries: 2, retry_backoff: 0}}\n"
        "inputs: [inputs/*.md]\n"
        "targets:\n  only: {prompt: 'do it'}\n"
    )
    _FlakyProvider._fails_remaining = 99
    try:
        build(load_workflow(ws), log=lambda *_: None)
    except BuildError:
        pass
    else:
        raise AssertionError("expected BuildError after retries exhausted")


# --------------------------------------------------------------------------- #
# DSPy provider (offline via DummyLM)
# --------------------------------------------------------------------------- #
def test_dspy_provider_predict():
    import dspy
    from dspy.utils.dummies import DummyLM

    with patch.object(dspy, "LM",
                      lambda *a, **k: DummyLM([{"response": "ANSWER"}])):
        provider = get_provider("dspy")
        res = provider.run(InferenceRequest(
            target="t", prompt="hello", model="openai/gpt-4o-mini",
            params={"module": "predict"},
        ))
    assert res.text == "ANSWER"
    assert res.provider == "dspy"
    assert res.meta["module"] == "predict"
    assert res.meta["llm_calls"] >= 1


def test_dspy_provider_cot():
    import dspy
    from dspy.utils.dummies import DummyLM

    with patch.object(dspy, "LM", lambda *a, **k: DummyLM(
            [{"reasoning": "because", "response": "COT_ANSWER"}])):
        res = get_provider("dspy").run(InferenceRequest(
            target="t", prompt="hello", model="openai/gpt-4o-mini",
            params={"module": "cot"},
        ))
    assert res.text == "COT_ANSWER"
    assert res.meta["module"] == "cot"


if __name__ == "__main__":
    import tempfile

    simple = [
        test_topo_order_respects_deps, test_topo_order_detects_cycle,
        test_build_plan_subgraph, test_render_placeholders_and_autoappend,
        test_dspy_provider_predict, test_dspy_provider_cot,
    ]
    needs_tmp = [
        test_incremental_build, test_force_rebuild,
        test_parallel_matches_sequential, test_retry_recovers,
        test_retry_exhausted,
    ]
    for fn in simple:
        fn()
    for fn in needs_tmp:
        with tempfile.TemporaryDirectory() as d:
            fn(Path(d))
    print("all tests passed")

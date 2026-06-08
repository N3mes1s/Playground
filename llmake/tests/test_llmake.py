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
from llmake.plan import expand, resolve_goals  # noqa: E402
from llmake.providers import get_provider, register  # noqa: E402
from llmake.providers.base import InferenceRequest, InferenceResult, Provider  # noqa: E402
from llmake.render import render  # noqa: E402
from llmake.runner import BuildError, build  # noqa: E402
from llmake.spec import load_workflow  # noqa: E402

EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"
EXAMPLE = EXAMPLES_DIR / "research-notes"
SYNTH = EXAMPLES_DIR / "research-synthesis"


def _all_examples():
    return sorted(p.parent for p in EXAMPLES_DIR.glob("*/llmake.yaml"))


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
# the shipped examples actually work (auto-discovered, so they can't rot)
# --------------------------------------------------------------------------- #
def test_examples_exist():
    names = {p.name for p in _all_examples()}
    assert {"research-notes", "research-synthesis", "kb-compile"} <= names


def test_every_example_builds_emits_artifacts_and_caches(tmp_path):
    for ex in _all_examples():
        ws = tmp_path / ex.name
        shutil.copytree(ex, ws)

        wf = load_workflow(ws)
        steps, _ = expand(wf)

        res = build(wf, provider_override="echo", log=lambda *_: None)
        built = {r.target for r in res}

        # every expanded step is built, exactly once, with an artifact on disk
        assert built == set(steps), f"{ex.name}: built {built} != steps {set(steps)}"
        for r in res:
            assert r.status == "built", f"{ex.name}: {r.target} not built"
            assert r.artifact.is_file(), f"{ex.name}: missing artifact {r.artifact}"
            # echo writes the step name as the artifact's H1 header
            assert r.artifact.read_text().lstrip().startswith("#"), \
                f"{ex.name}: {r.target} artifact looks empty"

        # a second build is a full cache hit (incrementality holds)
        res2 = build(load_workflow(ws), provider_override="echo", log=lambda *_: None)
        assert all(r.status == "cached" for r in res2), \
            f"{ex.name}: not all cached on rebuild: {[(r.target, r.status) for r in res2]}"


def test_every_example_fanin_includes_all_upstream_artifacts(tmp_path):
    """For every example, a step that consumes an upstream group must actually
    receive every member's artifact in its rendered prompt."""
    from llmake.runner import _artifact_path, _materialize

    checked = 0
    for ex in _all_examples():
        ws = tmp_path / ex.name
        shutil.copytree(ex, ws)
        wf = load_workflow(ws)
        steps, groups = expand(wf)
        build(wf, provider_override="echo", log=lambda *_: None)

        for step in steps.values():
            if not step.need_groups:
                continue
            # reconstruct upstream artifact text exactly like the runner does
            artifacts = {
                m: _artifact_path(wf, steps[m]).read_text() for m in
                {m for g in step.need_groups for m in groups[g]}
            }
            needs_text = {
                g: "\n\n".join(
                    f"### {steps[m].item_name or m}\n\n{artifacts[m]}"
                    for m in groups[g]
                )
                for g in step.need_groups
            }
            prompt, _ = _materialize(wf, step, needs_text)
            for g in step.need_groups:
                for m in groups[g]:
                    assert artifacts[m] in prompt, \
                        f"{ex.name}: {step.name} prompt missing upstream {m}"
                    checked += 1
    assert checked > 0, "no fan-in edges were exercised"


# --------------------------------------------------------------------------- #
# default provider/model resolution (manifest -> env -> built-in)
# --------------------------------------------------------------------------- #
def test_defaults_resolve_from_env(tmp_path):
    import os
    ws = tmp_path / "envws"
    ws.mkdir()
    (ws / "inputs").mkdir()
    (ws / "inputs" / "a.md").write_text("hi")
    saved = {k: os.environ.get(k) for k in ("LLMAKE_MODEL", "LLMAKE_PROVIDER")}
    try:
        # manifest sets no defaults.model/provider -> should fall back to env
        (ws / "llmake.yaml").write_text(
            "version: 1\nproject: e\ninputs: [inputs/*.md]\n"
            "targets:\n  t: {prompt: 'do it'}\n"
        )
        os.environ["LLMAKE_MODEL"] = "fireworks_ai/accounts/fireworks/models/kimi-k2p6"
        os.environ["LLMAKE_PROVIDER"] = "echo"
        wf = load_workflow(ws)
        assert wf.defaults.model == "fireworks_ai/accounts/fireworks/models/kimi-k2p6"
        assert wf.defaults.provider == "echo"

        # manifest value wins over env
        (ws / "llmake.yaml").write_text(
            "version: 1\nproject: e\ninputs: [inputs/*.md]\n"
            "defaults: {model: openai/gpt-4o-mini}\n"
            "targets:\n  t: {prompt: 'do it'}\n"
        )
        assert load_workflow(ws).defaults.model == "openai/gpt-4o-mini"
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# --------------------------------------------------------------------------- #
# foreach fan-out / fan-in
# --------------------------------------------------------------------------- #
def test_plan_expand_and_resolve_goals():
    wf = load_workflow(SYNTH)
    steps, groups = expand(wf)
    assert len(groups["extract"]) == 3                      # 3 source files
    assert set(steps["synthesis"].deps) == set(groups["extract"])  # fan-in
    assert resolve_goals(["extract"], groups) == groups["extract"]
    assert resolve_goals(["synthesis"], groups) == ["synthesis"]


def test_foreach_fanout(tmp_path):
    ws = tmp_path / "synth"
    shutil.copytree(SYNTH, ws)
    res = {s.target: s.status for s in
           build(load_workflow(ws), provider_override="echo", log=lambda *_: None)}
    extracts = [k for k in res if k.startswith("extract[")]
    assert len(extracts) == 3
    assert all(res[e] == "built" for e in extracts)
    assert res["synthesis"] == "built" and res["gaps"] == "built"
    # one artifact file per source, under build/extract/
    assert (ws / "build" / "extract" / "nondeterminism.md").is_file()


def test_foreach_selective_recompute(tmp_path):
    ws = tmp_path / "synth2"
    shutil.copytree(SYNTH, ws)
    build(load_workflow(ws), provider_override="echo", log=lambda *_: None)
    # edit ONE source
    (ws / "sources" / "nondeterminism.md").write_text("# changed\n\nnew claim")
    res = {s.target: s.status for s in
           build(load_workflow(ws), provider_override="echo", log=lambda *_: None)}
    assert res["extract[nondeterminism.md]"] == "built"     # changed -> rebuilt
    assert res["extract[caching-economics.md]"] == "cached"  # untouched -> cached
    assert res["extract[tooling-gap.md]"] == "cached"
    assert res["synthesis"] == "built"                      # fan-in dep changed
    assert res["gaps"] == "built"


def test_foreach_basename_collision_raises(tmp_path):
    from llmake.spec import SpecError
    ws = tmp_path / "collide"
    (ws / "a").mkdir(parents=True)
    (ws / "b").mkdir(parents=True)
    (ws / "a" / "dup.md").write_text("one")
    (ws / "b" / "dup.md").write_text("two")
    (ws / "llmake.yaml").write_text(
        "version: 1\nproject: c\n"
        "targets:\n  t: {foreach: '*/dup.md', prompt: 'x'}\n"
    )
    try:
        expand(load_workflow(ws))
    except SpecError as e:
        assert "basename" in str(e)
    else:
        raise AssertionError("expected SpecError on basename collision")


def test_corrupt_cache_does_not_crash(tmp_path):
    from llmake.cache import Cache, Entry
    p = tmp_path / "cache.json"
    p.write_text("{ this is not valid json")
    c = Cache(p)                 # must not raise
    assert c.entries == {}
    c.put("t", Entry(key="k", artifact="a.md"))
    c.save()                     # atomic save round-trips
    assert "t" in Cache(p).entries


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
        test_plan_expand_and_resolve_goals, test_examples_exist,
        test_dspy_provider_predict, test_dspy_provider_cot,
    ]
    needs_tmp = [
        test_defaults_resolve_from_env,
        test_incremental_build, test_force_rebuild,
        test_parallel_matches_sequential,
        test_every_example_builds_emits_artifacts_and_caches,
        test_every_example_fanin_includes_all_upstream_artifacts,
        test_foreach_fanout, test_foreach_selective_recompute,
        test_foreach_basename_collision_raises, test_corrupt_cache_does_not_crash,
        test_retry_recovers, test_retry_exhausted,
    ]
    for fn in simple:
        fn()
    for fn in needs_tmp:
        with tempfile.TemporaryDirectory() as d:
            fn(Path(d))
    print("all tests passed")

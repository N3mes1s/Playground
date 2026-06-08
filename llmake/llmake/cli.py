#!/usr/bin/env python3
"""
llmake CLI — drive the LLM build system.

Commands:
    build [targets...]   compile targets (incremental; whole graph if omitted)
    status [targets...]  show which targets are fresh vs. stale
    graph                print the dependency DAG
    providers            list available inference backends and their status
    snapshot -m MSG      git-commit + tag the current build artifacts
    snapshots            list snapshots
    export -o OUT.html   bundle artifacts into one shareable HTML file
    clean                remove build artifacts and the cache

Global:
    -C DIR / --workflow PATH   locate the llmake.yaml (default: ./llmake.yaml)

Usage:
    python -m llmake.cli build
    python -m llmake.cli build report --force
    python -m llmake.cli build --provider anthropic
    python -m llmake.cli export -o site/build.html
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys

from . import export as export_mod
from . import snapshot as snap_mod
from .graph import build_plan
from .providers import get_provider, list_providers
from .runner import BuildError, build
from .spec import SpecError, load_workflow


def _load(args) -> "object":
    path = args.workflow or args.directory or "."
    return load_workflow(path)


def cmd_build(args) -> int:
    wf = _load(args)
    goals = args.targets or None
    print(f"Building {wf.project} ({'all targets' if not goals else ', '.join(goals)})")
    try:
        results = build(
            wf, goals,
            force=args.force,
            provider_override=args.provider,
            model_override=args.model,
            jobs=args.jobs,
        )
    except BuildError as e:
        print(f"\nBuild failed: {e}", file=sys.stderr)
        return 1
    built = sum(1 for r in results if r.status == "built")
    cached = sum(1 for r in results if r.status == "cached")

    # Aggregate token/cost provenance from freshly built targets.
    tokens_in = sum(r.meta.get("input_tokens", 0) for r in results)
    tokens_out = sum(r.meta.get("output_tokens", 0) for r in results)
    cost = sum(r.meta.get("cost_usd", 0.0) for r in results)

    print(f"\nDone: {built} built, {cached} cached -> {wf.build_dir}")
    if tokens_in or tokens_out:
        line = f"Tokens: {tokens_in:,} in / {tokens_out:,} out"
        if cost:
            line += f"  |  Cost: ${cost:.4f}"
        print(line)
    return 0


def cmd_status(args) -> int:
    wf = _load(args)
    goals = args.targets or None
    print(f"{wf.project}: build status\n")
    results = build(wf, goals, dry_run=True, log=lambda *_: None)
    for r in results:
        mark = "OK" if r.status == "cached" else "STALE"
        print(f"  [{mark:>5}] {r.target:<20} {r.provider}")
    stale = sum(1 for r in results if r.status != "cached")
    print(f"\n{stale} of {len(results)} target(s) need building.")
    return 0


def cmd_graph(args) -> int:
    from .plan import expand
    wf = _load(args)
    _, groups = expand(wf)                       # validates foreach globs
    deps = {n: t.needs for n, t in wf.targets.items()}
    order = build_plan(deps)
    print(f"{wf.project}: dependency order\n")
    for n in order:
        t = wf.targets[n]
        arrow = f"  <- {', '.join(t.needs)}" if t.needs else ""
        fan = f"  (foreach {t.foreach} -> {len(groups[n])} steps)" if t.foreach else ""
        print(f"  {n}{arrow}{fan}")
    return 0


def cmd_providers(args) -> int:
    print("Inference providers:\n")
    for name in list_providers():
        p = get_provider(name)
        ok, reason = p.available()
        state = "available" if ok else f"unavailable ({reason})"
        kinds = ", ".join(p.kinds)
        print(f"  {name:<14} [{kinds:<11}] {state}")
    return 0


def cmd_snapshot(args) -> int:
    wf = _load(args)
    paths = args.paths or None
    snap = snap_mod.snapshot(wf.root, args.message, paths)
    print(f"Snapshot {snap.ref} created: {snap.message}")
    return 0


def cmd_snapshots(args) -> int:
    wf = _load(args)
    snaps = snap_mod.list_snapshots(wf.root)
    if not snaps:
        print("No snapshots yet. Create one with: llmake snapshot -m 'message'")
        return 0
    print(f"{wf.project}: snapshots\n")
    for s in snaps:
        print(f"  {s.ref}  {s.when}  {s.message}")
    return 0


def cmd_export(args) -> int:
    wf = _load(args)
    out = export_mod.export_html(wf, args.output)
    print(f"Exported shareable bundle -> {out}")
    return 0


def cmd_clean(args) -> int:
    wf = _load(args)
    if wf.build_dir.is_dir():
        shutil.rmtree(wf.build_dir)
        print(f"Removed {wf.build_dir}")
    cache = wf.cache_path
    if cache.is_file():
        cache.unlink()
        print(f"Removed {cache}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="llmake",
        description="A build system for LLM inference workflows "
                    "(GNU Autotools x Notion).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-C", "--directory", help="workspace dir containing llmake.yaml")
    p.add_argument("--workflow", help="explicit path to an llmake.yaml manifest")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="increase log verbosity (-v info, -vv debug)")

    sub = p.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="compile targets (incremental)")
    b.add_argument("targets", nargs="*", help="targets to build (default: all)")
    b.add_argument("--force", action="store_true", help="ignore cache, rebuild")
    b.add_argument("--provider", help="override the provider for all targets")
    b.add_argument("-m", "--model", help="override the model for all targets")
    b.add_argument("-j", "--jobs", type=int, default=1,
                   help="compile independent targets concurrently (default: 1)")
    b.set_defaults(func=cmd_build)

    s = sub.add_parser("status", help="show fresh vs. stale targets")
    s.add_argument("targets", nargs="*")
    s.set_defaults(func=cmd_status)

    g = sub.add_parser("graph", help="print the dependency DAG")
    g.set_defaults(func=cmd_graph)

    pr = sub.add_parser("providers", help="list inference backends")
    pr.set_defaults(func=cmd_providers)

    sn = sub.add_parser("snapshot", help="git-commit+tag the build artifacts")
    sn.add_argument("-m", "--message", required=True)
    sn.add_argument("paths", nargs="*", help="paths to snapshot (default: build/)")
    sn.set_defaults(func=cmd_snapshot)

    sl = sub.add_parser("snapshots", help="list snapshots")
    sl.set_defaults(func=cmd_snapshots)

    e = sub.add_parser("export", help="bundle artifacts into shareable HTML")
    e.add_argument("-o", "--output", default="build/export.html")
    e.set_defaults(func=cmd_export)

    c = sub.add_parser("clean", help="remove build artifacts and cache")
    c.set_defaults(func=cmd_clean)

    return p


def main(argv: list | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    level = {0: logging.WARNING, 1: logging.INFO}.get(args.verbose, logging.DEBUG)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    try:
        return args.func(args)
    except (SpecError, RuntimeError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

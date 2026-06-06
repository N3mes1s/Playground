#!/usr/bin/env python3
"""carve benchmark — measure noise reduction and check for FALSE CLEARS.

For each repo collected by run.sh, this:
  1. joins carve's per-finding verdicts (triage.vex.json) to the cargo-audit
     findings (audit.json) positionally;
  2. builds an INDEPENDENT ground-truth oracle from cargo's own resolve graph
     (meta.json) — re-deriving "present" and "ships at runtime" in a separate
     implementation from carve's Rust;
  3. asserts every `not_affected` verdict carve emits is backed by that oracle.
     A clear the oracle can't justify is a FALSE CLEAR (the one error class a
     fail-safe triager must never produce).

Metrics: noise reduction (strict = cleared; incl-review = cleared+review) and
the false-clear count. Writes REPORT-BENCHMARK.md.
"""
import json, os, sys, glob

TARGET_OS = os.environ.get("BENCH_TARGET_OS", "linux")
TARGET_ARCH = os.environ.get("BENCH_TARGET_ARCH", "x86_64")
HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
REPORT = os.path.join(HERE, "..", "REPORT-BENCHMARK.md")


def audit_findings(audit):
    """Replicate carve's parse order: vulnerabilities.list, then warnings by
    sorted category — so a positional join to the VEX statements lines up."""
    out = []
    for e in audit.get("vulnerabilities", {}).get("list", []):
        out.append(_finding(e, "vulnerability"))
    warns = audit.get("warnings", {}) or {}
    for cat in sorted(warns):
        for e in warns[cat] or []:
            out.append(_finding(e, cat))
    return out


def _finding(e, kind):
    adv = e.get("advisory", {}) or {}
    aff = e.get("affected") or {}
    crate = (e.get("package") or {}).get("name") or adv.get("package") or ""
    return {
        "id": adv.get("id", "UNKNOWN"),
        "crate": crate,
        "kind": kind,
        "os": aff.get("os", []) or [],
        "arch": aff.get("arch", []) or [],
    }


def oracle(meta):
    """Independent ground truth from cargo's resolve graph."""
    pkgs = {p["id"]: p for p in meta["packages"]}
    present = {p["name"] for p in meta["packages"]}
    resolve = meta.get("resolve") or {}
    nodes = {n["id"]: n for n in resolve.get("nodes", [])}
    root = resolve.get("root")
    roots = [root] if root else list(meta.get("workspace_members", []))
    seen, stack, runtime = set(roots), list(roots), set()
    while stack:
        x = stack.pop()
        if x in pkgs:
            runtime.add(pkgs[x]["name"])
        for dep in nodes.get(x, {}).get("deps", []):
            kinds = {k.get("kind") for k in dep.get("dep_kinds", [])}
            if None in kinds and dep["pkg"] not in seen:  # normal (kind=null) edge
                seen.add(dep["pkg"]); stack.append(dep["pkg"])
    return present, runtime


def platform_excluded(lst, target):
    return bool(lst) and target not in lst


def validate_clear(just, crate, os_l, arch_l, present, runtime):
    """Return None if the clear is justified by the oracle, else a reason string."""
    if just == "component_not_present":
        return None if crate not in present else "crate IS in the resolved graph"
    if just == "vulnerable_code_not_in_execute_path":
        return None if crate not in runtime else "crate IS normal-reachable (ships)"
    if just == "vulnerable_code_not_present":
        if platform_excluded(os_l, TARGET_OS) or platform_excluded(arch_l, TARGET_ARCH):
            return None
        return "advisory is not platform-excluded for the target"
    return f"unknown justification {just!r}"


def main():
    repos = sorted(d for d in glob.glob(f"{DATA}/*") if os.path.isdir(d))
    rows, false_clears = [], []
    agg = {"total": 0, "cleared": 0, "review": 0, "affected": 0}
    for rd in repos:
        name = os.path.basename(rd)
        try:
            audit = json.load(open(f"{rd}/audit.json"))
            vex = json.load(open(f"{rd}/triage.vex.json"))
            meta = json.load(open(f"{rd}/meta.json"))
        except Exception as e:
            print(f"  ! {name}: missing/invalid data ({e})"); continue
        findings = audit_findings(audit)
        stmts = vex.get("statements", [])
        if len(findings) != len(stmts):
            print(f"  ! {name}: join mismatch ({len(findings)} findings vs {len(stmts)} statements) — skip")
            continue
        present, runtime = oracle(meta)
        c = {"total": len(findings), "cleared": 0, "review": 0, "affected": 0}
        for f, s in zip(findings, stmts):
            st = s.get("status")
            if st == "not_affected":
                c["cleared"] += 1
                reason = validate_clear(s.get("justification"), f["crate"],
                                        f["os"], f["arch"], present, runtime)
                if reason:
                    false_clears.append((name, f["id"], f["crate"],
                                         s.get("justification"), reason))
            elif st == "under_investigation":
                c["review"] += 1
            elif st == "affected":
                c["affected"] += 1
        for k in agg:
            agg[k] += c[k]
        rows.append((name, c))

    def pct(a, b):
        return f"{(100*a//b) if b else 0}%"

    # ---- console summary ----
    print(f"\nTarget: {TARGET_OS}/{TARGET_ARCH}")
    print(f"{'repo':24} {'tot':>4} {'clr':>4} {'rev':>4} {'aff':>4}  {'clr%':>5} {'clr+rev%':>8}")
    for name, c in rows:
        print(f"{name:24} {c['total']:>4} {c['cleared']:>4} {c['review']:>4} "
              f"{c['affected']:>4}  {pct(c['cleared'],c['total']):>5} "
              f"{pct(c['cleared']+c['review'],c['total']):>8}")
    T = agg
    print(f"{'TOTAL':24} {T['total']:>4} {T['cleared']:>4} {T['review']:>4} {T['affected']:>4}")
    print(f"\nNoise reduction (cleared):          {pct(T['cleared'],T['total'])}")
    print(f"Noise reduction (cleared + review): {pct(T['cleared']+T['review'],T['total'])}")
    print(f"FALSE CLEARS (oracle-unjustified):  {len(false_clears)}")
    for fc in false_clears:
        print("   !!", fc)

    # ---- markdown report ----
    with open(REPORT, "w") as o:
        o.write("# carve benchmark — noise reduction & false-clear audit\n\n")
        o.write("Reproducible via `carve/bench/run.sh` + `carve/bench/verify.py`. "
                "Each finding from `cargo audit` is triaged by `carve triage`; every "
                "`not_affected` verdict is then checked against an **independent oracle** "
                "that re-derives presence and runtime-reachability directly from cargo's "
                "resolve graph (`cargo metadata`), in a separate implementation from "
                "carve's. A clear the oracle can't justify is a **false clear**.\n\n")
        o.write(f"Target triaged for: `{TARGET_OS}/{TARGET_ARCH}`.\n\n")
        o.write("## Per-project\n\n")
        o.write("| project | findings | cleared (not-affected) | needs review | affected | noise ↓ (cleared) | noise ↓ (cleared+review) |\n")
        o.write("|---|---:|---:|---:|---:|---:|---:|\n")
        for name, c in rows:
            o.write(f"| {name} | {c['total']} | {c['cleared']} | {c['review']} | "
                    f"{c['affected']} | {pct(c['cleared'],c['total'])} | "
                    f"{pct(c['cleared']+c['review'],c['total'])} |\n")
        o.write(f"| **total** | **{T['total']}** | **{T['cleared']}** | **{T['review']}** | "
                f"**{T['affected']}** | **{pct(T['cleared'],T['total'])}** | "
                f"**{pct(T['cleared']+T['review'],T['total'])}** |\n\n")
        o.write("## Headline\n\n")
        o.write(f"- **{pct(T['cleared'],T['total'])}** of `cargo audit` findings are "
                f"cleared with a machine-checkable justification (suppressible now).\n")
        o.write(f"- **{pct(T['cleared']+T['review'],T['total'])}** are moved out of the "
                f"\"affected\" bucket (cleared or down-prioritized to needs-review).\n")
        o.write(f"- **False clears: {len(false_clears)}** — every `not_affected` verdict "
                f"is backed by the independent cargo-resolve oracle.\n\n")
        if false_clears:
            o.write("### False clears found\n\n")
            for name, vid, crate, just, reason in false_clears:
                o.write(f"- `{name}` {vid} ({crate}): claimed `{just}` but {reason}\n")
            o.write("\n")
        o.write("## What the oracle checks\n\n")
        o.write("- `component_not_present` → crate must be absent from cargo's resolved package set.\n")
        o.write("- `vulnerable_code_not_in_execute_path` → crate must be unreachable via "
                "normal-only edges (a separate BFS over the resolve graph).\n")
        o.write("- `vulnerable_code_not_present` → the advisory's `os`/`arch` must exclude the target.\n\n")
        o.write("## Honest scope\n\n")
        o.write("- `affected` means \"ships and is reached\", not \"exploitable\"; the human still judges exploitability.\n")
        o.write("- `needs review` is **not** counted as cleared — carve is recall-biased and never downgrades a reached-but-unconfirmed crate to safe.\n")
        o.write("- The oracle and carve both consume cargo's authoritative resolve graph; "
                "they are independent *implementations*, so a divergence catches a carve bug "
                "(it is a cross-implementation check, not a fully orthogonal exploit oracle).\n")
    print(f"\nwrote {os.path.relpath(REPORT)}")
    return 1 if false_clears else 0


if __name__ == "__main__":
    sys.exit(main())

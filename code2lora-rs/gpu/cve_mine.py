#!/usr/bin/env python3
"""Build a REAL labelled vuln dataset from OSV Python CVE fix-commits.

For each CVE fix commit we take the changed .py functions:
  before-fix (parent)  -> label VULN   (the confirmed-vulnerable code)
  after-fix  (commit)  -> label SAFE   (the fix; often adds the repo's own sanitizer)

We also grab a per-repo CONTEXT blob: other .py files at the fixed commit,
PRIORITIZING the modules the changed file imports (where the custom sanitizer is
usually defined) — excluding the changed file itself (no leakage of the eval
functions). A repo-adapter trains on this context; the test is whether knowing the
repo's own sanitizer lets the scanner clear the (still-scary-looking) fixed code
without missing the real vuln.

Labels are CVE-grounded (the fix commit confirms before=vuln / after=fixed), far
stronger than pattern-mining. Output: gpu/cve_dataset.json.
"""
import ast, json, os, re, shutil, subprocess, sys, tempfile, random, zipfile, urllib.request

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
SINK_KW = re.compile(r"inject|rce|remote code|command|\bsql\b|xss|ssrf|path travers|"
                     r"deseriali|\beval\b|code execution|arbitrary (file|code|command)|"
                     r"traversal|template", re.I)
SKIP_REPOS = {"tensorflow/tensorflow"}  # too large to fetch quickly


def run(*a, **k):
    return subprocess.run(a, capture_output=True, text=True, **k)


def candidates(zip_path, limit_per_repo=3):
    z = zipfile.ZipFile(zip_path)
    crx = re.compile(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})")
    rows = []
    for n in z.namelist():
        try:
            d = json.loads(z.read(n))
        except Exception:
            continue
        summ = (d.get("summary", "") or "") + " " + (d.get("details", "") or "")
        if not SINK_KW.search(summ):
            continue
        refs = " ".join(r.get("url", "") for r in d.get("references", []))
        m = crx.search(refs)
        if not m:
            continue
        repo, sha = m.group(1), m.group(2)
        if repo.endswith(".git"):
            repo = repo[:-4]
        if repo in SKIP_REPOS:
            continue
        cve = next((a for a in d.get("aliases", []) if a.startswith("CVE")), d.get("id"))
        rows.append({"cve": cve, "repo": repo, "sha": sha, "summary": summ[:160].strip()})
    return rows


def funcs(src):
    out = {}
    try:
        tree = ast.parse(src)
    except Exception:
        return out, None
    lines = src.splitlines()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            try:
                out[n.name] = "\n".join(lines[n.lineno - 1:n.end_lineno])
            except Exception:
                pass
    return out, tree


def imported_modules(src):
    mods = set()
    try:
        for n in ast.walk(ast.parse(src)):
            if isinstance(n, ast.ImportFrom) and n.module:
                mods.add(n.module.split(".")[-1])
            elif isinstance(n, ast.Import):
                for a in n.names:
                    mods.add(a.name.split(".")[-1])
    except Exception:
        pass
    return mods


def fetch(repo, sha, dst):
    run("git", "init", "-q", dst)
    r = run("git", "-C", dst, "fetch", "-q", "--depth", "2",
            f"https://github.com/{repo}", sha)
    return r.returncode == 0


def process(cand, ctx_chars=12000):
    repo, sha = cand["repo"], cand["sha"]
    d = tempfile.mkdtemp()
    try:
        if not fetch(repo, sha, d):
            return None
        changed = run("git", "-C", d, "show", "--name-only", "--pretty=format:", sha).stdout.split()
        pys = [f for f in changed if f.endswith(".py") and "test" not in f.lower()]
        if not pys:
            return None
        pairs, want_mods = [], set()
        for f in pys:
            before = run("git", "-C", d, "show", f"{sha}^:{f}").stdout
            after = run("git", "-C", d, "show", f"{sha}:{f}").stdout
            if not before or not after:
                continue
            want_mods |= imported_modules(after)
            fb, _ = funcs(before)
            fa, _ = funcs(after)
            for name in fb:
                if name in fa and fb[name] != fa[name] and 40 < len(fa[name]) < 1600 \
                        and 40 < len(fb[name]) < 1600:
                    pairs.append({"file": f, "func": name,
                                  "vuln": fb[name], "safe": fa[name]})
        if not pairs:
            return None
        # context: other .py files at sha, prioritizing imported modules
        tree = run("git", "-C", d, "ls-tree", "-r", "--name-only", sha).stdout.split()
        changed_set = set(pys)
        allpy = [f for f in tree if f.endswith(".py") and f not in changed_set
                 and "test" not in f.lower()]
        def score(f):
            base = os.path.basename(f)[:-3]
            return (base in want_mods, "util" in f or "secur" in f or "saniti" in f)
        allpy.sort(key=score, reverse=True)
        ctx, used = "", 0
        for f in allpy[:25]:
            t = run("git", "-C", d, "show", f"{sha}:{f}").stdout
            if not t:
                continue
            ctx += f"\n# === {f} ===\n" + t[:4000]
            used += len(t[:4000])
            if used >= ctx_chars:
                break
        return {"repo": repo, "sha": sha, "cve": cand["cve"],
                "summary": cand["summary"], "pairs": pairs, "context": ctx[:ctx_chars]}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_dataset.json")
    zip_path = os.environ.get("OSV_ZIP", "/tmp/probe/pypi_osv.zip")
    if not os.path.exists(zip_path):
        print("downloading OSV ...", flush=True)
        urllib.request.urlretrieve(OSV_URL, zip_path)
    target_repos = int(os.environ.get("CVE_REPOS", "40"))
    cands = candidates(zip_path)
    random.Random(0).shuffle(cands)
    print(f"{len(cands)} sink-relevant CVE candidates", flush=True)
    seen_repos, dataset, n_pairs = {}, [], 0
    for c in cands:
        if seen_repos.get(c["repo"], 0) >= 2:   # cap pairs per repo for diversity
            continue
        try:
            r = process(c)
        except Exception:
            r = None
        if not r:
            continue
        seen_repos[c["repo"]] = seen_repos.get(c["repo"], 0) + 1
        dataset.append(r)
        n_pairs += len(r["pairs"])
        print(f"  [{len(dataset):3d}] {r['repo']:34s} {len(r['pairs'])} pairs  {r['cve']}", flush=True)
        if len(dataset) >= target_repos:
            break
    json.dump(dataset, open(out_path, "w"))
    print(f"\nwrote {out_path}: {len(dataset)} repo-commits, {n_pairs} before/after pairs")


if __name__ == "__main__":
    main()

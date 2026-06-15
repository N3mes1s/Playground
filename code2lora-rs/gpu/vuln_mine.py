#!/usr/bin/env python3
"""Mine REAL sink call sites from real repos and heuristically label them:
  SAFE_WRAPPED : a dangerous sink whose tainted-looking arg is wrapped in a
                 sanitizer/escaper (the false-positive trap for naive scanners)
  VULN_RAW     : a dangerous sink fed a tainted source with NO sanitizer
  (sites that are neither are skipped)

Captures the enclosing function source as real context. Labels are heuristic
(AST pattern), not ground-truth — reported honestly. This probe just measures
YIELD so we know if a real-data experiment is viable.
"""
import ast, os, sys, json, glob

SINKS = {"execute", "executemany", "system", "popen", "call", "run", "Popen",
         "eval", "exec", "render_template_string", "loads", "load"}
SANITIZERS = {"escape", "mark_safe", "sanitize", "clean", "quote", "urlencode",
              "escape_uri_path", "shlex", "quote_plus", "format_html", "bleach",
              "validate", "escape_sql", "parameterize", "conditional_escape"}
TAINT = ("request", "input", "argv", "environ", "getenv", "self.request",
         ".form", ".args", ".GET", ".POST", ".params", ".values", ".data",
         "stdin", "user_input", "untrusted")


def src_of(node, lines):
    try:
        return "\n".join(lines[node.lineno - 1: node.end_lineno])
    except Exception:
        return ""


def has_taint(s):
    return any(t in s for t in TAINT)


def has_sanitizer(node):
    found = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            name = getattr(f, "attr", None) or getattr(f, "id", None)
            if name and any(sz in name.lower() for sz in SANITIZERS):
                found.append(name)
    return found


def enclosing_func(tree, lineno, lines):
    best = None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if n.lineno <= lineno <= (n.end_lineno or n.lineno):
                if best is None or n.lineno > best.lineno:
                    best = n
    return src_of(best, lines) if best else None


def mine_file(path):
    try:
        code = open(path, encoding="utf-8", errors="ignore").read()
        tree = ast.parse(code)
    except Exception:
        return []
    lines = code.splitlines()
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        fname = getattr(n.func, "attr", None) or getattr(n.func, "id", None)
        if fname not in SINKS:
            continue
        if not n.args:
            continue
        arg_src = " ".join(src_of(a, lines) for a in n.args)
        call_src = src_of(n, lines)
        san = has_sanitizer(n)
        taint = has_taint(arg_src)
        label = None
        if taint and san:
            label = "SAFE_WRAPPED"
        elif taint and not san:
            label = "VULN_RAW"
        if label is None:
            continue
        ctx = enclosing_func(tree, n.lineno, lines) or call_src
        if len(ctx) > 1600:
            ctx = ctx[:1600]
        out.append({"sink": fname, "label": label, "call": call_src.strip()[:200],
                    "sanitizers": san, "context": ctx, "file": path})
    return out


def main():
    repos = sys.argv[1:] or ["/tmp/probe/flask", "/tmp/probe/django", "/tmp/probe/requests"]
    grand = {}
    samples = {"SAFE_WRAPPED": [], "VULN_RAW": []}
    for repo in repos:
        cnt = {"SAFE_WRAPPED": 0, "VULN_RAW": 0}
        for f in glob.glob(os.path.join(repo, "**", "*.py"), recursive=True):
            for it in mine_file(f):
                cnt[it["label"]] += 1
                if len(samples[it["label"]]) < 4:
                    samples[it["label"]].append(it)
        grand[os.path.basename(repo)] = cnt
        print(f"{os.path.basename(repo):12s}  SAFE_WRAPPED={cnt['SAFE_WRAPPED']:4d}  VULN_RAW={cnt['VULN_RAW']:4d}")
    print("\n--- sample SAFE_WRAPPED (real false-positive traps) ---")
    for s in samples["SAFE_WRAPPED"][:3]:
        print(f"[{s['sink']} | san={s['sanitizers']}] {s['call']}\n   {s['file']}")
    print("\n--- sample VULN_RAW ---")
    for s in samples["VULN_RAW"][:3]:
        print(f"[{s['sink']}] {s['call']}\n   {s['file']}")


if __name__ == "__main__":
    main()

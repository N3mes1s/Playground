#!/usr/bin/env python3
"""Multi-language assertion-completion miner.

Extends the Python-AST miner to JavaScript/TypeScript, Rust, and Go via robust
balanced-paren argument extraction. Python files are delegated to the AST miner
(`mine_assertions`) for quality; other languages use call-marker matching.

Each task: predict the assertion's target argument given the test code up to it.
Exposes `mine_repo(path)` -> list of {prefix, target, file, kind, lang}.
"""
import os

import mine_assertions

# language -> list of (marker, target_arg_index_from_relevant_args)
# For `expect(x).toBe(y)` the marker call has a single arg -> index -1.
# For `assert.equal(a, b)` / `assert_eq!(a, b)` -> the second arg (index 1).
# For testify `assert.Equal(t, exp, act)` -> index 1 (expected).
MARKERS = {
    "js": [
        (".toBe(", -1), (".toEqual(", -1), (".toStrictEqual(", -1),
        ("assert.strictEqual(", 1), ("assert.equal(", 1),
        ("assert.deepEqual(", 1), ("t.is(", 1), ("t.deepEqual(", 1),
    ],
    "rs": [("assert_eq!(", 1)],
    "go": [("assert.Equal(", 1), ("require.Equal(", 1)],
}
EXT_LANG = {
    ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".mjs": "js",
    ".rs": "rs", ".go": "go",
}


def split_args(s: str):
    """Split top-level comma-separated args of `s` starting right after an open
    paren; return (args, end_index_of_matching_close)."""
    depth = 1
    args, cur, i = [], [], 0
    instr = None
    while i < len(s):
        ch = s[i]
        if instr:
            cur.append(ch)
            if ch == instr and s[i - 1] != "\\":
                instr = None
        elif ch in "\"'`":
            instr = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(cur))
                return args, i
            cur.append(ch)
        elif ch == "," and depth == 1:
            args.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    return args, len(s)


GOOD = (1, 80)


def acceptable(t: str) -> bool:
    t = t.strip()
    if not t or t.startswith(",") or "\n" in t:
        return False
    if len(t) < GOOD[0] or len(t) > GOOD[1]:
        return False
    return any(c.isalnum() for c in t)


def build_prefix(text: str, target_abs: int) -> str:
    head = text[:200]
    tail = text[max(0, target_abs - 1400):target_abs]
    return (head + "\n...\n" + tail) if target_abs > 1600 else text[:target_abs]


def mine_text(text: str, lang: str, rel: str):
    out = []
    for marker, idx in MARKERS[lang]:
        start = 0
        while True:
            pos = text.find(marker, start)
            if pos == -1:
                break
            start = pos + len(marker)
            args, _ = split_args(text[start:])
            if not args:
                continue
            try:
                arg = args[idx]
            except IndexError:
                continue
            if not acceptable(arg):
                continue
            # absolute offset where this arg begins
            before = "".join(args[: idx if idx >= 0 else len(args) + idx])
            sep = (idx if idx >= 0 else len(args) + idx)
            arg_abs = start + len(before) + (sep if sep > 0 else 0)
            # leading whitespace of arg
            lead = len(arg) - len(arg.lstrip())
            out.append({
                "prefix": build_prefix(text, arg_abs + lead),
                "target": arg.strip(),
                "file": rel,
                "kind": marker.strip("(."),
                "lang": lang,
            })
    return out


def is_test_path(path: str, lang: str) -> bool:
    p = path.replace("\\", "/")
    name = os.path.basename(p)
    parts = p.split("/")
    if lang == "rs":
        return "tests" in parts or name.endswith("_test.rs") or "test" in name
    if lang == "go":
        return name.endswith("_test.go")
    # js/ts
    return (
        ".test." in name or ".spec." in name or "__tests__" in parts
        or "test" in parts or "tests" in parts
    )


def mine_repo(root: str):
    tasks = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "node_modules", ".venv", "venv",
                                            "__pycache__", "target", "dist", "build", "vendor")]
        for f in fn:
            full = os.path.join(dp, f)
            ext = os.path.splitext(f)[1].lower()
            if ext == ".py":
                tasks += [dict(t, lang="py") for t in mine_assertions.mine_file(full, root)
                          if mine_assertions.is_test_path(full)]
                continue
            lang = EXT_LANG.get(ext)
            if not lang or not is_test_path(full, lang):
                continue
            try:
                text = open(full, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            tasks += mine_text(text, lang, os.path.relpath(full, root))
    return tasks


if __name__ == "__main__":
    import sys
    ts = mine_repo(sys.argv[1])
    from collections import Counter
    print(f"{len(ts)} tasks", Counter(t["lang"] for t in ts))
    for t in ts[:5]:
        print(f"  [{t['lang']}/{t['kind']}] target={t['target']!r}")

#!/usr/bin/env python3
"""Mine assertion-completion tasks from a Python repository's test suite.

This is the Code2LoRA / RepoPeftBench task (paper §4): given a structured prefix
from a test file (imports + enclosing class + test body up to an assertion cut
point), the model must predict the *target* — the right-hand side of the
assertion. We extract two assertion families that cover the bulk of real suites:

    assert <expr> == <TARGET>
    self.assertEqual(<expr>, <TARGET>)

Output is JSONL with {prefix, target, file, kind}, ready for `run_tinker.py`.
"""
import argparse
import ast
import json
import os
import sys


def line_starts(src: str):
    offsets, pos = [0], 0
    for line in src.splitlines(keepends=True):
        pos += len(line)
        offsets.append(pos)
    return offsets


def abs_offset(starts, lineno, col):
    return starts[lineno - 1] + col


def import_block(tree: ast.AST, src: str, starts) -> str:
    lines = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            seg = ast.get_source_segment(src, node)
            if seg:
                lines.append(seg)
    return "\n".join(lines)


def is_test_func(node) -> bool:
    return isinstance(node, ast.FunctionDef) and node.name.startswith("test")


GOOD_LEN = (1, 80)


def acceptable_target(text: str) -> bool:
    t = text.strip()
    if not t or t.startswith(","):
        return False
    if len(t) < GOOD_LEN[0] or len(t) > GOOD_LEN[1]:
        return False
    if "\n" in t:
        return False
    if all(not c.isalnum() for c in t):  # punctuation-only
        return False
    return True


def extract_from_func(func, src, starts, imports, class_name, file_rel):
    func_start = abs_offset(starts, func.lineno, func.col_offset)
    tasks = []
    for node in ast.walk(func):
        target_node = None
        kind = None
        if isinstance(node, ast.Assert) and isinstance(node.test, ast.Compare):
            cmp = node.test
            if len(cmp.ops) == 1 and isinstance(cmp.ops[0], ast.Eq):
                target_node = cmp.comparators[0]
                kind = "assert_eq"
        elif isinstance(node, ast.Call):
            f = node.func
            is_assert_equal = (
                isinstance(f, ast.Attribute)
                and f.attr in ("assertEqual", "assertEquals")
                and len(node.args) >= 2
            )
            if is_assert_equal:
                target_node = node.args[1]
                kind = "assertEqual"
        if target_node is None:
            continue
        target_text = ast.get_source_segment(src, target_node)
        if not target_text or not acceptable_target(target_text):
            continue
        tgt_start = abs_offset(starts, target_node.lineno, target_node.col_offset)
        if tgt_start <= func_start:
            continue
        body_prefix = src[func_start:tgt_start]
        header = f"class {class_name}:\n" if class_name else ""
        prefix = (imports + "\n\n" + header + body_prefix).strip("\n")
        tasks.append(
            {"prefix": prefix, "target": target_text.strip(), "file": file_rel, "kind": kind}
        )
    return tasks


def mine_file(path: str, repo_root: str):
    try:
        src = open(path, encoding="utf-8", errors="ignore").read()
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return []
    starts = line_starts(src)
    imports = import_block(tree, src, starts)
    rel = os.path.relpath(path, repo_root)
    out = []
    for node in tree.body:
        if is_test_func(node):
            out += extract_from_func(node, src, starts, imports, None, rel)
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if is_test_func(sub):
                    out += extract_from_func(sub, src, starts, imports, node.name, rel)
    return out


def is_test_path(path: str) -> bool:
    name = os.path.basename(path)
    parts = path.replace("\\", "/").split("/")
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or "tests" in parts
        or "test" in parts
    ) and name.endswith(".py")


def mine_repo(repo_root: str):
    tasks = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", ".venv", "venv")]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if fn.endswith(".py") and is_test_path(full):
                tasks += mine_file(full, repo_root)
    return tasks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", help="path to a local repository")
    ap.add_argument("-o", "--out", default="-", help="output JSONL (default stdout)")
    args = ap.parse_args()

    tasks = mine_repo(args.repo)
    fh = sys.stdout if args.out == "-" else open(args.out, "w")
    for t in tasks:
        fh.write(json.dumps(t) + "\n")
    if fh is not sys.stdout:
        fh.close()
    print(f"mined {len(tasks)} assertion tasks from {args.repo}", file=sys.stderr)


if __name__ == "__main__":
    main()

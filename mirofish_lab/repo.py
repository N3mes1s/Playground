"""Repo helpers: walk files, extract Python symbols, find naive callers.

Used by blast-radius-prediction. Intentionally simple — full call-graph
extraction is out of scope; we use AST + grep.
"""

from __future__ import annotations

import ast
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Symbol:
    name: str
    kind: str  # "function" | "class" | "method"
    file: Path
    lineno: int


@dataclass
class Subsystem:
    """A loose grouping of files we treat as one 'agent' for blast-radius sims."""
    name: str
    files: list[Path] = field(default_factory=list)
    description: str = ""

    def files_summary(self, max_chars: int = 4000) -> str:
        lines = []
        used = 0
        for f in self.files:
            try:
                head = f.read_text(errors="ignore").splitlines()[:40]
            except Exception:
                continue
            chunk = f"--- {f} ---\n" + "\n".join(head) + "\n"
            if used + len(chunk) > max_chars:
                break
            lines.append(chunk)
            used += len(chunk)
        return "\n".join(lines)


def clone_repo(url: str, dest: Path | None = None) -> Path:
    """Shallow clone url into dest (or a fresh tmp dir). Returns the path."""
    if dest is None:
        dest = Path(tempfile.mkdtemp(prefix="mirofish_repo_"))
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        check=True,
        capture_output=True,
    )
    return dest


def python_files(root: Path, *, ignore: tuple[str, ...] = (".venv", "venv", "node_modules", ".git")) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*.py"):
        if any(part in ignore for part in p.parts):
            continue
        out.append(p)
    return out


def extract_symbols(file: Path) -> list[Symbol]:
    try:
        src = file.read_text(errors="ignore")
        tree = ast.parse(src)
    except Exception:
        return []
    syms: list[Symbol] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            syms.append(Symbol(node.name, "function", file, node.lineno))
        elif isinstance(node, ast.AsyncFunctionDef):
            syms.append(Symbol(node.name, "function", file, node.lineno))
        elif isinstance(node, ast.ClassDef):
            syms.append(Symbol(node.name, "class", file, node.lineno))
            for ch in node.body:
                if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    syms.append(Symbol(f"{node.name}.{ch.name}", "method", file, ch.lineno))
    return syms


def grep_callers(root: Path, name: str) -> list[Path]:
    """Naive: any .py file that mentions `name` as a word, except its own file."""
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    hits: list[Path] = []
    for p in python_files(root):
        try:
            txt = p.read_text(errors="ignore")
        except Exception:
            continue
        if pattern.search(txt):
            hits.append(p)
    return hits


def parse_unified_diff(diff_text: str) -> list[tuple[Path, list[int]]]:
    """Return [(file, [changed_line_numbers_on_new_side])] for added/modified lines."""
    out: list[tuple[Path, list[int]]] = []
    cur_file: Path | None = None
    cur_lines: list[int] = []
    new_ln = 0
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            if cur_file is not None:
                out.append((cur_file, cur_lines))
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            cur_file = Path(path) if path != "/dev/null" else None
            cur_lines = []
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            if m:
                new_ln = int(m.group(1)) - 1
        elif cur_file is not None:
            if line.startswith("+") and not line.startswith("+++"):
                new_ln += 1
                cur_lines.append(new_ln)
            elif line.startswith("-"):
                pass
            else:
                new_ln += 1
    if cur_file is not None:
        out.append((cur_file, cur_lines))
    return out


def cluster_into_subsystems(root: Path, *, max_files_per: int = 20) -> list[Subsystem]:
    """Cluster a Python repo's files by top-level package directory."""
    files = python_files(root)
    by_pkg: dict[str, list[Path]] = {}
    for f in files:
        rel = f.relative_to(root)
        top = rel.parts[0] if len(rel.parts) > 1 else "(root)"
        by_pkg.setdefault(top, []).append(f)
    out: list[Subsystem] = []
    for pkg, fs in sorted(by_pkg.items()):
        out.append(
            Subsystem(
                name=pkg,
                files=fs[:max_files_per],
                description=f"Top-level package '{pkg}' with {len(fs)} Python files.",
            )
        )
    return out

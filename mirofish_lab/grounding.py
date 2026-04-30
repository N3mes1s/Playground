"""Generic codebase grounding for rollout planning.

The pipeline up to this point produced abstract plans. To be useful in
a world where a coding agent executes the diffs, plans must reference
**actual files, lines, and identifiers** from the target repo. This
module bridges intent -> concrete codebase findings.

Three-stage pipeline:

  1. **Search-plan generation** (LLM, one call): an agent reads the
     intent and emits a list of search patterns -- regexes, AST node
     queries, file-glob filters. Generic; the intent decides what to
     look for. No domain knowledge baked into the scanner.

  2. **Repo scan** (deterministic, no LLM): walk the repo, apply each
     pattern, collect matches with file:line:context. AST queries run
     against Python's `ast` module; non-Python files use regex only.

  3. **Findings summary** (deterministic): structured aggregation
     suitable for injection into stakeholder-constraint prompts.
     Produces:
       - matches grouped by pattern
       - hot files (most matches)
       - per-file match catalogue
       - markdown rendering capped at a token budget

The contract is: "give me an intent and a repo, I'll tell you exactly
which files / lines an executor agent needs to touch and why." That
turns a stakeholder's `Backend: keep API contracts intact` constraint
from a checklist item into `Backend: keep API contracts intact;
relevant call sites: scanner.py:148 (calls validate(...)), cli.py:88,
parallel_scanner.py:32`.

Reference: this is the "ground the agent in the codebase" pattern from
Cursor / Greptile / Cline, but lifted up to the rollout-planning layer
so the plan ITSELF references real code, not just the implementation.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mirofish_lab.agent import Agent
from mirofish_lab.config import Config
from mirofish_lab.personas import Persona
from mirofish_lab.rollout import extract_json


# ---------------------------------------------------------------------------
# 1. Search-plan generation (LLM)
# ---------------------------------------------------------------------------


SEARCH_PLANNER_PERSONA = Persona(
    name="SearchPlanner",
    role="codebase grounding agent",
    system_prompt=(
        "You read a migration / rollout intent and produce a list of search "
        "patterns whose matches in a repo will tell the rollout planner WHICH "
        "files an executor needs to touch.\n\n"
        "Output ONLY a JSON object (wrap in ```json fenced block):\n"
        "{\n"
        '  "patterns": [\n'
        "    {\n"
        '      "description": "<= 80 chars; what this pattern catches",\n'
        '      "regex": "Python regex matching identifiers, imports, decorators, etc., or null",\n'
        '      "ast_kind": "ClassDef" | "FunctionDef" | "Import" | "ImportFrom" | "Call" | "Decorator" | null,\n'
        '      "ast_name_regex": "regex for the AST node name, or null",\n'
        '      "file_globs": ["**/*.py", "**/*.ts", ...]   // optional; default **/*.py\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Rules:\n"
        "- 4-10 patterns. Each pattern targets ONE concept (one decorator "
        "  family, one import, one config key, etc.).\n"
        "- Prefer specific patterns over broad ones. `@validator\\b` is good; "
        "  `validator` alone is too broad.\n"
        "- For Python AST queries, use `ast_kind` and `ast_name_regex`. The "
        "  scanner will match nodes where the kind is `ast_kind` and the node's "
        "  primary name (class name, function name, decorator dotted name, "
        "  imported module/name) matches `ast_name_regex`.\n"
        "- Use `regex` for things AST cannot easily express (config keys, "
        "  string literals, comments).\n"
        "- For non-Python repos, set `file_globs` to the right extensions and "
        "  rely on `regex` only.\n"
        "- Generic only: do NOT hard-code domain knowledge unless it's in the "
        "  intent.\n"
        "- IMPORTANT: `file_globs` are interpreted relative to the repo root "
        "  the scanner is given. Do NOT include the repo's directory name as "
        "  a prefix (`**/*.py`, NOT `myrepo/**/*.py`)."
    ),
)


@dataclass
class SearchPattern:
    description: str
    regex: str | None = None
    ast_kind: str | None = None
    ast_name_regex: str | None = None
    file_globs: tuple[str, ...] = ("**/*.py",)


@dataclass
class SearchPlan:
    intent_excerpt: str
    patterns: list[SearchPattern] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "intent_excerpt": self.intent_excerpt,
            "patterns": [
                {
                    "description": p.description,
                    "regex": p.regex,
                    "ast_kind": p.ast_kind,
                    "ast_name_regex": p.ast_name_regex,
                    "file_globs": list(p.file_globs),
                }
                for p in self.patterns
            ],
        }


def _parse_search_plan(raw: object, intent: str) -> SearchPlan:
    out = SearchPlan(intent_excerpt=intent[:500])
    if not isinstance(raw, dict):
        return out
    for p in raw.get("patterns") or []:
        if not isinstance(p, dict):
            continue
        out.patterns.append(
            SearchPattern(
                description=str(p.get("description", "")).strip()[:120],
                regex=p.get("regex") or None,
                ast_kind=p.get("ast_kind") or None,
                ast_name_regex=p.get("ast_name_regex") or None,
                file_globs=tuple(p.get("file_globs") or ("**/*.py",)),
            )
        )
    return out


def generate_search_plan(intent: str, cfg: Config) -> SearchPlan:
    agent = Agent(SEARCH_PLANNER_PERSONA, cfg)
    prompt = (
        "# Intent\n\n"
        f"{intent.strip()}\n\n"
        "Produce the search-plan JSON per your schema."
    )
    resp = agent.respond(prompt)
    raw = extract_json(resp.content)
    return _parse_search_plan(raw, intent)


# ---------------------------------------------------------------------------
# 2. Repo scan (deterministic)
# ---------------------------------------------------------------------------


@dataclass
class Match:
    pattern_description: str
    file: str
    line: int
    context: str

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern_description,
            "file": self.file,
            "line": self.line,
            "context": self.context,
        }


@dataclass
class Findings:
    repo_path: str
    n_files_scanned: int = 0
    matches: list[Match] = field(default_factory=list)
    matches_by_pattern: dict[str, list[Match]] = field(default_factory=dict)
    matches_by_file: dict[str, list[Match]] = field(default_factory=dict)
    hot_files: list[tuple[str, int]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "repo_path": self.repo_path,
            "n_files_scanned": self.n_files_scanned,
            "n_matches": len(self.matches),
            "matches_by_pattern": {
                k: [m.to_dict() for m in v]
                for k, v in self.matches_by_pattern.items()
            },
            "hot_files": self.hot_files,
        }


_DEFAULT_IGNORE = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    "build", "dist", ".mypy_cache", ".pytest_cache",
    ".mirofish_memory", "reports", "baselines", "probes",
}


def _normalise_globs(root: Path, globs: tuple[str, ...]) -> list[str]:
    """LLMs sometimes include the repo's basename as a glob prefix
    (e.g. `myrepo/**/*.py`). When the glob is relative to root, that
    prefix is double-applied. Strip leading path components that match
    `root.name` or any of root's parents."""
    normalised: list[str] = []
    base = root.name
    for g in globs:
        normalised.append(g)
        # Try also a stripped variant if the glob has a leading component.
        parts = g.split("/", 1)
        if len(parts) == 2 and parts[0] == base:
            normalised.append(parts[1])
    return normalised


def _iter_files(root: Path, globs: tuple[str, ...]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for g in _normalise_globs(root, globs):
        for p in root.glob(g):
            if not p.is_file():
                continue
            if any(part in _DEFAULT_IGNORE for part in p.relative_to(root).parts):
                continue
            if p in seen:
                continue
            seen.add(p)
            out.append(p)
    return out


def _dotted(node: ast.AST) -> str:
    """Render an Attribute / Name chain as a dotted string."""
    parts: list[str] = []
    cur: ast.AST | None = node
    while isinstance(cur, ast.Attribute):
        parts.insert(0, cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.insert(0, cur.id)
    return ".".join(parts)


def _ast_candidate_names(node: ast.AST) -> list[str]:
    """All plausible names for an AST node, any of which can match
    pattern.ast_name_regex. We try multiple forms so the LLM's regex
    matches whether it says `dspy.LM` (dotted) or just `LM` (attr only)."""
    if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
        return [node.name]
    if isinstance(node, ast.Import):
        return [a.name for a in node.names]
    if isinstance(node, ast.ImportFrom):
        out = []
        if node.module:
            out.append(node.module)
        for a in node.names or []:
            out.append(a.name)
            if node.module:
                out.append(f"{node.module}.{a.name}")
        return out or [""]
    if isinstance(node, ast.Call):
        f = node.func
        names: list[str] = []
        dotted = _dotted(f)
        if dotted:
            names.append(dotted)
        if isinstance(f, ast.Attribute):
            names.append(f.attr)
        elif isinstance(f, ast.Name):
            names.append(f.id)
        return names or [""]
    if isinstance(node, ast.Attribute):
        return [_dotted(node), node.attr]
    if isinstance(node, ast.Name):
        return [node.id]
    return [""]


def _ast_node_name(node: ast.AST) -> str:
    """Primary display name for a node (used in match context)."""
    cands = _ast_candidate_names(node)
    return cands[0] if cands else ""


def _decorator_dotted_name(d: ast.AST) -> str:
    """For a decorator AST node, render its dotted name (e.g.
    `validator`, `pydantic.validator`, `pre_load.bound_method`)."""
    if isinstance(d, ast.Name):
        return d.id
    if isinstance(d, ast.Attribute):
        # @x.y.z
        parts: list[str] = []
        cur: ast.AST | None = d
        while isinstance(cur, ast.Attribute):
            parts.insert(0, cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.insert(0, cur.id)
        return ".".join(parts)
    if isinstance(d, ast.Call):
        return _decorator_dotted_name(d.func)
    return ""


def _scan_python_ast(path: Path, src: str, patterns: list[SearchPattern]) -> list[Match]:
    try:
        tree = ast.parse(src)
    except Exception:
        return []
    matches: list[Match] = []
    rel = str(path)
    lines = src.splitlines()
    for node in ast.walk(tree):
        for p in patterns:
            if not p.ast_kind:
                continue
            kind = p.ast_kind
            # decorator special case: scan FunctionDef/AsyncFunctionDef/ClassDef decorators
            if kind == "Decorator":
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                for d in getattr(node, "decorator_list", []) or []:
                    name = _decorator_dotted_name(d)
                    if p.ast_name_regex and not re.search(p.ast_name_regex, name):
                        continue
                    line_no = getattr(d, "lineno", node.lineno)
                    ctx = lines[line_no - 1].strip() if line_no - 1 < len(lines) else ""
                    matches.append(
                        Match(p.description, rel, line_no, ctx[:200])
                    )
                continue
            # generic kind match on node class name
            if node.__class__.__name__ != kind:
                continue
            if p.ast_name_regex:
                if not any(re.search(p.ast_name_regex, n) for n in _ast_candidate_names(node)):
                    continue
            line_no = getattr(node, "lineno", 0)
            ctx = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            matches.append(Match(p.description, rel, line_no, ctx[:200]))
    return matches


def _scan_regex(path: Path, src: str, patterns: list[SearchPattern]) -> list[Match]:
    matches: list[Match] = []
    rel = str(path)
    lines = src.splitlines()
    for p in patterns:
        if not p.regex:
            continue
        try:
            rx = re.compile(p.regex)
        except re.error:
            continue
        for i, ln in enumerate(lines, 1):
            if rx.search(ln):
                matches.append(Match(p.description, rel, i, ln.strip()[:200]))
    return matches


def scan_repo(repo_path: Path, plan: SearchPlan) -> Findings:
    root = Path(repo_path).resolve()
    findings = Findings(repo_path=str(root))

    # Bucket patterns by file glob to avoid double iteration.
    glob_to_patterns: dict[tuple[str, ...], list[SearchPattern]] = {}
    for p in plan.patterns:
        glob_to_patterns.setdefault(p.file_globs, []).append(p)

    seen_files: set[Path] = set()
    for globs, pats in glob_to_patterns.items():
        for f in _iter_files(root, globs):
            if f in seen_files:
                pass
            seen_files.add(f)
            try:
                src = f.read_text(errors="ignore")
            except Exception:
                continue
            ast_pats = [p for p in pats if p.ast_kind]
            regex_pats = [p for p in pats if p.regex]
            if f.suffix == ".py" and ast_pats:
                findings.matches.extend(_scan_python_ast(f, src, ast_pats))
            if regex_pats:
                findings.matches.extend(_scan_regex(f, src, regex_pats))
    findings.n_files_scanned = len(seen_files)

    for m in findings.matches:
        findings.matches_by_pattern.setdefault(m.pattern_description, []).append(m)
        findings.matches_by_file.setdefault(m.file, []).append(m)

    findings.hot_files = sorted(
        ((f, len(ms)) for f, ms in findings.matches_by_file.items()),
        key=lambda kv: -kv[1],
    )[:20]
    return findings


# ---------------------------------------------------------------------------
# 3. Findings summary (for prompt injection)
# ---------------------------------------------------------------------------


def render_findings_summary(findings: Findings, *, max_chars: int = 3000) -> str:
    lines: list[str] = [
        f"## Codebase findings",
        f"",
        f"- Scanned {findings.n_files_scanned} files at `{findings.repo_path}`.",
        f"- {len(findings.matches)} total matches across "
        f"{len(findings.matches_by_pattern)} patterns.",
        "",
    ]
    if findings.hot_files:
        lines.append("**Hot files (most matches):**")
        for f, n in findings.hot_files[:8]:
            lines.append(f"- `{f}` — {n}")
        lines.append("")
    lines.append("**Matches by pattern:**")
    lines.append("")
    used = sum(len(ln) for ln in lines)
    for pattern, ms in findings.matches_by_pattern.items():
        header = f"- **{pattern}** ({len(ms)} matches):"
        if used + len(header) > max_chars:
            lines.append("- _(truncated; see findings.json for full list)_")
            break
        lines.append(header)
        used += len(header)
        for m in ms[:6]:
            row = f"    - `{m.file}:{m.line}` — {m.context[:80]}"
            if used + len(row) > max_chars:
                break
            lines.append(row)
            used += len(row)
        if len(ms) > 6:
            extra = f"    - _... and {len(ms) - 6} more._"
            if used + len(extra) <= max_chars:
                lines.append(extra)
                used += len(extra)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Convenience: clone-on-demand for remote repos
# ---------------------------------------------------------------------------


def shallow_clone(url: str, dest: Path) -> Path:
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        check=True,
        capture_output=True,
    )
    return dest

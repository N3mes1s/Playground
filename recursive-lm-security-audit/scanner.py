"""
Recursive Language Model Security Auditor

Uses DSPy's RLM module to decompose security analysis of a codebase into
recursive sub-tasks, enabling thorough vulnerability detection at minimal cost.

Based on: https://kmad.ai/Recursive-Language-Models-Security-Audit
"""

import os
from pathlib import Path
from typing import Any

import dspy


class CodeScanner(dspy.Signature):
    """Review provided application source code in detail. Focus specifically on
    identifying security vulnerabilities, insecure coding patterns, and other
    areas of concern."""

    source_tree: dict = dspy.InputField(
        desc="Dictionary containing folder-to-file mapping of the target codebase"
    )
    documentation: str = dspy.OutputField(
        desc="Detailed security audit report in markdown format"
    )


# File extensions worth scanning (skip binaries, images, lock files, etc.)
SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".rb", ".php",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt", ".scala", ".sh",
    ".bash", ".zsh", ".ps1", ".sql", ".html", ".htm", ".css", ".scss",
    ".yaml", ".yml", ".json", ".toml", ".xml", ".tf", ".hcl", ".dockerfile",
    ".env", ".cfg", ".ini", ".conf", ".vue", ".svelte",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".next", ".nuxt", "vendor", "target", ".terraform",
}


def load_source_tree(root: str | Path) -> dict[str, Any]:
    """Recursively load a codebase into a nested dictionary preserving
    folder hierarchy and file contents."""
    root = Path(root).resolve()
    tree: dict[str, Any] = {}

    for entry in sorted(root.iterdir()):
        if entry.name.startswith(".") and entry.name in SKIP_DIRS:
            continue
        if entry.is_dir():
            if entry.name in SKIP_DIRS:
                continue
            subtree = load_source_tree(entry)
            if subtree:  # only include non-empty directories
                tree[entry.name] = subtree
        elif entry.is_file():
            if entry.suffix.lower() in SOURCE_EXTENSIONS:
                try:
                    tree[entry.name] = entry.read_text(errors="ignore")
                except (OSError, PermissionError):
                    tree[entry.name] = "<unreadable>"

    return tree


def run_audit(
    source_path: str | Path,
    model: str = "openrouter/moonshotai/kimi-k2.5",
    sub_model: str | None = None,
    max_tokens: int = 16000,
    max_iterations: int = 35,
    verbose: bool = True,
) -> str:
    """Run a recursive LM security audit on the given source directory.

    Args:
        source_path: Path to the codebase root directory.
        model: Primary LM identifier (OpenRouter, OpenAI, etc.).
        sub_model: Model for recursive sub-queries (defaults to same as model).
        max_tokens: Max tokens per LM call.
        max_iterations: Maximum REPL iterations for the RLM.
        verbose: Enable detailed execution logging.

    Returns:
        Markdown-formatted security audit report.
    """
    lm = dspy.LM(model, max_tokens=max_tokens)
    sub_lm = dspy.LM(sub_model, max_tokens=max_tokens) if sub_model else lm
    dspy.configure(lm=lm)

    code_scanner = dspy.RLM(
        CodeScanner,
        max_iterations=max_iterations,
        sub_lm=sub_lm,
        verbose=verbose,
    )

    source_tree = load_source_tree(source_path)

    if not source_tree:
        raise ValueError(f"No scannable source files found in {source_path}")

    # Remove top-level non-source artifacts if present
    for key in ["CONTENT", "LICENSE", "CHANGELOG"]:
        source_tree.pop(key, None)

    result = code_scanner(source_tree=source_tree)
    return result.documentation

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


def _configure_deno_tls() -> None:
    """Ensure Deno trusts the system CA bundle when behind a proxy.

    Sets DENO_CERT from SSL_CERT_FILE if not already configured, so
    pyodide can be downloaded through corporate/MITM proxies.
    """
    if "DENO_CERT" not in os.environ:
        cert_file = os.environ.get("SSL_CERT_FILE")
        if cert_file and Path(cert_file).is_file():
            os.environ["DENO_CERT"] = cert_file
    # Also ensure deno is on PATH
    deno_home = Path.home() / ".deno" / "bin"
    if deno_home.is_dir() and str(deno_home) not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{deno_home}:{os.environ.get('PATH', '')}"


def run_audit(
    source_path: str | Path,
    model: str = "openrouter/moonshotai/kimi-k2.5",
    sub_model: str | None = None,
    max_tokens: int = 16000,
    max_iterations: int = 35,
    verbose: bool = True,
    reasoning_effort: str | None = None,
) -> str:
    """Run a recursive LM security audit on the given source directory.

    Args:
        source_path: Path to the codebase root directory.
        model: Primary LM identifier (OpenRouter, OpenAI, etc.).
        sub_model: Model for recursive sub-queries (defaults to same as model).
        max_tokens: Max tokens per LM call.
        max_iterations: Maximum REPL iterations for the RLM.
        verbose: Enable detailed execution logging.
        reasoning_effort: Reasoning effort level for supported models (e.g. "xhigh").

    Returns:
        Markdown-formatted security audit report.
    """
    lm_kwargs = {}
    if reasoning_effort:
        lm_kwargs["reasoning_effort"] = reasoning_effort

    lm = dspy.LM(model, max_tokens=max_tokens, **lm_kwargs)
    sub_lm_kwargs = dict(lm_kwargs)  # same reasoning effort for sub-model
    sub_lm = dspy.LM(sub_model, max_tokens=max_tokens, **sub_lm_kwargs) if sub_model else lm
    dspy.configure(lm=lm)

    _configure_deno_tls()

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

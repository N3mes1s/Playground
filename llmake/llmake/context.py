"""
Workspace — manage the set of input files and general-purpose context.

Resolves the glob patterns declared in the manifest into concrete files and
loads their contents. This is the "manage a set of input files (Markdown or
similar), plus other general-purpose context" requirement, isolated so the
source-material layer can later grow (binary assets, URLs, databases) without
touching the build engine.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .spec import Workflow


def _expand(root: Path, patterns: list) -> dict:
    """Expand glob patterns (relative to root) into {relpath: contents}."""
    files: dict[str, str] = {}
    for pattern in patterns:
        for path in sorted(root.glob(pattern)):
            if path.is_file():
                rel = path.relative_to(root).as_posix()
                files[rel] = path.read_text(errors="replace")
    return files


def load_inputs(wf: Workflow, patterns: list | None = None) -> dict:
    """Load input files. If ``patterns`` is given, use those; else the global
    ``inputs:`` patterns from the manifest."""
    return _expand(wf.root, patterns if patterns is not None else wf.inputs)


def load_context(wf: Workflow) -> dict:
    """Load the shared general-purpose context files."""
    return _expand(wf.root, wf.context)


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

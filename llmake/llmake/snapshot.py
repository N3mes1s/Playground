"""
Snapshots — lightweight VCS integration over git.

The "snapshots / VCS integration" requirement, MVP-style: a snapshot is a git
commit of the build artifacts (and optionally the inputs that produced them),
tagged so you can list, diff, and restore the state of a compile. Because it's
just git underneath, snapshots interoperate with normal version control and
push to any remote.

Real-time *collaboration* (multiple cursors / live editing) is intentionally
out of MVP scope — see DESIGN.md. The seam for it lives here: a future
backend could replace git commits with CRDT sync (e.g. y-py) behind the same
``snapshot`` / ``list_snapshots`` interface.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Snapshot:
    ref: str
    message: str
    when: str


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=str(root), capture_output=True, text=True
    )


def is_git_repo(root: Path) -> bool:
    return _git(root, "rev-parse", "--is-inside-work-tree").returncode == 0


def snapshot(root: Path, message: str, paths: list | None = None) -> Snapshot:
    """Create a snapshot (git commit + tag) of the given paths.

    Defaults to snapshotting the ``build/`` directory. Returns the new tag.
    """
    if not is_git_repo(root):
        raise RuntimeError(f"{root} is not inside a git repository")

    # Force-add: build artifacts are often .gitignored, but snapshotting them
    # is the whole point of this command.
    paths = paths or ["build"]
    add = _git(root, "add", "-f", "--", *paths)
    if add.returncode != 0:
        raise RuntimeError(f"git add failed: {add.stderr.strip()}")

    commit = _git(root, "commit", "-m", f"llmake snapshot: {message}")
    # An empty commit (nothing changed) is fine — fall through to tagging HEAD.
    if commit.returncode != 0 and "nothing to commit" not in commit.stdout:
        raise RuntimeError(f"git commit failed: {commit.stderr.strip() or commit.stdout.strip()}")

    sha = _git(root, "rev-parse", "--short", "HEAD").stdout.strip()
    tag = f"llmake/{sha}"
    _git(root, "tag", "-f", tag, "-m", message)
    when = _git(root, "show", "-s", "--format=%cI", "HEAD").stdout.strip()
    return Snapshot(ref=tag, message=message, when=when)


def list_snapshots(root: Path) -> list:
    """List llmake snapshot tags, newest first."""
    out = _git(root, "tag", "-l", "llmake/*", "--sort=-creatordate",
               "--format=%(refname:short)\t%(contents:subject)\t%(creatordate:iso)")
    snaps: list[Snapshot] = []
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            snaps.append(Snapshot(ref=parts[0], message=parts[1], when=parts[2]))
    return snaps

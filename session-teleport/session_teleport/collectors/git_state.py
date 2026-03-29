"""Capture and restore git repository state."""

from __future__ import annotations

import subprocess
from pathlib import Path

from ..utils.display import info, warning


def _run_git(cwd: str, *args: str) -> str:
    """Run a git command and return stdout."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def capture_git_state(cwd: str) -> dict[str, bytes]:
    """Capture git state from a working directory. Returns {filename: content} for the bundle."""
    files: dict[str, bytes] = {}

    # Check if this is a git repo
    if not (Path(cwd) / ".git").exists() and not _run_git(cwd, "rev-parse", "--git-dir"):
        warning("Not a git repository, skipping git state capture")
        return files

    # Branch name
    branch = _run_git(cwd, "rev-parse", "--abbrev-ref", "HEAD")
    if branch:
        files["git/branch.txt"] = branch.encode()

    # Current commit
    commit = _run_git(cwd, "rev-parse", "HEAD")
    if commit:
        files["git/commit.txt"] = commit.encode()

    # Remote URL
    remote = _run_git(cwd, "remote", "get-url", "origin")
    if remote:
        files["git/remote.txt"] = remote.encode()

    # Status
    status = _run_git(cwd, "status", "--short")
    if status:
        files["git/status.txt"] = status.encode()

    # Uncommitted changes (staged + unstaged)
    diff = _run_git(cwd, "diff", "HEAD")
    if diff:
        files["git/uncommitted.patch"] = diff.encode()
        info(f"  Git diff: {len(diff):,} bytes")

    # Staged but not yet committed
    staged = _run_git(cwd, "diff", "--cached")
    if staged:
        files["git/staged.patch"] = staged.encode()

    # Log of recent commits for context
    log = _run_git(cwd, "log", "--oneline", "-20")
    if log:
        files["git/log.txt"] = log.encode()

    # Stash list
    stash = _run_git(cwd, "stash", "list")
    if stash:
        files["git/stash.txt"] = stash.encode()

    return files


def apply_git_state(cwd: str, reader, dry_run: bool = False) -> list[str]:
    """Apply git state from a bundle to a working directory. Returns list of actions taken."""
    actions = []

    try:
        branch_data = reader.read_file("git/branch.txt")
        branch = branch_data.decode().strip()
        actions.append(f"Source branch: {branch}")
    except FileNotFoundError:
        return actions

    try:
        commit_data = reader.read_file("git/commit.txt")
        actions.append(f"Source commit: {commit_data.decode().strip()}")
    except FileNotFoundError:
        pass

    try:
        remote_data = reader.read_file("git/remote.txt")
        actions.append(f"Source remote: {remote_data.decode().strip()}")
    except FileNotFoundError:
        pass

    try:
        patch_data = reader.read_file("git/uncommitted.patch")
        patch = patch_data.decode()
        if patch:
            actions.append(f"Uncommitted changes patch: {len(patch):,} bytes")
            if not dry_run:
                result = subprocess.run(
                    ["git", "apply", "--stat", "-"],
                    input=patch,
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    # Actually apply
                    subprocess.run(
                        ["git", "apply", "-"],
                        input=patch,
                        cwd=cwd,
                        capture_output=True,
                        text=True,
                    )
                    actions.append("Applied uncommitted changes patch")
                else:
                    actions.append(f"Patch apply failed: {result.stderr}")
    except FileNotFoundError:
        pass

    return actions

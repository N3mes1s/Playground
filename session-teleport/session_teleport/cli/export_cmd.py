"""CLI export command."""

from __future__ import annotations

from pathlib import Path

import click

from ..collectors.env_snapshot import capture_env
from ..collectors.git_state import capture_git_state
from ..collectors.tool_versions import capture_tool_versions
from ..core.bundle import BundleBuilder
from ..core.manifest import Manifest
from ..security.warnings import warn_secrets_in_content
from ..transfer.file_transfer import save_bundle
from ..utils.display import error, info
from ..utils.paths import get_hostname, get_platform
from . import _find_session, _prompt_passphrase


@click.command()
@click.argument("session_id")
@click.option("--provider", "-p", type=click.Choice(["claude", "codex"]), default=None)
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path")
@click.option("--include-git/--no-git", default=True, help="Include git state")
@click.option("--include-env/--no-env", default=True, help="Include environment snapshot")
@click.option("--encrypt/--no-encrypt", default=True, help="Encrypt the bundle")
def export(
    session_id: str,
    provider: str | None,
    output: str | None,
    include_git: bool,
    include_env: bool,
    encrypt: bool,
):
    """Export a session to a .stp bundle file."""
    prov, session = _find_session(session_id, provider)
    if not prov or not session:
        error(f"Session not found: {session_id}")
        raise SystemExit(1)

    manifest = Manifest(
        provider=prov.name,
        session_id=session.session_id,
        source_hostname=get_hostname(),
        source_platform=get_platform(),
        source_cwd=session.cwd,
        components=["session"],
    )

    builder = BundleBuilder(manifest)
    prov.export_session(session.session_id, builder)

    # Git state
    if include_git and session.cwd:
        info("Capturing git state...")
        git_files = capture_git_state(session.cwd)
        for path, content in git_files.items():
            builder.add_file(path, content)
        if git_files:
            manifest.components.append("git")

    # Environment
    if include_env:
        info("Capturing environment...")
        env_files = capture_env()
        for path, content in env_files.items():
            builder.add_file(path, content)
        manifest.components.append("env")

        version_files = capture_tool_versions()
        for path, content in version_files.items():
            builder.add_file(path, content)

    # Scan for secrets in conversation log
    for path, data in builder.files.items():
        if path.endswith(".jsonl") and not warn_secrets_in_content(data.decode(errors="replace")):
            error("Export cancelled by user")
            raise SystemExit(1)

    # Encrypt
    passphrase = _prompt_passphrase(confirm=True) if encrypt else None

    # Build and save
    bundle_data = builder.build(passphrase)

    if not output:
        output = f"session-{session.session_id[:8]}.stp"
    save_bundle(bundle_data, Path(output))

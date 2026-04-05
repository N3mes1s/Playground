"""CLI import command."""

from __future__ import annotations

from pathlib import Path

import click

from ..collectors.git_state import apply_git_state
from ..security.warnings import warn_cwd_mismatch, warn_platform_mismatch
from ..transfer.file_transfer import load_bundle
from ..utils.display import console, error, info, print_bundle_info, success
from ..utils.paths import get_platform
from . import PROVIDER_MAP, _convert_if_needed, _open_bundle


@click.command()
@click.argument("bundle_path", type=click.Path(exists=True))
@click.option(
    "--target-dir", "-t", type=click.Path(), default=None,
    help="Override working directory on this machine",
)
@click.option(
    "--target-provider", "-tp", type=click.Choice(["claude", "codex"]),
    default=None, help="Convert to a different provider format",
)
@click.option(
    "--apply-git/--no-apply-git", default=None,
    help="Apply git patches (default: prompt)",
)
@click.option("--dry-run", is_flag=True, help="Show what would be imported without writing")
@click.option("--passphrase", type=str, default=None, help="Decryption passphrase")
def import_session(
    bundle_path: str,
    target_dir: str | None,
    target_provider: str | None,
    apply_git: bool | None,
    dry_run: bool,
    passphrase: str | None,
):
    """Import a session from a .stp bundle file."""
    data = load_bundle(Path(bundle_path))

    try:
        reader = _open_bundle(data, passphrase)
    except ValueError as e:
        error(str(e))
        raise SystemExit(1) from e

    reader = _convert_if_needed(reader, target_provider, target_dir)
    manifest = reader.manifest

    print_bundle_info(manifest.__dict__)

    # Platform warnings
    warn_platform_mismatch(manifest.source_platform, get_platform())
    warn_cwd_mismatch(manifest.source_cwd, target_dir)

    if dry_run:
        console.print("\n[bold]Bundle contents:[/]")
        for f in reader.list_files():
            console.print(f"  {f}")
        console.print("\n[dim]Dry run - no changes made.[/]")
        return

    # Import session files
    provider_cls = PROVIDER_MAP.get(manifest.provider)
    if not provider_cls:
        error(f"Unknown provider in bundle: {manifest.provider}")
        raise SystemExit(1)

    provider = provider_cls()
    provider.import_session(reader, target_dir)

    # Apply git state
    if "git" in manifest.components:
        cwd = target_dir or manifest.source_cwd
        if apply_git is None:
            apply_git = click.confirm(
                "Apply git patches from bundle?", default=False
            )
        if apply_git:
            actions = apply_git_state(cwd, reader)
            for action in actions:
                info(f"  {action}")

    # Show environment info
    if "env" in manifest.components:
        try:
            versions = reader.read_json("env/tool_versions.json")
            info(f"  Source tool versions: {versions}")
        except FileNotFoundError:
            pass

    reader.close()
    success("Session imported successfully!")

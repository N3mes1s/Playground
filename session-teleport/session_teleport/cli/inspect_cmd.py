"""CLI inspect command."""

from __future__ import annotations

from pathlib import Path

import click

from ..transfer.file_transfer import load_bundle
from ..utils.display import console, print_bundle_info
from . import _open_bundle


@click.command()
@click.argument("bundle_path", type=click.Path(exists=True))
@click.option("--passphrase", type=str, default=None)
def inspect(bundle_path: str, passphrase: str | None):
    """Inspect a .stp bundle without importing."""
    data = load_bundle(Path(bundle_path))
    reader = _open_bundle(data, passphrase)
    print_bundle_info(reader.manifest.__dict__)

    console.print("\n[bold]Files in bundle:[/]")
    for f in reader.list_files():
        console.print(f"  {f}")

    for path, label in [("git/branch.txt", "Git branch"), ("git/status.txt", "Git status")]:
        try:
            text = reader.read_file(path).decode().strip()
            sep = "\n" if "\n" in text else " "
            console.print(f"\n[bold]{label}:[/]{sep}{text}")
        except FileNotFoundError:
            pass

    try:
        versions = reader.read_json("env/tool_versions.json")
        console.print("\n[bold]Tool versions:[/]")
        for tool, ver in versions.items():
            console.print(f"  {tool}: {ver}")
    except FileNotFoundError:
        pass

    reader.close()

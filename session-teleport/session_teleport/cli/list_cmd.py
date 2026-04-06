"""CLI list command."""

from __future__ import annotations

import click

from ..utils.display import info, print_sessions_table, warning
from . import _get_provider, _get_providers


@click.command()
@click.option(
    "--provider", "-p",
    type=click.Choice(["claude", "codex", "all"]),
    default="all",
)
def list_sessions(provider: str):
    """List available sessions."""
    providers = _get_providers() if provider == "all" else [_get_provider(provider)]

    all_sessions = []
    for p in providers:
        if p.is_available():
            all_sessions.extend(s.to_dict() for s in p.list_sessions())
        else:
            info(f"{p.name}: data directory not found")

    if all_sessions:
        print_sessions_table(all_sessions)
    else:
        warning("No sessions found")

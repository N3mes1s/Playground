"""CLI relay-server command."""

from __future__ import annotations

import click


@click.command()
@click.option("--port", type=int, default=8765)
@click.option("--ttl", type=int, default=30, help="Bundle TTL in minutes")
def relay_server(port: int, ttl: int):
    """Start a relay server for indirect transfers."""
    from ..transfer.relay import start_relay_server

    start_relay_server(port, ttl)

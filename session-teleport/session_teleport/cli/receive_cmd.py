"""CLI receive command."""

from __future__ import annotations

import asyncio
from pathlib import Path

import click

from ..transfer.file_transfer import save_bundle
from ..transfer.peer import receive_from_peer
from ..transfer.relay import download_from_relay
from ..utils.display import error, print_bundle_info, success
from . import PROVIDER_MAP, _open_bundle


@click.command()
@click.option(
    "--method", "-m",
    type=click.Choice(["peer", "relay"]),
    default="peer",
    help="Transfer method: peer (direct TCP) or relay (via server)",
)
@click.option("--port", type=int, default=9876, help="Port to listen on")
@click.option("--relay-url", type=str, default=None, help="Relay server URL")
@click.option("--code", type=str, default=None, help="Pickup code for relay")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save bundle to file")
@click.option("--auto-import", is_flag=True, help="Automatically import after receiving")
@click.option(
    "--target-provider", "-tp", type=click.Choice(["claude", "codex"]),
    default=None, help="Convert to a different provider format",
)
@click.option("--passphrase", type=str, default=None)
def receive(
    method: str,
    port: int,
    relay_url: str | None,
    code: str | None,
    output: str | None,
    auto_import: bool,
    target_provider: str | None,
    passphrase: str | None,
):
    """Receive a session from another machine."""
    if method == "peer":
        data = asyncio.run(receive_from_peer(port))
    elif method == "relay":
        if not relay_url or not code:
            error("--relay-url and --code required for relay receive")
            raise SystemExit(1)
        data = asyncio.run(download_from_relay(relay_url, code))
    else:
        error(f"Unknown method: {method}")
        raise SystemExit(1)

    if output:
        save_bundle(data, Path(output))
    elif auto_import:
        try:
            reader = _open_bundle(data, passphrase)
        except ValueError as e:
            error(str(e))
            raise SystemExit(1) from e

        manifest = reader.manifest

        # Cross-provider conversion
        if target_provider:
            target_key = {"claude": "claude_code", "codex": "codex_cli"}[target_provider]
            if target_key != manifest.provider:
                from ..converters import get_converter

                converter = get_converter(manifest.provider, target_key)
                if not converter:
                    error(
                        f"No converter available from"
                        f" {manifest.provider} to {target_key}"
                    )
                    raise SystemExit(1)
                reader = converter.convert(reader)
                manifest = reader.manifest

        print_bundle_info(manifest.__dict__)

        provider_cls = PROVIDER_MAP.get(manifest.provider)
        if provider_cls:
            provider_cls().import_session(reader)
            success("Session imported!")
        reader.close()
    else:
        output = "received-session.stp"
        save_bundle(data, Path(output))

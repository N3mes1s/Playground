"""CLI send command."""

from __future__ import annotations

import asyncio
from pathlib import Path

import click

from ..collectors.env_snapshot import capture_env
from ..collectors.git_state import capture_git_state
from ..collectors.tool_versions import capture_tool_versions
from ..core.bundle import BundleBuilder
from ..core.manifest import Manifest
from ..transfer.file_transfer import save_bundle
from ..transfer.peer import send_to_peer
from ..transfer.relay import upload_to_relay
from ..utils.display import console, error
from ..utils.paths import get_hostname, get_platform
from . import _find_session, _prompt_passphrase


@click.command()
@click.argument("session_id")
@click.option("--provider", "-p", type=click.Choice(["claude", "codex"]), default=None)
@click.option(
    "--method", "-m",
    type=click.Choice(["file", "peer", "relay"]),
    default="file",
    help="Transfer method: file (save .stp), peer (direct TCP), relay (via server)",
)
@click.option("--host", type=str, default=None, help="Target host for peer transfer")
@click.option("--port", type=int, default=9876, help="Port for peer transfer")
@click.option("--relay-url", type=str, default=None, help="Relay server URL")
@click.option("--encrypt/--no-encrypt", default=True, help="Encrypt the bundle")
def send(
    session_id: str,
    provider: str | None,
    method: str,
    host: str | None,
    port: int,
    relay_url: str | None,
    encrypt: bool,
):
    """Export and send a session to another machine."""
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
        components=["session", "git", "env"],
    )

    builder = BundleBuilder(manifest)
    prov.export_session(session.session_id, builder)

    if session.cwd:
        for path, content in capture_git_state(session.cwd).items():
            builder.add_file(path, content)
    for path, content in capture_env().items():
        builder.add_file(path, content)
    for path, content in capture_tool_versions().items():
        builder.add_file(path, content)

    passphrase = _prompt_passphrase(confirm=True) if encrypt else None
    bundle_data = builder.build(passphrase)

    if method == "file":
        output = f"session-{session.session_id[:8]}.stp"
        save_bundle(bundle_data, Path(output))

    elif method == "peer":
        if not host:
            error("--host required for peer transfer")
            raise SystemExit(1)
        auth_code = click.prompt("Enter the receiver's auth code")
        asyncio.run(send_to_peer(bundle_data, host, port, auth_code))

    elif method == "relay":
        if not relay_url:
            error("--relay-url required for relay transfer")
            raise SystemExit(1)
        code = asyncio.run(upload_to_relay(bundle_data, relay_url))
        console.print(
            f"\n[bold]Share this pickup code with the receiver:"
            f" [yellow]{code}[/][/]"
        )

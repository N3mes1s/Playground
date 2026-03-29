"""CLI entry point for session-teleport."""

from __future__ import annotations

import asyncio
from pathlib import Path

import click

from .collectors.env_snapshot import capture_env
from .collectors.git_state import apply_git_state, capture_git_state
from .collectors.tool_versions import capture_tool_versions
from .core.bundle import BundleBuilder, BundleReader, is_bundle_encrypted
from .core.manifest import Manifest
from .providers.base import SessionProvider
from .providers.claude_code import ClaudeCodeProvider
from .providers.codex_cli import CodexCliProvider
from .security.warnings import warn_cwd_mismatch, warn_platform_mismatch, warn_secrets_in_content
from .transfer.file_transfer import load_bundle, save_bundle
from .transfer.peer import receive_from_peer, send_to_peer
from .transfer.relay import download_from_relay, upload_to_relay
from .utils.display import (
    console,
    error,
    info,
    print_bundle_info,
    print_sessions_table,
    success,
    warning,
)
from .utils.paths import get_hostname, get_platform

PROVIDER_MAP: dict[str, type[SessionProvider]] = {
    "claude_code": ClaudeCodeProvider,
    "codex_cli": CodexCliProvider,
}


def _get_providers() -> list[SessionProvider]:
    return [ClaudeCodeProvider(), CodexCliProvider()]


def _get_provider(name: str) -> SessionProvider:
    providers = {"claude": ClaudeCodeProvider(), "codex": CodexCliProvider()}
    if name not in providers:
        raise click.BadParameter(f"Unknown provider: {name}. Use 'claude' or 'codex'.")
    return providers[name]


def _find_session(session_id: str, provider_name: str | None = None):
    """Find a session by ID, optionally filtering by provider."""
    providers = [_get_provider(provider_name)] if provider_name else _get_providers()
    for provider in providers:
        if not provider.is_available():
            continue
        for session in provider.list_sessions():
            if session.session_id.startswith(session_id):
                return provider, session
    return None, None


def _prompt_passphrase(confirm: bool = False) -> str:
    """Prompt user for a passphrase."""
    return click.prompt("Passphrase", hide_input=True, confirmation_prompt=confirm)


def _open_bundle(data: bytes, passphrase: str | None = None) -> BundleReader:
    """Open a bundle, prompting for passphrase if encrypted."""
    encrypted = is_bundle_encrypted(data)
    if encrypted and not passphrase:
        passphrase = _prompt_passphrase()
    return BundleReader(data, passphrase if encrypted else None)


@click.group()
@click.version_option()
def main():
    """Teleport Claude Code and Codex CLI sessions between machines."""


@main.command("list")
@click.option("--provider", "-p", type=click.Choice(["claude", "codex", "all"]), default="all")
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


@main.command()
@click.argument("session_id")
@click.option("--provider", "-p", type=click.Choice(["claude", "codex"]), default=None)
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path")
@click.option("--include-git/--no-git", default=True, help="Include git state")
@click.option("--include-env/--no-env", default=True, help="Include environment snapshot")
@click.option("--encrypt/--no-encrypt", default=True, help="Encrypt the bundle")
def export(session_id: str, provider: str | None, output: str | None,
           include_git: bool, include_env: bool, encrypt: bool):
    """Export a session to a .stp bundle file."""
    prov, session = _find_session(session_id, provider)
    if not prov or not session:
        error(f"Session not found: {session_id}")
        raise SystemExit(1)

    # Build manifest
    manifest = Manifest(
        provider=prov.name,
        session_id=session.session_id,
        source_hostname=get_hostname(),
        source_platform=get_platform(),
        source_cwd=session.cwd,
        components=["session"],
    )

    builder = BundleBuilder(manifest)

    # Export session files
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

        # Tool versions
        version_files = capture_tool_versions()
        for path, content in version_files.items():
            builder.add_file(path, content)

    # Scan for secrets in conversation log
    try:
        conv_files = [f for f in builder._files if f.endswith(".jsonl")]
        for cf in conv_files:
            content = builder._files[cf].decode(errors="replace")
            if not warn_secrets_in_content(content):
                error("Export cancelled by user")
                raise SystemExit(1)
    except (UnicodeDecodeError, KeyError):
        pass

    # Encrypt
    passphrase = _prompt_passphrase(confirm=True) if encrypt else None

    # Build and save
    bundle_data = builder.build(passphrase)

    if not output:
        output = f"session-{session.session_id[:8]}.stp"
    save_bundle(bundle_data, Path(output))


@main.command("import")
@click.argument("bundle_path", type=click.Path(exists=True))
@click.option("--target-dir", "-t", type=click.Path(), default=None,
              help="Override working directory on this machine")
@click.option("--target-provider", "-tp", type=click.Choice(["claude", "codex"]),
              default=None, help="Convert to a different provider format")
@click.option("--apply-git/--no-apply-git", default=None,
              help="Apply git patches (default: prompt)")
@click.option("--dry-run", is_flag=True, help="Show what would be imported without writing")
@click.option("--passphrase", type=str, default=None, help="Decryption passphrase")
def import_session(bundle_path: str, target_dir: str | None, target_provider: str | None,
                   apply_git: bool | None, dry_run: bool, passphrase: str | None):
    """Import a session from a .stp bundle file."""
    data = load_bundle(Path(bundle_path))

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
            from .converters import get_converter
            converter = get_converter(manifest.provider, target_key)
            if not converter:
                error(f"No converter available from {manifest.provider} to {target_key}")
                raise SystemExit(1)
            reader = converter.convert(reader, target_dir)
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
            apply_git = click.confirm("Apply git patches from bundle?", default=False)
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


@main.command()
@click.argument("session_id")
@click.option("--provider", "-p", type=click.Choice(["claude", "codex"]), default=None)
@click.option("--method", "-m", type=click.Choice(["file", "peer", "relay"]), default="file")
@click.option("--host", type=str, default=None, help="Target host for peer transfer")
@click.option("--port", type=int, default=9876, help="Port for peer transfer")
@click.option("--relay-url", type=str, default=None, help="Relay server URL")
@click.option("--encrypt/--no-encrypt", default=True)
def send(session_id: str, provider: str | None, method: str,
         host: str | None, port: int, relay_url: str | None, encrypt: bool):
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
        console.print(f"\n[bold]Share this pickup code with the receiver: [yellow]{code}[/][/]")


@main.command()
@click.option("--method", "-m", type=click.Choice(["peer", "relay"]), default="peer")
@click.option("--port", type=int, default=9876, help="Port to listen on")
@click.option("--relay-url", type=str, default=None, help="Relay server URL")
@click.option("--code", type=str, default=None, help="Pickup code for relay")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save bundle to file")
@click.option("--auto-import", is_flag=True, help="Automatically import after receiving")
@click.option("--target-provider", "-tp", type=click.Choice(["claude", "codex"]),
              default=None, help="Convert to a different provider format")
@click.option("--passphrase", type=str, default=None)
def receive(method: str, port: int, relay_url: str | None, code: str | None,
            output: str | None, auto_import: bool, target_provider: str | None,
            passphrase: str | None):
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
                from .converters import get_converter
                converter = get_converter(manifest.provider, target_key)
                if not converter:
                    error(f"No converter available from {manifest.provider} to {target_key}")
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


@main.command("relay-server")
@click.option("--port", type=int, default=8765)
@click.option("--ttl", type=int, default=30, help="Bundle TTL in minutes")
def relay_server(port: int, ttl: int):
    """Start a relay server for indirect transfers."""
    from .transfer.relay import start_relay_server
    start_relay_server(port, ttl)


@main.command()
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

    # Show git state summary
    try:
        branch = reader.read_file("git/branch.txt").decode().strip()
        console.print(f"\n[bold]Git branch:[/] {branch}")
    except FileNotFoundError:
        pass

    try:
        status = reader.read_file("git/status.txt").decode()
        console.print(f"\n[bold]Git status:[/]\n{status}")
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


if __name__ == "__main__":
    main()

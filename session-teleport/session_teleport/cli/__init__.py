"""CLI entry point for session-teleport."""

from __future__ import annotations

import click

from ..core.bundle import BundleReader, is_bundle_encrypted
from ..providers.base import SessionProvider
from ..providers.claude_code import ClaudeCodeProvider
from ..providers.codex_cli import CodexCliProvider
from ..utils.display import error

PROVIDER_MAP: dict[str, type[SessionProvider]] = {
    "claude_code": ClaudeCodeProvider,
    "codex_cli": CodexCliProvider,
}

PROVIDER_KEY_MAP: dict[str, str] = {"claude": "claude_code", "codex": "codex_cli"}


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


def _convert_if_needed(
    reader: BundleReader, target_provider: str | None, target_dir: str | None = None,
) -> BundleReader:
    """Convert bundle to target provider format if needed. Returns original or converted reader."""
    if not target_provider:
        return reader
    target_key = PROVIDER_KEY_MAP[target_provider]
    if target_key == reader.manifest.provider:
        return reader
    from ..converters import get_converter

    converter = get_converter(reader.manifest.provider, target_key)
    if not converter:
        error(f"No converter available from {reader.manifest.provider} to {target_key}")
        raise SystemExit(1)
    return converter.convert(reader, target_dir)


@click.group()
@click.version_option()
def main():
    """Teleport Claude Code and Codex CLI sessions between machines."""


# Register all subcommands
from .export_cmd import export  # noqa: E402
from .import_cmd import import_session  # noqa: E402
from .inspect_cmd import inspect  # noqa: E402
from .list_cmd import list_sessions  # noqa: E402
from .receive_cmd import receive  # noqa: E402
from .relay_cmd import relay_server  # noqa: E402
from .send_cmd import send  # noqa: E402

main.add_command(list_sessions, "list")
main.add_command(export)
main.add_command(import_session, "import")
main.add_command(send)
main.add_command(receive)
main.add_command(relay_server, "relay-server")
main.add_command(inspect)

if __name__ == "__main__":
    main()

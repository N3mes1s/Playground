"""User-facing security warnings and confirmations."""

import click

from .secret_filter import scan_text_for_secrets
from ..utils.display import warning, console


def warn_secrets_in_content(content: str) -> bool:
    """Scan content for secrets and warn the user. Returns True if user confirms to proceed."""
    detections = scan_text_for_secrets(content)
    if not detections:
        return True

    warning("Potential secrets detected in session data:")
    for d in detections:
        console.print(f"  [yellow]- {d}[/]")

    return click.confirm(
        "Session data may contain sensitive information. Continue?",
        default=False,
    )


def warn_platform_mismatch(source: str, target: str) -> None:
    if source != target:
        warning(
            f"Platform mismatch: bundle from '{source}', importing on '{target}'. "
            "Absolute paths in session history may not resolve correctly."
        )


def warn_cwd_mismatch(source_cwd: str, target_cwd: str | None) -> None:
    if target_cwd and source_cwd != target_cwd:
        warning(
            f"Working directory differs: source was '{source_cwd}', "
            f"importing to '{target_cwd}'. Path references will be rewritten."
        )

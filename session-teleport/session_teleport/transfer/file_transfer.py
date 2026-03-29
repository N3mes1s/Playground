"""File-based transfer: export to and import from local .stp files."""

from __future__ import annotations

from pathlib import Path

from ..utils.display import info, success


def save_bundle(data: bytes, output_path: Path) -> None:
    """Save a bundle to a local file."""
    output_path.write_bytes(data)
    size_mb = len(data) / (1024 * 1024)
    success(f"Bundle saved to {output_path} ({size_mb:.2f} MB)")


def load_bundle(input_path: Path) -> bytes:
    """Load a bundle from a local file."""
    if not input_path.exists():
        raise FileNotFoundError(f"Bundle not found: {input_path}")
    data = input_path.read_bytes()
    size_mb = len(data) / (1024 * 1024)
    info(f"Loaded bundle from {input_path} ({size_mb:.2f} MB)")
    return data

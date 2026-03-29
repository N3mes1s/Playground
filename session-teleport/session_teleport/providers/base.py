"""Abstract base class for session providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from ..core.bundle import BundleBuilder, BundleReader


@dataclass
class SessionInfo:
    provider: str
    session_id: str
    cwd: str
    started_at: str
    pid: int | None = None
    extra: dict | None = None

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "session_id": self.session_id,
            "cwd": self.cwd,
            "started_at": self.started_at,
            "pid": self.pid,
        }


class SessionProvider(ABC):
    name: str
    base_dir: Path

    @abstractmethod
    def list_sessions(self) -> list[SessionInfo]:
        """Discover all available sessions."""
        ...

    @abstractmethod
    def export_session(self, session_id: str, builder: BundleBuilder) -> None:
        """Export session files into the bundle builder."""
        ...

    @abstractmethod
    def import_session(self, reader: BundleReader, target_dir: str | None = None) -> None:
        """Import session files from a bundle reader."""
        ...

    def is_available(self) -> bool:
        """Check if this provider's data directory exists."""
        return self.base_dir.exists()

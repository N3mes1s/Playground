"""Bundle creation and extraction for session teleport (.stp format).

A .stp bundle is a tar.gz archive containing:
  manifest.json        - bundle metadata
  session/             - provider-specific session files
  git/                 - git state (branch, patches, etc.)
  env/                 - environment snapshot
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

from .manifest import Manifest
from .crypto import encrypt_bundle, decrypt_bundle


class BundleBuilder:
    """Incrementally build a session teleport bundle."""

    def __init__(self, manifest: Manifest):
        self.manifest = manifest
        self._files: dict[str, bytes] = {}

    def add_file(self, archive_path: str, content: bytes) -> None:
        """Add a file to the bundle."""
        self._files[archive_path] = content

    def add_directory_tree(self, archive_prefix: str, local_path: Path) -> int:
        """Recursively add a local directory tree. Returns number of files added."""
        count = 0
        if not local_path.exists():
            return 0
        for file in local_path.rglob("*"):
            if file.is_file():
                rel = file.relative_to(local_path)
                self._files[f"{archive_prefix}/{rel}"] = file.read_bytes()
                count += 1
        return count

    def build(self, passphrase: str | None = None) -> bytes:
        """Build the final .stp bundle as bytes.

        If passphrase is provided, the bundle is encrypted.
        """
        tar_bytes = self._create_tar()

        self.manifest.bundle_checksum = hashlib.sha256(tar_bytes).hexdigest()
        self.manifest.encrypted = passphrase is not None

        # Rebuild tar with final manifest (checksum now set)
        tar_bytes = self._create_tar()

        if passphrase:
            return encrypt_bundle(tar_bytes, passphrase)
        return tar_bytes

    def _create_tar(self) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            # Add manifest
            manifest_data = self.manifest.to_json().encode()
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest_data)
            tar.addfile(info, io.BytesIO(manifest_data))

            # Add all collected files
            for path, content in sorted(self._files.items()):
                info = tarfile.TarInfo(name=path)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))

        return buf.getvalue()


class BundleReader:
    """Read and extract a session teleport bundle."""

    def __init__(self, data: bytes, passphrase: str | None = None):
        if passphrase:
            data = decrypt_bundle(data, passphrase)

        self._data = data
        self._tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
        self.manifest = self._read_manifest()

    def _read_manifest(self) -> Manifest:
        member = self._tar.getmember("manifest.json")
        f = self._tar.extractfile(member)
        if f is None:
            raise ValueError("Bundle missing manifest.json")
        return Manifest.from_json(f.read().decode())

    def list_files(self) -> list[str]:
        return [m.name for m in self._tar.getmembers() if m.isfile()]

    def read_file(self, path: str) -> bytes:
        try:
            f = self._tar.extractfile(path)
        except KeyError:
            raise FileNotFoundError(f"File not found in bundle: {path}")
        if f is None:
            raise FileNotFoundError(f"File not found in bundle: {path}")
        return f.read()

    def extract_prefix(self, prefix: str, target_dir: Path) -> int:
        """Extract all files under a prefix to a target directory. Returns count."""
        count = 0
        for member in self._tar.getmembers():
            if member.isfile() and member.name.startswith(prefix + "/"):
                rel_path = member.name[len(prefix) + 1:]
                target = target_dir / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                f = self._tar.extractfile(member)
                if f:
                    target.write_bytes(f.read())
                    count += 1
        return count

    def read_json(self, path: str) -> dict:
        return json.loads(self.read_file(path).decode())

    def close(self):
        self._tar.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

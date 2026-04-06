"""Tests for CLI receive command."""

import json
import threading
import urllib.request
from http.server import HTTPServer
from pathlib import Path

from click.testing import CliRunner

from session_teleport.cli import main
from session_teleport.core.bundle import BundleBuilder
from session_teleport.core.manifest import Manifest
from session_teleport.transfer.relay import RelayHandler, _bundles

runner = CliRunner()


def test_cli_receive_relay_missing_args():
    result = runner.invoke(main, ["receive", "--method", "relay"])
    assert result.exit_code == 1


def test_cli_receive_relay_with_output(tmp_path, monkeypatch):
    """Test receive relay that downloads and saves to file."""
    server = HTTPServer(("127.0.0.1", 0), RelayHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        bundle_data = b"test-receive-bundle"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/bundle", data=bundle_data, method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            code = json.loads(resp.read())["code"]

        output_path = str(tmp_path / "received.stp")
        result = runner.invoke(main, [
            "receive", "--method", "relay",
            "--relay-url", f"http://127.0.0.1:{port}",
            "--code", code,
            "--output", output_path,
        ])
        assert result.exit_code == 0
        assert Path(output_path).read_bytes() == bundle_data
    finally:
        server.shutdown()
        _bundles.clear()


def test_cli_receive_relay_no_output(tmp_path, monkeypatch):
    """Receive relay without --output saves to default file."""
    server = HTTPServer(("127.0.0.1", 0), RelayHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        bundle_data = b"test-receive-default"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/bundle", data=bundle_data, method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            code = json.loads(resp.read())["code"]

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(main, [
            "receive", "--method", "relay",
            "--relay-url", f"http://127.0.0.1:{port}",
            "--code", code,
        ])
        assert result.exit_code == 0
        assert (tmp_path / "received-session.stp").read_bytes() == bundle_data
    finally:
        server.shutdown()
        _bundles.clear()


def test_cli_receive_relay_auto_import(tmp_path, monkeypatch):
    """Receive via relay with --auto-import flag."""
    server = HTTPServer(("127.0.0.1", 0), RelayHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        manifest = Manifest(
            provider="claude_code",
            session_id="auto-import-test",
            source_cwd=str(tmp_path / "src"),
        )
        builder = BundleBuilder(manifest)
        builder.add_file("session/sessions/1.json", json.dumps({
            "pid": 1, "sessionId": "auto-import-test",
            "cwd": str(tmp_path / "src"), "startedAt": "2025-01-01",
        }).encode())
        bundle_data = builder.build()

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/bundle", data=bundle_data, method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            code = json.loads(resp.read())["code"]

        import_dir = tmp_path / "import-claude"
        monkeypatch.setattr(
            "session_teleport.providers.claude_code.get_claude_dir",
            lambda: import_dir,
        )

        result = runner.invoke(main, [
            "receive", "--method", "relay",
            "--relay-url", f"http://127.0.0.1:{port}",
            "--code", code,
            "--auto-import",
        ])
        assert result.exit_code == 0
        assert "imported" in result.output.lower()
    finally:
        server.shutdown()
        _bundles.clear()


def test_cli_receive_peer_method(tmp_path, monkeypatch):
    """Receive via peer with mocked receive_from_peer."""
    bundle_data = b"mock-peer-bundle"

    async def mock_receive(port):
        return bundle_data

    monkeypatch.setattr(
        "session_teleport.cli.receive_cmd.receive_from_peer", mock_receive
    )
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(main, [
        "receive", "--method", "peer", "--port", "9999",
        "--output", str(tmp_path / "peer.stp"),
    ])
    assert result.exit_code == 0
    assert (tmp_path / "peer.stp").read_bytes() == bundle_data

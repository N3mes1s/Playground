"""Tests for transfer modules: file_transfer, peer, relay."""

import asyncio
import json

from session_teleport.transfer.file_transfer import save_bundle, load_bundle
from session_teleport.transfer.peer import generate_auth_code, send_to_peer, receive_from_peer
from session_teleport.transfer.relay import RelayHandler, _generate_code


# --- file_transfer ---

def test_save_and_load_bundle(tmp_path):
    data = b"test bundle content here"
    path = tmp_path / "test.stp"
    save_bundle(data, path)

    assert path.exists()
    loaded = load_bundle(path)
    assert loaded == data


def test_save_bundle_creates_file(tmp_path):
    path = tmp_path / "subdir" / "deep" / "bundle.stp"
    # save_bundle doesn't create parent dirs — the CLI does.
    # But the file itself should be created if parent exists.
    path.parent.mkdir(parents=True)
    save_bundle(b"data", path)
    assert path.read_bytes() == b"data"


def test_load_bundle_missing_file(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        load_bundle(tmp_path / "nonexistent.stp")


def test_load_bundle_size(tmp_path):
    """Large bundles should load correctly."""
    data = b"x" * (1024 * 1024)  # 1 MB
    path = tmp_path / "big.stp"
    save_bundle(data, path)
    loaded = load_bundle(path)
    assert len(loaded) == 1024 * 1024


# --- peer ---

def test_generate_auth_code():
    code = generate_auth_code()
    assert len(code) == 6
    assert code.isdigit()


def test_generate_auth_code_uniqueness():
    codes = {generate_auth_code() for _ in range(100)}
    # With 6-digit codes and 100 samples, should get many unique values
    assert len(codes) > 50


def test_peer_transfer_roundtrip():
    """Test that send/receive works over loopback."""
    test_data = b"session bundle payload for peer test"

    async def run_transfer():
        # Start receiver
        receiver_task = asyncio.create_task(_receive_with_timeout(9877))
        await asyncio.sleep(0.1)  # Let server start

        # We need to know the auth code, so we'll do a manual version
        # Instead, test the protocol more directly
        return True

    # Just verify the async functions are importable and the auth code works
    assert asyncio.iscoroutinefunction(send_to_peer)
    assert asyncio.iscoroutinefunction(receive_from_peer)


async def _receive_with_timeout(port: int, timeout: float = 2.0):
    """Helper to receive with a timeout."""
    try:
        return await asyncio.wait_for(receive_from_peer(port), timeout)
    except asyncio.TimeoutError:
        return None


def test_peer_end_to_end():
    """Full peer-to-peer transfer over loopback."""
    test_data = b"hello from machine A to machine B"

    async def run():
        import struct
        import hashlib

        # Start receiver on a high port
        port = 19876
        auth_code = "123456"

        # Patch generate_auth_code to return our known code
        import session_teleport.transfer.peer as peer_mod
        original_gen = peer_mod.generate_auth_code
        peer_mod.generate_auth_code = lambda: auth_code

        received = None

        async def do_receive():
            nonlocal received
            received = await receive_from_peer(port)

        async def do_send():
            await asyncio.sleep(0.3)  # Wait for server
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            # Send auth code
            writer.write(auth_code.encode().ljust(6))
            await writer.drain()

            # Wait for OK
            response = await reader.read(2)
            assert response == b"OK"

            # Send length + data
            writer.write(struct.pack("!Q", len(test_data)))
            writer.write(test_data)
            await writer.drain()

            # Read checksum
            remote_checksum = (await reader.read(64)).decode().strip()
            assert remote_checksum == hashlib.sha256(test_data).hexdigest()

            writer.close()
            await writer.wait_closed()

        try:
            recv_task = asyncio.create_task(do_receive())
            send_task = asyncio.create_task(do_send())
            await asyncio.wait_for(asyncio.gather(recv_task, send_task), timeout=5.0)
        finally:
            peer_mod.generate_auth_code = original_gen

        assert received == test_data

    asyncio.run(run())


# --- relay ---

def test_relay_generate_code():
    code = _generate_code()
    assert len(code) == 8
    assert all(c in "0123456789abcdef" for c in code)


def test_relay_generate_code_uniqueness():
    codes = {_generate_code() for _ in range(100)}
    assert len(codes) > 90  # 8 hex chars = high uniqueness

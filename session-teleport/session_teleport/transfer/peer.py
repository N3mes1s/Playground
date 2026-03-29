"""Direct peer-to-peer TCP transfer with authentication."""

from __future__ import annotations

import asyncio
import hashlib
import os
import struct

from ..utils.display import console, create_progress, error, info, success

DEFAULT_PORT = 9876
AUTH_CODE_LENGTH = 6
CHUNK_SIZE = 64 * 1024  # 64 KB
RECEIVE_TIMEOUT = 300  # 5 minutes


def generate_auth_code() -> str:
    """Generate a random 6-digit authentication code."""
    return str(int.from_bytes(os.urandom(4), "big") % 1_000_000).zfill(AUTH_CODE_LENGTH)


async def send_to_peer(
    data: bytes, host: str, port: int = DEFAULT_PORT, auth_code: str = ""
) -> None:
    """Connect to a receiving peer and send a bundle."""
    reader, writer = await asyncio.open_connection(host, port)
    info(f"Connected to {host}:{port}")

    try:
        # Send auth code
        writer.write(auth_code.encode().ljust(AUTH_CODE_LENGTH))
        await writer.drain()

        # Wait for auth response
        response = await reader.read(2)
        if response != b"OK":
            raise ConnectionError("Authentication failed - wrong code")

        # Send data length + data
        writer.write(struct.pack("!Q", len(data)))
        writer.write(data)
        await writer.drain()

        # Wait for checksum confirmation
        remote_checksum = (await reader.read(64)).decode().strip()
        local_checksum = hashlib.sha256(data).hexdigest()
        if remote_checksum != local_checksum:
            raise ValueError("Checksum mismatch after transfer")

        success("Transfer complete and verified")
    finally:
        writer.close()
        await writer.wait_closed()


async def receive_from_peer(port: int = DEFAULT_PORT) -> bytes:
    """Listen for an incoming bundle transfer. Returns the received data."""
    auth_code = generate_auth_code()
    received_data: bytes = b""
    done_event = asyncio.Event()

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        nonlocal received_data
        try:
            # Verify auth code
            code = (await reader.readexactly(AUTH_CODE_LENGTH)).decode().strip()
            if code != auth_code:
                writer.write(b"NO")
                await writer.drain()
                error("Authentication failed")
                return

            writer.write(b"OK")
            await writer.drain()

            # Read data length
            length_bytes = await reader.readexactly(8)
            length = struct.unpack("!Q", length_bytes)[0]
            info(f"Receiving {length / (1024*1024):.2f} MB...")

            # Read data in chunks
            chunks = []
            remaining = length
            with create_progress() as progress:
                task = progress.add_task("Receiving", total=length)
                while remaining > 0:
                    chunk_size = min(remaining, CHUNK_SIZE)
                    chunk = await reader.read(chunk_size)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                    progress.update(task, advance=len(chunk))

            received_data = b"".join(chunks)

            # Send checksum
            checksum = hashlib.sha256(received_data).hexdigest()
            writer.write(checksum.encode().ljust(64))
            await writer.drain()

            success("Transfer complete and verified")
        finally:
            writer.close()
            await writer.wait_closed()
            done_event.set()

    server = await asyncio.start_server(handle_client, "0.0.0.0", port)
    console.print(f"\n[bold cyan]Waiting for connection on port {port}[/]")
    console.print(f"[bold yellow]Authentication code: {auth_code}[/]")
    console.print("Share this code with the sender.\n")

    async with server:
        await server.start_serving()
        try:
            await asyncio.wait_for(done_event.wait(), timeout=RECEIVE_TIMEOUT)
        except asyncio.TimeoutError:
            raise ConnectionError(
                f"No connection received within {RECEIVE_TIMEOUT} seconds"
            ) from None

    return received_data

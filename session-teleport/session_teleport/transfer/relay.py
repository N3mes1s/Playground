"""HTTP relay for transferring bundles through a middleman server.

The relay server stores encrypted bundles temporarily with a one-time pickup code.
This enables transfer even when machines can't connect directly (NAT, firewalls).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

from ..utils.display import info, success, error, console

DEFAULT_TTL_MINUTES = 30

# In-memory store for the relay server
_bundles: dict[str, dict] = {}


def _generate_code() -> str:
    return hashlib.sha256(os.urandom(32)).hexdigest()[:8]


class RelayHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for the relay server."""

    def do_POST(self):
        if self.path == "/bundle":
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length)
            code = _generate_code()
            _bundles[code] = {
                "data": data,
                "created": time.time(),
                "ttl": DEFAULT_TTL_MINUTES * 60,
            }
            # Clean up expired bundles
            now = time.time()
            expired = [k for k, v in _bundles.items() if now - v["created"] > v["ttl"]]
            for k in expired:
                del _bundles[k]

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"code": code}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path.startswith("/bundle/"):
            code = self.path.split("/")[-1]
            if code in _bundles:
                data = _bundles.pop(code)["data"]  # Single-use
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Bundle not found or already retrieved")
        elif self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        info(f"[relay] {format % args}")


def start_relay_server(port: int = 8765, ttl_minutes: int = DEFAULT_TTL_MINUTES) -> None:
    """Start the relay server (blocking)."""
    global DEFAULT_TTL_MINUTES
    DEFAULT_TTL_MINUTES = ttl_minutes

    server = HTTPServer(("0.0.0.0", port), RelayHandler)
    console.print(f"[bold cyan]Relay server running on port {port}[/]")
    console.print(f"[dim]Bundles expire after {ttl_minutes} minutes. Ctrl+C to stop.[/]")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\nShutting down relay server.")
        server.shutdown()


async def upload_to_relay(data: bytes, relay_url: str) -> str:
    """Upload a bundle to the relay server. Returns the pickup code."""
    import urllib.request
    import urllib.error

    req = urllib.request.Request(
        f"{relay_url.rstrip('/')}/bundle",
        data=data,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read().decode())
            code = result["code"]
            success(f"Bundle uploaded to relay. Pickup code: {code}")
            return code
    except urllib.error.URLError as e:
        raise ConnectionError(f"Failed to upload to relay: {e}")


async def download_from_relay(relay_url: str, code: str) -> bytes:
    """Download a bundle from the relay server using the pickup code."""
    import urllib.request
    import urllib.error

    url = f"{relay_url.rstrip('/')}/bundle/{code}"
    try:
        with urllib.request.urlopen(url) as resp:
            data = resp.read()
            success(f"Bundle downloaded from relay ({len(data) / (1024*1024):.2f} MB)")
            return data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise ValueError("Bundle not found - code may be invalid or already used")
        raise ConnectionError(f"Failed to download from relay: {e}")

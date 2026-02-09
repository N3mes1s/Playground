"""
Monkey-patches grpclib to tunnel gRPC through an HTTP CONNECT proxy
and use the system CA bundle instead of certifi (for MITM proxy CAs).

Usage:
    import proxy_patch  # must be imported before using modal
    import modal
"""

import asyncio
import base64
import os
import socket
import ssl as _ssl_mod
import urllib.parse

SYSTEM_CA_FILE = "/etc/ssl/certs/ca-certificates.crt"


def _get_proxy_info():
    proxy_url = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy", "")
    if not proxy_url:
        return None
    parsed = urllib.parse.urlparse(proxy_url)
    auth = None
    if parsed.username:
        cred = f"{parsed.username}:{parsed.password or ''}"
        auth = base64.b64encode(cred.encode()).decode()
    return parsed.hostname, parsed.port, auth


def _create_tunnel_sync(target_host, target_port, proxy_info):
    """Create a raw TCP socket tunneled through an HTTP CONNECT proxy."""
    proxy_host, proxy_port, proxy_auth = proxy_info
    sock = socket.create_connection((proxy_host, proxy_port), timeout=30)
    req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    if proxy_auth:
        req += f"Proxy-Authorization: Basic {proxy_auth}\r\n"
    req += "\r\n"
    sock.sendall(req.encode())

    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Proxy closed connection during CONNECT")
        resp += chunk

    status_line = resp.split(b"\r\n")[0]
    if b"200" not in status_line:
        sock.close()
        raise ConnectionError(f"CONNECT failed: {status_line.decode()}")

    return sock


_proxy_info = _get_proxy_info()

if _proxy_info:
    import grpclib.client
    from grpclib.protocol import H2Protocol

    # --- Patch 1: SSL context uses system CA bundle (has the MITM CA) ---
    _orig_get_default_ssl_context = grpclib.client.Channel._get_default_ssl_context

    def _patched_get_default_ssl_context(self, *, verify_paths=None):
        cafile = SYSTEM_CA_FILE if os.path.exists(SYSTEM_CA_FILE) else None
        ctx = _ssl_mod.create_default_context(
            purpose=_ssl_mod.Purpose.SERVER_AUTH,
            cafile=cafile,
        )
        ctx.minimum_version = _ssl_mod.TLSVersion.TLSv1_2
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
        ctx.set_alpn_protocols(["h2"])
        return ctx

    grpclib.client.Channel._get_default_ssl_context = _patched_get_default_ssl_context

    # --- Patch 2: _create_connection routes through HTTP CONNECT proxy ---
    _orig_create_connection = grpclib.client.Channel._create_connection

    async def _patched_create_connection(self) -> H2Protocol:
        """Route TCP connections through the HTTP CONNECT proxy."""
        if self._path is not None:
            return await _orig_create_connection(self)

        target_host = self._host
        target_port = self._port

        loop = self._loop
        sock = await loop.run_in_executor(
            None, _create_tunnel_sync, target_host, target_port, _proxy_info
        )

        ssl_arg = self._ssl
        server_hostname = None
        if ssl_arg is not None:
            server_hostname = (
                self._config.ssl_target_name_override
                if self._config and self._config.ssl_target_name_override
                else target_host
            )

        _, protocol = await loop.create_connection(
            self._protocol_factory,
            ssl=ssl_arg,
            sock=sock,
            server_hostname=server_hostname,
        )
        return protocol

    grpclib.client.Channel._create_connection = _patched_create_connection
    print(f"[proxy_patch] Patched grpclib: proxy={_proxy_info[0]}:{_proxy_info[1]}, ca={SYSTEM_CA_FILE}")
else:
    print("[proxy_patch] No HTTPS_PROXY set, no patching needed")

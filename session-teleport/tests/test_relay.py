"""Tests for the relay server and client (upload/download)."""

import asyncio
import json
import threading
import urllib.error
import urllib.request

import pytest

from session_teleport.transfer.relay import (
    RelayHandler,
    _bundles,
    download_from_relay,
    upload_to_relay,
)


@pytest.fixture()
def relay_server():
    """Start a relay server on a random port in a background thread."""
    from http.server import HTTPServer

    server = HTTPServer(("127.0.0.1", 0), RelayHandler)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield url, server
    server.shutdown()
    _bundles.clear()


def test_relay_health(relay_server):
    url, _ = relay_server
    with urllib.request.urlopen(f"{url}/health") as resp:
        assert resp.read() == b"OK"


def test_relay_post_and_get_bundle(relay_server):
    url, _ = relay_server
    payload = b"test-bundle-data"

    # POST
    req = urllib.request.Request(f"{url}/bundle", data=payload, method="POST")
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
        code = result["code"]
    assert len(code) == 8

    # GET (single-use)
    with urllib.request.urlopen(f"{url}/bundle/{code}") as resp:
        data = resp.read()
    assert data == payload

    # Second GET should 404
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{url}/bundle/{code}")
    assert exc_info.value.code == 404


def test_relay_get_unknown_code(relay_server):
    url, _ = relay_server
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{url}/bundle/nonexistent")
    assert exc_info.value.code == 404


def test_relay_post_unknown_path(relay_server):
    url, _ = relay_server
    req = urllib.request.Request(f"{url}/unknown", data=b"x", method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 404


def test_relay_get_unknown_path(relay_server):
    url, _ = relay_server
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{url}/unknown")
    assert exc_info.value.code == 404


def test_relay_log_message(relay_server):
    """log_message should not crash."""
    url, _ = relay_server
    # Just make a request; the handler's log_message will be called
    urllib.request.urlopen(f"{url}/health")


def test_upload_to_relay(relay_server):
    url, _ = relay_server
    code = asyncio.run(upload_to_relay(b"upload-test-data", url))
    assert len(code) == 8

    # Verify we can fetch it
    with urllib.request.urlopen(f"{url}/bundle/{code}") as resp:
        assert resp.read() == b"upload-test-data"


def test_download_from_relay(relay_server):
    url, _ = relay_server

    # Upload first
    req = urllib.request.Request(f"{url}/bundle", data=b"download-test", method="POST")
    with urllib.request.urlopen(req) as resp:
        code = json.loads(resp.read())["code"]

    data = asyncio.run(download_from_relay(url, code))
    assert data == b"download-test"


def test_download_from_relay_invalid_code(relay_server):
    url, _ = relay_server
    with pytest.raises(ValueError, match="not found"):
        asyncio.run(download_from_relay(url, "badcode1"))


def test_upload_to_relay_bad_url():
    with pytest.raises(ConnectionError):
        asyncio.run(upload_to_relay(b"data", "http://127.0.0.1:1"))


def test_download_from_relay_bad_url():
    with pytest.raises((ConnectionError, ValueError)):
        asyncio.run(download_from_relay("http://127.0.0.1:1", "code"))

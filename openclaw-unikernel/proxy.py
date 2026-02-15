#!/usr/bin/env python3
"""Simple HTTP-to-HTTPS forwarding proxy for OpenClaw unikernel.

Listens on port 8080 for plain HTTP from the QEMU guest,
forwards requests to the target host over HTTPS.
"""
import http.server
import urllib.request
import ssl
import sys
import traceback

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stderr.write("[proxy] %s\n" % (format % args))

    def _proxy(self):
        # Read body if present
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length > 0 else None

        # Get the target host from the Host header
        host = self.headers.get('Host', 'api.openai.com')
        url = f'https://{host}{self.path}'

        self.log_message("-> %s %s", self.command, url)

        # Build forwarded request
        headers = {}
        for key, value in self.headers.items():
            if key.lower() not in ('host', 'connection', 'transfer-encoding'):
                headers[key] = value
        headers['Host'] = host

        req = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method=self.command
        )

        # Disable SSL verification for simplicity
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                resp_body = resp.read()
                self.send_response(resp.status)
                # Forward response headers
                for key, value in resp.headers.items():
                    if key.lower() not in ('transfer-encoding', 'connection'):
                        self.send_header(key, value)
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(resp_body)
                self.log_message("<- %d (%d bytes)", resp.status, len(resp_body))
        except urllib.error.HTTPError as e:
            resp_body = e.read()
            self.send_response(e.code)
            for key, value in e.headers.items():
                if key.lower() not in ('transfer-encoding', 'connection'):
                    self.send_header(key, value)
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(resp_body)
            self.log_message("<- %d (%d bytes)", e.code, len(resp_body))
        except Exception as e:
            tb = traceback.format_exc()
            self.log_message("ERROR: %s", tb)
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(f"Proxy error: {e}".encode())

    do_GET = _proxy
    do_POST = _proxy
    do_PUT = _proxy
    do_DELETE = _proxy
    do_PATCH = _proxy

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = http.server.HTTPServer(('0.0.0.0', port), ProxyHandler)
    print(f"[proxy] listening on 0.0.0.0:{port}", file=sys.stderr)
    server.serve_forever()

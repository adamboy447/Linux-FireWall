"""Lab service: HTTPS (or plain HTTP) that reports which client address it saw.

GET /          -> {"service": NAME, "client": "ip:port", "time": ...}
GET /bytes?n=N -> N bytes of a known pattern (transfer tests)

Seeing the client address on the server side is the evidence for NAT: the
WAN server must see the gateway's outside address (SNAT), and the DMZ server
must see the real WAN client (DNAT keeps the source).
"""
from __future__ import annotations

import argparse
import json
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PATTERN = bytes(range(256))


def make_handler(name: str):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 15          # a peer that vanished (e.g. its NAT session was reset) frees the thread

        def log_message(self, fmt, *args):
            print(json.dumps({"service": name, "client": "%s:%d" % self.client_address,
                              "request": self.requestline, "time": time.time()}), flush=True)

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/bytes":
                n = min(int(parse_qs(u.query).get("n", ["0"])[0]), 512 * 1024 * 1024)
                self.send_response(200)
                self.send_header("Content-Length", str(n))
                self.end_headers()
                full, rest = divmod(n, len(PATTERN))
                for _ in range(full):
                    self.wfile.write(PATTERN)
                self.wfile.write(PATTERN[:rest])
                return
            body = json.dumps({"service": name, "client": "%s:%d" % self.client_address,
                               "time": time.time()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return H


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    a = ap.parse_args(argv)
    ctx = None
    if a.cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.cert, a.key)

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 128

        def finish_request(self, request, client_address):
            # TLS handshake runs in the per-connection thread, never in the accept loop,
            # so one stalled client cannot stop the service from accepting others.
            if ctx is not None:
                request.settimeout(15)
                try:
                    request = ctx.wrap_socket(request, server_side=True)
                except (OSError, ssl.SSLError):
                    request.close()
                    return
            super().finish_request(request, client_address)

    Server(("0.0.0.0", a.port), make_handler(a.name)).serve_forever()


if __name__ == "__main__":
    main()

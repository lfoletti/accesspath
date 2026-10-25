"""Serveur HTTP local (127.0.0.1, port libre) pour les tests du moteur SAP.

Chaque route est une fonction `handler(req) -> None` qui écrit la réponse.
Aucun accès réseau : tout reste sur la boucle locale.
"""

from __future__ import annotations

import gzip
import threading
import time
import zlib
from collections import Counter
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MiB = 1 << 20


def _send(req, status: int, body: bytes, headers: dict | None = None) -> None:
    req.send_response(status)
    for k, v in (headers or {}).items():
        req.send_header(k, v)
    req.send_header("Content-Length", str(len(body)))
    req.end_headers()
    try:
        req.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        pass


def body(status: int, payload: bytes, **headers) -> Callable:
    hdrs = {k.replace("_", "-"): v for k, v in headers.items()}
    return lambda req: _send(req, status, payload, hdrs)


def gzip_bomb(size: int = 64 * MiB) -> Callable:
    data = gzip.compress(b"\0" * size, 9)
    return body(200, data, Content_Type="text/html", Content_Encoding="gzip")


def deflate_bomb(size: int = 64 * MiB) -> Callable:
    data = zlib.compress(b"\0" * size, 9)
    return body(200, data, Content_Type="text/html", Content_Encoding="deflate")


def br_bomb(size: int = 64 * MiB) -> Callable:
    import brotli

    data = brotli.compress(b"\0" * size, quality=5)
    return body(200, data, Content_Type="text/html", Content_Encoding="br")


def huge(size: int = 12 * MiB) -> Callable:
    """Corps non compressé plus gros que la limite sur le fil (en flux, sans Content-Length)."""

    def _h(req):
        req.send_response(200)
        req.send_header("Content-Type", "text/html")
        req.send_header("Connection", "close")
        req.end_headers()
        chunk = b"a" * 65536
        sent = 0
        try:
            while sent < size:
                req.wfile.write(chunk)
                sent += len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass

    return _h


def slow(seconds: float, status: int = 404, payload: bytes = b"") -> Callable:
    """Répond après `seconds` secondes (pour mesurer la concurrence côté serveur)."""

    def _h(req):
        time.sleep(seconds)
        _send(req, status, payload, {"Content-Type": "text/plain"})

    return _h


def drip(seconds: float = 20.0, interval: float = 0.2) -> Callable:
    """En-têtes tout de suite, puis un octet toutes les `interval` secondes."""

    def _h(req):
        req.send_response(200)
        req.send_header("Content-Type", "text/html")
        req.send_header("Connection", "close")
        req.end_headers()
        end = time.monotonic() + seconds
        try:
            while time.monotonic() < end:
                req.wfile.write(b"a")
                req.wfile.flush()
                time.sleep(interval)
        except (BrokenPipeError, ConnectionResetError):
            pass

    return _h


class LocalServer:
    def __init__(self, routes: dict[str, Callable]):
        self.routes = dict(routes)
        self.hits: Counter = Counter()
        self.log: list[str] = []
        self.times: list[tuple[str, float]] = []
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()
        server = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):  # noqa: N802
                path = self.path
                with server._lock:
                    server.hits[path] += 1
                    server.log.append(path)
                    server.times.append((path, time.monotonic()))
                    server.active += 1
                    server.max_active = max(server.max_active, server.active)
                try:
                    fn = server.routes.get(path) or server.routes.get(path.split("?", 1)[0]) or server.routes.get("*")
                    if fn is None:
                        _send(self, 404, b"not found", {"Content-Type": "text/plain"})
                    else:
                        fn(self)
                finally:
                    with server._lock:
                        server.active -= 1

            do_POST = do_GET  # noqa: N815 — le corps se lit dans le gestionnaire (req.rfile)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def url(self, path: str) -> str:
        return self.base + path

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

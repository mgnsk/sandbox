"""Shared test infra for the scripts in src/.

They have no .py extension and hyphenated names, so they
can't be `import`ed normally - load_module() imports one by file path instead.
"""

import base64
import http.client
import importlib.machinery
import importlib.util
import json
import socket
import ssl
import sys
import threading
from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent.parent / "src"

# What sys.path[0] is when a guard runs as a script: its guard_popup import.
sys.path.insert(0, str(BIN_DIR))


def load_module(filename):
    """Import a src/<filename> script as a module and return it.

    Registered in sys.modules under a name derived from the filename before
    exec_module runs, since dbus_fast's service decorators resolve type-hint
    strings against the module. The scripts' `if __name__ == "__main__":`
    guards mean main() never runs as a side effect of this import.
    """
    path = BIN_DIR / filename
    module_name = filename.replace("-", "_")
    # spec_from_file_location can't infer a loader for an extension-less
    # file, so hand it a SourceFileLoader explicitly.
    loader = importlib.machinery.SourceFileLoader(module_name, str(path))
    spec = importlib.util.spec_from_file_location(module_name, path, loader=loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class FakeProxy:
    """Unix-socket HTTP server recording each request and answering with JSON,
    standing in for an API proxy in the client patch tests."""

    def __init__(self, path, response):
        self.requests = []
        self._response = json.dumps(response).encode()
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(path))
        self._server.listen(8)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self._server.accept()
            except OSError:
                return
            with conn:
                self._handle(conn)

    def _handle(self, conn):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                return
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        length = int(headers.get("content-length", "0"))
        while len(body) < length:
            body += conn.recv(65536)
        self.requests.append({"line": lines[0], "headers": headers, "body": body})
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n"
            + f"Content-Length: {len(self._response)}\r\nConnection: close\r\n\r\n".encode()
            + self._response
        )

    def close(self):
        self._server.close()


# -- HTTPS-intercepting proxies -------------------------------------------------


def serve(server):
    """Run a socketserver in a daemon thread; returns it."""
    threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
    return server


def connect(server, target, auth=True):
    """A socket CONNECTed through an api_proxy.HttpsProxyServer to target
    ("host:port"), and the proxy's status line and headers. auth: send its
    secret (True), nothing (False) or this Proxy-Authorization value."""
    sock = socket.create_connection(server.server_address[:2], timeout=10)
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    if auth is True:
        token = base64.b64encode(f"sandbox:{server.secret}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    elif auth:
        lines.append(f"Proxy-Authorization: {auth}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    head = b""
    while b"\r\n\r\n" not in head:
        byte = sock.recv(1)
        if not byte:
            break
        head += byte
    return sock, head.decode("latin-1")


def tls_wrap(sock, server, hostname):
    """sock wrapped in TLS, trusting only server's CA."""
    ctx = ssl.create_default_context(cadata=server.ca.pem().decode())
    return ctx.wrap_socket(sock, server_hostname=hostname)


def https_send(server, target, raw):
    """raw sent inside a CONNECT tunnel to target, intercepted by server;
    returns (status, headers, body)."""
    sock, head = connect(server, target)
    assert " 200 " in head.split("\r\n", 1)[0], head
    tls = tls_wrap(sock, server, target.rsplit(":", 1)[0])
    try:
        tls.sendall(raw)
        method = raw.split(b" ", 1)[0].decode()
        response = http.client.HTTPResponse(tls, method=method)
        response.begin()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        tls.close()

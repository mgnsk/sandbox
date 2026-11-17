"""Shared test infra for the scripts in src/.

They have no .py extension and hyphenated names, so they
can't be `import`ed normally - load_module() imports one by file path instead.
"""

import importlib.machinery
import importlib.util
import json
import socket
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

"""Black-box harness for the guards: each runs as the program the launcher
starts, `GUARD ARGS...`, and is judged by what it does on its sockets, what
it asks in popups and what reaches the stand-ins for the real services.

- Popups: $SANDBOX_POPUP_SOCKET points at a FakePopups, which records each
  {"name", "text"} request and answers as told.
- The API proxies' real hosts: $SANDBOX_TEST_UPSTREAM sends their upstream
  connections to an Upstream, which serves TLS for every host name with a
  certificate from a FakeCA their $SSL_CERT_FILE trusts.
"""

import base64
import datetime
import http.client
import ipaddress
import json
import os
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from conftest import BIN_DIR
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def guard_argv(name, *args):
    """The program name with args, as the launcher starts it."""
    return [str(BIN_DIR / name), *map(str, args)]


def short_dir():
    """A fresh directory with a short path: unix socket paths are limited to
    108 bytes, which pytest's tmp_path can exceed."""
    return Path(tempfile.mkdtemp(prefix="g-"))


def base_env(**extra):
    """A clean environment for a guard: nothing of the test runner's but
    PATH and coverage."""
    env = {
        "PATH": os.environ["PATH"],
        "HOME": "/nonexistent",
        **{k: v for k, v in os.environ.items() if k == "GOCOVERDIR"},
    }
    env.update({k: str(v) for k, v in extra.items() if v is not None})
    return env


class Guard:
    """A running guard; stopped with SIGTERM, as the launcher does."""

    def __init__(self, name, *args, env=None, ready=None, cwd=None, timeout=10):
        self.name = name
        self.proc = subprocess.Popen(
            guard_argv(name, *args),
            env=env or base_env(),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if ready is not None:
            deadline = time.monotonic() + timeout
            while not os.path.exists(ready):
                if self.proc.poll() is not None:
                    raise AssertionError(f"{name} exited: {self.proc.stderr.read()}")
                if time.monotonic() > deadline:
                    self.stop()
                    raise AssertionError(f"{name} didn't create {ready}")
                time.sleep(0.02)

    def stop(self):
        """Stop it; its exit status and stderr."""
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        return self.proc.returncode, self.proc.stderr.read()


class FakePopups:
    """The launcher's popup socket: records each request, answers with
    .answer (bytes, or a callable taking the request), optionally after
    .hold is set."""

    def __init__(self, path):
        self.path = str(path)
        self.requests = []
        self.answer = b"no"
        self.hold = None
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(16)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            data = b""
            while chunk := conn.recv(65536):
                data += chunk
            request = json.loads(data)
            self.requests.append(request)
            if self.hold is not None:
                self.hold.wait(10)
            answer = self.answer(request) if callable(self.answer) else self.answer
            conn.sendall(answer)

    @property
    def texts(self):
        return [r["text"] for r in self.requests]

    def close(self):
        self.sock.close()


# -- TLS ------------------------------------------------------------------------


class FakeCA:
    """A CA for the stand-ins' certificates, and its PEM bundle file."""

    def __init__(self, directory):
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test CA")])
        now = datetime.datetime.now(datetime.UTC)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )  # fmt: skip
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        self.directory = Path(directory)
        self.file = self.directory / "test-ca.pem"
        self.file.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))

    def server_context(self, *names):
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.UTC)
        sans = [
            x509.IPAddress(ipaddress.ip_address(n))
            if n[0].isdigit()
            else x509.DNSName(n)
            for n in names
        ]
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
            )
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.key.public_key()
                ),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        d = Path(tempfile.mkdtemp(dir=self.directory))
        (d / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (d / "key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(d / "cert.pem", d / "key.pem")
        return ctx


UPSTREAM_NAMES = (
    "api.github.com",
    "uploads.github.com",
    "objects.githubusercontent.com",
    "api.anthropic.com",
    "forgejo.example",
)

BIG = b"x" * (1024 * 1024 + 7)


class Upstream:
    """Every real host at once, over TLS: records each request, answers via
    .route(handler) -> (status, headers, body) or the default below."""

    def __init__(self, ca, names=UPSTREAM_NAMES):
        self.seen = []
        self.route = None
        self.release = threading.Event()
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):  # pylint: disable=redefined-builtin
                pass

            def answer(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                upstream.seen.append(
                    {
                        "method": self.command,
                        "host": self.headers.get("Host"),
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": body,
                    }
                )
                if upstream.route and upstream.route(self, body):
                    return
                default(self)

            do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = (
                answer
            )

        def default(h):
            if h.path == "/big":
                # Chunked, so the proxy has to relay it close-delimited.
                h.send_response(200)
                h.send_header("Transfer-Encoding", "chunked")
                h.end_headers()
                for i in range(0, len(BIG), 100_000):
                    chunk = BIG[i : i + 100_000]
                    h.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                h.wfile.write(b"0\r\n\r\n")
                return
            if h.path == "/redirect":
                h.send_response(302)
                h.send_header("Location", "https://objects.githubusercontent.com/asset")
                h.send_header("Content-Length", "0")
                h.end_headers()
                return
            if h.path.startswith("/v1/messages?stream"):
                h.send_response(200)
                h.send_header("Content-Type", "text/event-stream")
                h.send_header("Transfer-Encoding", "chunked")
                h.end_headers()
                for event in (b"event: one\n\n", None, b"event: two\n\n"):
                    if event is None:
                        upstream.release.wait(10)
                        continue
                    h.wfile.write(f"{len(event):x}\r\n".encode() + event + b"\r\n")
                    h.wfile.flush()
                h.wfile.write(b"0\r\n\r\n")
                return
            out = json.dumps({"login": "someone", "path": h.path}).encode()
            h.send_response(200)
            h.send_header("Content-Type", "application/json")
            h.send_header("Content-Length", str(len(out)))
            h.end_headers()
            if h.command != "HEAD":
                h.wfile.write(out)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.socket = ca.server_context(*names).wrap_socket(
            self.server.socket, server_side=True
        )
        threading.Thread(
            target=self.server.serve_forever, args=(0.02,), daemon=True
        ).start()

    @property
    def address(self):
        return f"127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()


# -- HTTPS proxies -------------------------------------------------------------------


class ProxyInfo:
    """What an HTTPS-intercepting guard announced in its dir."""

    def __init__(self, directory):
        info = json.loads((Path(directory) / "proxy.json").read_text())
        self.port, self.secret = info["port"], info["secret"]
        self.ca_pem = (Path(directory) / "ca.pem").read_text()

    @property
    def url(self):
        return f"http://sandbox:{self.secret}@127.0.0.1:{self.port}"


def proxy_connect(info, target, auth=True):
    """A socket CONNECTed through the proxy to target, and its answer's head.
    auth: the secret (True), nothing (False) or this Proxy-Authorization."""
    sock = socket.create_connection(("127.0.0.1", info.port), timeout=10)
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    if auth is True:
        token = base64.b64encode(f"sandbox:{info.secret}".encode()).decode()
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


def tls_wrap(sock, ca_pem, hostname):
    ctx = ssl.create_default_context(cadata=ca_pem)
    return ctx.wrap_socket(sock, server_hostname=hostname)


def read_response(sock, method):
    response = http.client.HTTPResponse(sock, method=method)
    response.begin()
    return response.status, dict(response.getheaders()), response.read()


def https_send(info, target, raw):
    """raw sent inside a tunnel to target, intercepted by the proxy;
    (status, headers, body)."""
    sock, head = proxy_connect(info, target)
    assert " 200 " in head.split("\r\n", 1)[0], head
    tls = tls_wrap(sock, info.ca_pem, target.rsplit(":", 1)[0])
    try:
        tls.sendall(raw)
        return read_response(tls, raw.split(b" ", 1)[0].decode())
    finally:
        tls.close()


def raw_request(method, host, path, body=b"", headers=(), auth="token placeholder"):
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    if auth:
        lines.append(f"Authorization: {auth}")
    lines += list(headers)
    if body or method not in ("GET", "HEAD"):
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body
